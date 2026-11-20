# ------------------------------------------------------------------------------
# app.py - Paanipahra IoT API (PostgreSQL / Neon)
#
# Keys (set in API_KEYS as name:role:hash):
#   device  IoT devices. Send readings by LOCATION TITLE only. No internal IDs.
#   admin   The dashboard administrator. Changes cooler details and locations.
#   read    Reserved. Public GET routes need no key.
#
# Devices never receive or send internal database IDs. The database finds the
# cooler from the location title.
#
# Start command on Render:  gunicorn -w 1 --threads 4 app:app
# ------------------------------------------------------------------------------
import hashlib
import os
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from functools import wraps

import psycopg2
import psycopg2.extras
from flask import Flask, jsonify, request, g
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 8192  # reject request bodies over 8 KB

# ---------- Configuration (environment variables on Render) ----------
# DATABASE_URL     Neon connection string, must include ?sslmode=require (required)
# API_KEYS         name:role:sha256hash,... ; role "write" is used by devices and admin tools
# ALLOWED_ORIGINS  comma-separated website addresses allowed to call the API from a browser
DATABASE_URL = os.environ.get('DATABASE_URL')
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable is not set")

ALLOWED_ORIGINS = [o.strip() for o in os.environ.get('ALLOWED_ORIGINS', '').split(',') if o.strip()]
if not ALLOWED_ORIGINS:
    print("WARNING: ALLOWED_ORIGINS is not set. Browsers (the dashboard) will be blocked from reading the API.")


def parse_keys(raw):
    keys = {}
    for entry in raw.split(','):
        parts = entry.strip().split(':')
        if len(parts) != 3:
            continue
        name, role, digest = parts
        if role in ('read', 'device', 'admin'):
            keys[digest.lower()] = {'name': name, 'role': role}
    return keys


API_KEYS = parse_keys(os.environ.get('API_KEYS', ''))

# Only the listed website origins may call the API from a browser
CORS(app, resources={r"/api/*": {"origins": ALLOWED_ORIGINS}})


def hash_key(raw_key):
    return hashlib.sha256(raw_key.encode()).hexdigest()


def rate_key():
    sent = request.headers.get('X-API-Key', '')
    return hash_key(sent) if sent else get_remote_address()


limiter = Limiter(
    rate_key,
    app=app,
    default_limits=["120 per minute"],
    storage_uri="memory://",
)

# Public reads refresh every few seconds from each open page. Many pages can share
# one school IP address, so reads get a higher limit than writes.
READ_LIMIT = "600 per minute"


def error(message, status):
    return jsonify({"error": message}), status


def require_role(*roles):
    """Allows only keys whose role is in roles. 401 = unknown key, 403 = wrong role."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not API_KEYS:
                return error("Service not configured", 503)  # fail closed
            sent = request.headers.get('X-API-Key', '')
            client = API_KEYS.get(hash_key(sent)) if sent else None
            if client is None:
                return error("Unauthorized", 401)
            if client['role'] not in roles:
                return error("This key is not allowed to use this route", 403)
            g.client = client['name']
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ---------- Database ----------
def get_db():
    if 'db' not in g:
        g.db = psycopg2.connect(DATABASE_URL)
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def query_all(sql, params=()):
    with get_db().cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(sql, params)
        return cur.fetchall()


def query_one(sql, params=()):
    rows = query_all(sql, params)
    return rows[0] if rows else None


def call_procedure(sql, params):
    """Run a CALL and commit. Returns the output value, or None.
    Only procedures with an OUT/INOUT parameter return a row, so the row is read only then."""
    db = get_db()
    with db.cursor() as cur:
        cur.execute(sql, params)
        out = cur.fetchone() if cur.description is not None else None
    db.commit()
    return out[0] if out else None


@app.errorhandler(psycopg2.Error)
def handle_database_error(e):
    """Turns database errors into clear API responses."""
    try:
        get_db().rollback()
    except Exception:
        pass
    code = getattr(e, 'pgcode', None)
    message = (getattr(getattr(e, 'diag', None), 'message_primary', None) or "Database error")
    if code == '02000':                                   # not found (raised by the procedures)
        return error(message, 404)
    if code == '23505':                                   # duplicate value
        return error("Already exists: " + message, 409)
    if code in ('22023', '23514', '23503', '23502', '22P02', '22007', '22008'):
        return error(message, 400)                        # bad input or failed check
    app.logger.exception("Database error")
    return error("Database error", 500)


# ---------- Input helpers ----------
def to_number(name, value):
    if isinstance(value, bool) or value is None or (isinstance(value, str) and value.strip() == ""):
        raise ValueError(f"{name} must be a number")
    try:
        number = Decimal(str(value))
    except InvalidOperation:
        raise ValueError(f"{name} must be a number")
    if not number.is_finite():
        raise ValueError(f"{name} must be a number")
    return number


def to_int(name, value):
    number = to_number(name, value)
    if number != number.to_integral_value():
        raise ValueError(f"{name} must be a whole number")
    return int(number)


def to_date(name, value):
    if value is None or (isinstance(value, str) and value.strip() == ""):
        return None
    try:
        return date.fromisoformat(str(value).strip())
    except ValueError:
        raise ValueError(f"{name} must be a date like 2026-06-01")


def to_bool(name, value):
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ('true', '1', 'yes'):
        return True
    if text in ('false', '0', 'no'):
        return False
    raise ValueError(f"{name} must be true or false")


def to_text(value):
    """Blank text means 'leave unchanged' for update routes."""
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def parse_time(text):
    """ISO time such as 2026-11-15T07:00:00+05:30. Without a zone, UTC is assumed."""
    try:
        t = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        raise ValueError("time must be ISO format, for example 2026-11-15T07:00:00+05:30")
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def time_range(default_hours=24, max_hours=168):
    """Reads from/to, or hours back from now. Returns (from, to)."""
    to_text_arg = request.args.get('to')
    from_text_arg = request.args.get('from')
    to_time = parse_time(to_text_arg) if to_text_arg else datetime.now(timezone.utc)
    if from_text_arg:
        from_time = parse_time(from_text_arg)
    else:
        try:
            hours = int(request.args.get('hours', default_hours))
        except ValueError:
            raise ValueError("hours must be a whole number")
        hours = max(1, min(hours, max_hours))
        from_time = to_time - timedelta(hours=hours)
    if from_time > to_time:
        raise ValueError("from must be earlier than to")
    return from_time, to_time


def fmt(value):
    """Numbers as text without a trailing .0, e.g. 30.0 -> '30', 18.5 -> '18.5'."""
    if value is None:
        return ""
    f = float(value)
    return str(int(f)) if f.is_integer() else str(f)


def iso(value):
    return value.isoformat() if value is not None else None


# ---------- Converting database rows to API JSON ----------
def cooler_to_api(row):
    """Same keys the dashboard already uses, plus extra details."""
    return {
        "id": row["cooler_id"],
        "title": row["location_name"],          # the dashboard card title
        "location": row["location_name"],
        "building": row["building"],
        "block": row["block_floor_wing_room_no"],
        "video": row["cctv_url"],
        "waterLevel": fmt(row["water_level"]),
        "waterMeter": fmt(row["water_meter"]),
        "waterTemp": fmt(row["water_temp"]),
        "roTds": fmt(row["ro_tds"]),
        "safety": row["safety_status"],
        "systemWorking": row["system_status"],
        "consumption": fmt(row["consumption_today"]),
        "volume": fmt(row["volume_litres"]),
        "fillPercent": fmt(row["fill_percent"]),
        "alarms": {
            "tempHigh": bool(row["alarm_temp_high"]),
            "levelLow": bool(row["alarm_level_low"]),
            "tdsHigh": bool(row["alarm_tds_high"]),
        },
        "lastUpdated": iso(row["last_updated_at"]),
        "details": {
            "tankCapacityLitre": fmt(row["tank_capacity_litre"]),
            "tankBottomAreaCm2": fmt(row["tank_bottom_area_cm2"]),
            "tankDepthCm": fmt(row["tank_depth_cm"]),
            "modelNo": row["model_no"],
            "serialNo": row["serial_no"],
            "manufacturer": row["manufacturer"],
            "powerRatingW": row["power_rating_w"],
            "installationDate": iso(row["installation_date"]),
            "warrantyExpiryDate": iso(row["warranty_expiry_date"]),
            "lastServiceDate": iso(row["last_service_date"]),
            "nextServiceDueDate": iso(row["next_service_due_date"]),
            "amcExpiryDate": iso(row["amc_expiry_date"]),
            "customerCareNo": row["customer_care_no"],
            "serviceContactName": row["service_contact_name"],
            "alarmTempHighC": fmt(row["alarm_temp_high_c"]),
            "alarmLevelLowL": fmt(row["alarm_level_low_l"]),
            "alarmTdsHighPpm": row["alarm_tds_high_ppm"],
        },
    }


def location_to_api(row):
    return {
        "locationId": row["location_id"],
        "locationName": row["location_name"],
        "building": row["building"],
        "blockFloorWingRoomNo": row["block_floor_wing_room_no"],
        "isActive": row["is_active"],
        "coolerCount": row["cooler_count"],
    }


def tank_to_api(row):
    return {
        "waterLevel": fmt(row["water_level_l"]),
        "safety": row["safety_status"],
        "systemWorking": row["system_status"],
        "lastUpdated": iso(row["update_timestamp"]),
    }


# ---------- Shared database calls ----------
def get_one_cooler(cooler_id):
    return query_one("SELECT * FROM get_cooler(%s)", (cooler_id,))


# Cooler details: API key -> (procedure parameter order, parser)
DETAIL_FIELDS = [
    ("locationId",          lambda v: to_int("locationId", v)),
    ("cctvUrl",             to_text),
    ("tankCapacityLitre",   lambda v: to_number("tankCapacityLitre", v)),
    ("tankBottomAreaCm2",   lambda v: to_number("tankBottomAreaCm2", v)),
    ("tankDepthCm",         lambda v: to_number("tankDepthCm", v)),
    ("modelNo",             to_text),
    ("serialNo",            to_text),
    ("manufacturer",        to_text),
    ("powerRatingW",        lambda v: to_int("powerRatingW", v)),
    ("installationDate",    lambda v: to_date("installationDate", v)),
    ("warrantyExpiryDate",  lambda v: to_date("warrantyExpiryDate", v)),
    ("lastServiceDate",     lambda v: to_date("lastServiceDate", v)),
    ("nextServiceDueDate",  lambda v: to_date("nextServiceDueDate", v)),
    ("amcExpiryDate",       lambda v: to_date("amcExpiryDate", v)),
    ("customerCareNo",      to_text),
    ("serviceContactName",  to_text),
    ("alarmTempHighC",      lambda v: to_number("alarmTempHighC", v)),
    ("alarmLevelLowL",      lambda v: to_number("alarmLevelLowL", v)),
    ("alarmTdsHighPpm",     lambda v: to_int("alarmTdsHighPpm", v)),
]


# ---------- Routes: home and health ----------
@app.route('/')
def home():
    return '<h1>Welcome to Paanipahra IoT API!</h1>'


@app.route('/api/health', methods=['GET'])
@limiter.limit(READ_LIMIT)
def health():
    """Checks that the API can reach the database."""
    try:
        query_one("SELECT 1 AS ok")
        return jsonify({"status": "ok", "database": "connected"}), 200
    except psycopg2.Error:
        return error("Database not reachable", 503)


# ---------- Routes: coolers ----------
@app.route('/api/coolers', methods=['GET'])
@limiter.limit(READ_LIMIT)
def get_coolers():
    rows = query_all("SELECT * FROM get_coolers()")
    return jsonify({str(row["cooler_id"]): cooler_to_api(row) for row in rows})


@app.route('/api/coolers/<int:cooler_id>', methods=['GET'])
@limiter.limit(READ_LIMIT)
def get_cooler(cooler_id):
    row = get_one_cooler(cooler_id)
    if row is None:
        return error("Cooler not found", 404)
    return jsonify(cooler_to_api(row))


@app.route('/api/coolers/<int:cooler_id>/details', methods=['PUT', 'POST'])
@require_role('admin')
def update_cooler_details(cooler_id):
    """Changes tank, model, service, contact and alarm details. Blank or missing = unchanged."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not payload:
        return error("Body must be a non-empty JSON object", 400)
    allowed = {name for name, _ in DETAIL_FIELDS}
    unknown = sorted(set(payload) - allowed)
    if unknown:
        return error("Unknown field(s): " + ", ".join(unknown), 400)

    if get_one_cooler(cooler_id) is None:
        return error("Cooler not found", 404)

    params = [cooler_id]
    try:
        for name, parse in DETAIL_FIELDS:
            value = payload.get(name)
            params.append(parse(value) if value not in (None, "") else None)
    except ValueError as e:
        return error(str(e), 400)

    call_procedure(
        "CALL update_cooler_details(" + ", ".join(["%s"] * 20) + ")", tuple(params))
    print(f"{g.client} updated details of cooler {cooler_id}: {list(payload)}")
    return jsonify({"status": "success", "coolerId": cooler_id,
                    "updated_data": cooler_to_api(get_one_cooler(cooler_id))}), 200


@app.route('/api/coolers/<int:cooler_id>/history', methods=['GET'])
@limiter.limit(READ_LIMIT)
def get_cooler_history(cooler_id):
    if get_one_cooler(cooler_id) is None:
        return error("Cooler not found", 404)
    try:
        start, end = time_range()
    except ValueError as e:
        return error(str(e), 400)
    rows = query_all("SELECT * FROM get_cooler_history(%s, %s, %s)", (cooler_id, start, end))
    return jsonify({
        "coolerId": cooler_id,
        "from": iso(start),
        "to": iso(end),
        "readings": [{
            "time": iso(r["update_timestamp"]),
            "waterMeter": fmt(r["water_meter_reading"]),
            "waterLevel": fmt(r["water_level"]),
            "waterTemp": fmt(r["water_temp"]),
            "roTds": fmt(r["ro_tds"]),
            "safety": r["safety_status"],
            "systemWorking": r["system_status"],
        } for r in rows],
    })


# ---------- Routes: locations ----------
@app.route('/api/locations', methods=['GET'])
@limiter.limit(READ_LIMIT)
def get_locations():
    rows = query_all("SELECT * FROM get_locations()")
    return jsonify([location_to_api(r) for r in rows])


@app.route('/api/locations', methods=['POST'])
@require_role('admin')
def add_location():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return error("Body must be a JSON object", 400)
    name = to_text(payload.get("locationName"))
    if not name:
        return error("locationName is required", 400)
    try:
        is_active = to_bool("isActive", payload.get("isActive", True))
    except ValueError as e:
        return error(str(e), 400)
    new_id = call_procedure(
        "CALL add_location(%s, %s, %s, %s, %s)",
        (name, to_text(payload.get("building")), to_text(payload.get("blockFloorWingRoomNo")), is_active, None),
    )
    row = query_one("SELECT * FROM get_locations() WHERE location_id = %s", (new_id,))
    return jsonify({"status": "success", "location": location_to_api(row)}), 201


@app.route('/api/locations/<int:location_id>', methods=['PUT', 'POST'])
@require_role('admin')
def update_location(location_id):
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not payload:
        return error("Body must be a non-empty JSON object", 400)
    allowed = {"locationName", "building", "blockFloorWingRoomNo", "isActive"}
    unknown = sorted(set(payload) - allowed)
    if unknown:
        return error("Unknown field(s): " + ", ".join(unknown), 400)
    try:
        is_active = to_bool("isActive", payload["isActive"]) if "isActive" in payload else None
    except ValueError as e:
        return error(str(e), 400)
    call_procedure(
        "CALL update_location(%s, %s, %s, %s, %s)",
        (location_id, to_text(payload.get("locationName")), to_text(payload.get("building")),
         to_text(payload.get("blockFloorWingRoomNo")), is_active),
    )
    row = query_one("SELECT * FROM get_locations() WHERE location_id = %s", (location_id,))
    return jsonify({"status": "success", "location": location_to_api(row)}), 200


# ---------- Routes: main tank ----------
@app.route('/api/main-tank', methods=['GET'])
@limiter.limit(READ_LIMIT)
def get_main_tank():
    row = query_one("SELECT * FROM get_main_tank_current()")
    if row is None:
        return error("No main tank readings yet", 404)
    return jsonify(tank_to_api(row))


@app.route('/api/main-tank/history', methods=['GET'])
@limiter.limit(READ_LIMIT)
def get_main_tank_history():
    try:
        start, end = time_range()
    except ValueError as e:
        return error(str(e), 400)
    rows = query_all("SELECT * FROM get_main_tank_history(%s, %s)", (start, end))
    return jsonify({
        "from": iso(start),
        "to": iso(end),
        "readings": [tank_to_api(r) for r in rows],
    })


# ---------- Routes: IoT devices (by location title, never by internal ID) ----------
DEVICE_READING_FIELDS = ("waterMeter", "waterLevel", "waterTemp", "roTds", "safety", "systemWorking")
DEVICE_TO_COLUMN = {
    "waterMeter": "water_meter",
    "waterLevel": "water_level",
    "waterTemp": "water_temp",
    "roTds": "ro_tds",
    "safety": "safety_status",
    "systemWorking": "system_status",
}


def device_error(e):
    """Errors shown to devices: our own messages only, never database details."""
    try:
        get_db().rollback()
    except Exception:
        pass
    code = getattr(e, 'pgcode', None)
    if code == '02000':
        return error("Location not found", 404)
    if code == '22023':
        return error(getattr(getattr(e, 'diag', None), 'message_primary', None) or "Invalid reading", 400)
    if code in ('23514', '23502', '23503', '22P02', '22007', '22008'):
        return error("Reading rejected: a value is missing or outside the allowed range", 400)
    app.logger.exception("Device request failed")
    return error("Could not save, please retry", 500)


@app.route('/api/device/readings', methods=['POST', 'PUT'])
@require_role('device', 'admin')
def device_reading():
    """Body: {"locationTitle": "Location01A", "waterLevel": 120, ...}. Send only the fields you have."""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return error("Body must be a JSON object", 400)
    title = to_text(payload.get("locationTitle"))
    if not title:
        return error("locationTitle is required", 400)
    sent = sorted(k for k in payload if k != "locationTitle")
    if not sent:
        return error("Send at least one reading field", 400)
    unknown = sorted(set(sent) - set(DEVICE_READING_FIELDS))
    if unknown:
        return error("Unknown field(s): " + ", ".join(unknown), 400)

    current = query_one("SELECT * FROM get_cooler_by_title(%s)", (title,))
    if current is None:
        return error("Location not found", 404)

    # Start from the latest values; replace only the fields sent
    values = {
        "water_meter": current["water_meter"],
        "water_level": current["water_level"],
        "water_temp": current["water_temp"],
        "ro_tds": current["ro_tds"],
        "safety_status": current["safety_status"],
        "system_status": current["system_status"],
    }
    try:
        for field in sent:
            column = DEVICE_TO_COLUMN[field]
            if column in ("safety_status", "system_status"):
                values[column] = str(payload[field]).strip()
            else:
                values[column] = to_number(field, payload[field])
    except ValueError as e:
        return error(str(e), 400)

    now = datetime.now(timezone.utc)
    try:
        call_procedure(
            "CALL add_location_reading(%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (title, values["water_meter"], values["water_level"], values["water_temp"],
             values["ro_tds"], values["safety_status"], values["system_status"], now, None),
        )
    except psycopg2.Error as e:
        return device_error(e)
    print(f"{g.client} reading saved for {title}: {sent}")
    return jsonify({"status": "success", "locationTitle": title,
                    "received": sent, "receivedAt": now.isoformat()}), 200


@app.route('/api/device/main-tank', methods=['POST', 'PUT'])
@require_role('device', 'admin')
def device_main_tank():
    """Body: {"waterLevel": 230, "safety": "Green", "systemWorking": "OK"}"""
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return error("Body must be a JSON object", 400)
    unknown = sorted(set(payload) - {"waterLevel", "safety", "systemWorking"})
    if unknown:
        return error("Unknown field(s): " + ", ".join(unknown), 400)
    if any(k not in payload for k in ("waterLevel", "safety", "systemWorking")):
        return error("waterLevel, safety and systemWorking are required", 400)
    try:
        level = to_number("waterLevel", payload["waterLevel"])
    except ValueError as e:
        return error(str(e), 400)

    now = datetime.now(timezone.utc)
    try:
        call_procedure(
            "CALL add_main_tank_reading(%s, %s, %s, %s, %s)",
            (level, str(payload["safety"]).strip(), str(payload["systemWorking"]).strip(), now, None),
        )
    except psycopg2.Error as e:
        return device_error(e)
    print(f"{g.client} main tank reading saved")
    return jsonify({"status": "success", "receivedAt": now.isoformat()}), 200


# ---------- Errors and security headers ----------
@app.errorhandler(404)
def not_found(e):
    return error("Not found", 404)


@app.errorhandler(405)
def method_not_allowed(e):
    return error("Method not allowed", 405)


@app.errorhandler(413)
def too_large(e):
    return error("Request too large", 413)


@app.errorhandler(429)
def rate_limited(e):
    return error("Too many requests, slow down", 429)


@app.after_request
def security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'no-referrer'
    if request.path.startswith('/api/'):
        resp.headers['Cache-Control'] = 'no-store'
    return resp


if __name__ == '__main__':
    # Local testing only. On Render, gunicorn runs the app.
    app.run(debug=False)
