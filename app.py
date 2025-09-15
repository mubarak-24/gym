import os
import csv
import json
import secrets
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask, render_template, request, jsonify,
    send_from_directory, abort, session, redirect, url_for, flash, make_response
)

from sqlalchemy import (
    create_engine, Column, Integer, String, Float, DateTime,
    UniqueConstraint, text, or_, func
)
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.sql import expression
from werkzeug.security import generate_password_hash, check_password_hash

# --- .env ---
from dotenv import load_dotenv
load_dotenv()

# ------------ Password hashing policy ------------
PW_METHOD    = os.getenv("PASSWORD_HASH_METHOD", "pbkdf2:sha256")
PW_SALT_LEN  = int(os.getenv("PASSWORD_SALT_LENGTH", "16"))
HAS_SCRYPT   = hasattr(hashlib, "scrypt")
# -------------------------------------------------

# --- Google Sheets deps (optional; safe to keep even if unused) ---
import gspread
from google.oauth2.service_account import Credentials

# --- Web Push deps (optional) ---
from pywebpush import webpush, WebPushException

# -----------------------------------------------------------------------------
# App
# -----------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")

# -----------------------------------------------------------------------------
# Google Sheets config (optional)
# -----------------------------------------------------------------------------
SERVICE_ACCOUNT_FILE = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
SPREADSHEET_ID       = os.getenv("SHEETS_SPREADSHEET_ID")
SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]

_gs_client = None
def sheets_client():
    """Singleton gspread client."""
    global _gs_client
    if _gs_client is None:
        if not SERVICE_ACCOUNT_FILE or not os.path.exists(SERVICE_ACCOUNT_FILE):
            raise RuntimeError("GOOGLE_APPLICATION_CREDENTIALS missing or path is wrong")
        creds = Credentials.from_service_account_file(SERVICE_ACCOUNT_FILE, scopes=SCOPES)
        _gs_client = gspread.authorize(creds)
    return _gs_client

def append_logs_to_sheet(rows, user_id, username):
    """Append rows to the first worksheet. Ensures a single header row exists."""
    sh = sheets_client().open_by_key(SPREADSHEET_ID)
    ws = sh.sheet1

    header = [
        "timestamp","date","day_name","program","session_id","exercise",
        "sets","reps","weight_kg","rpe","volume_kg","duration_min","notes",
        "source","user_id","username","day_code","program_id"
    ]

    first_row = ws.get_values("A1:T1")
    if not first_row:
        ws.append_row(header)

    data = []
    for r in rows:
        data.append([
            r.get("timestamp") or "",
            r.get("date") or "",
            r.get("day_name") or "",
            r.get("program") or "",
            r.get("session_id") or "",
            r.get("exercise") or "",
            r.get("sets") or "",
            r.get("reps") or "",
            r.get("weight_kg") or "",
            r.get("rpe") or "",
            r.get("volume_kg") or "",
            r.get("duration_min") or "",
            r.get("notes") or "",
            r.get("source") or "pwa",
            user_id or "",
            username or "",
            r.get("day_code") or "",
            r.get("program_id") or "",
        ])

    if data:
        ws.append_rows(data, value_input_option="USER_ENTERED")

# -----------------------------------------------------------------------------
# CSV export helpers
# -----------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
CSV_PATH = DATA_DIR / "logs.csv"

CSV_HEADER = [
    "user_id","username",
    "timestamp","date","day_name","time_hhmm",
    "program","program_id","day_code","session_id","exercise",
    "sets","reps","weight_kg","rpe","volume_kg","duration_min",
    "notes","source"
]

def _ensure_csv_header():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not CSV_PATH.exists():
        with CSV_PATH.open("w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(CSV_HEADER)

def append_rows_to_csv(rows):
    """rows: list[dict] whose keys match CSV_HEADER (missing keys -> "")."""
    _ensure_csv_header()
    with CSV_PATH.open("a", newline="") as f:
        w = csv.writer(f)
        for r in rows:
            w.writerow([
                r.get("user_id",""),
                r.get("username",""),
                r.get("timestamp",""),
                r.get("date",""),
                r.get("day_name",""),
                r.get("time_hhmm",""),
                r.get("program",""),
                r.get("program_id",""),
                r.get("day_code",""),
                r.get("session_id",""),
                r.get("exercise",""),
                r.get("sets",""),
                r.get("reps",""),
                r.get("weight_kg",""),
                r.get("rpe",""),
                r.get("volume_kg",""),
                r.get("duration_min",""),
                r.get("notes",""),
                r.get("source",""),
            ])

# -----------------------------------------------------------------------------
# DB setup
# -----------------------------------------------------------------------------
# -----------------------------------------------------------------------------
# DB setup (uses DATABASE_URL if present, else local SQLite)
# -----------------------------------------------------------------------------
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///database.db")

# Heroku-style URLs sometimes start with postgres:// — SQLAlchemy needs postgresql+psycopg2://
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)

engine = create_engine(DATABASE_URL, echo=False, future=True)

# -----------------------------------------------------------------------------
# Models
# -----------------------------------------------------------------------------
class User(Base):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True)
    email = Column(String(120), unique=True, nullable=False)
    username = Column(String(64), nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(16), nullable=False, default="user")
    created_at = Column(String(32))
    __table_args__ = (UniqueConstraint("username", name="uq_user_username"),)

class WorkoutLog(Base):
    __tablename__ = "workout_log"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    session_id = Column(String(32), index=True)
    date = Column(String(10))            # "YYYY-MM-DD"
    day_name = Column(String(12))
    program = Column(String(32))
    exercise = Column(String(64))
    sets = Column(Integer)
    reps = Column(Integer)
    weight_kg = Column(Float)
    rpe = Column(String(8))
    volume_kg = Column(Float)
    duration_min = Column(Integer)
    notes = Column(String(255))
    source = Column(String(16), default="pwa")
    user_id = Column(Integer, index=True)
    # NEW:
    day_code = Column(String(16), index=True)     # e.g. "upper_a"
    program_id = Column(Integer, index=True)      # FK-ish (no constraint for SQLite simplicity)

class PushSubscription(Base):
    __tablename__ = "push_subscriptions"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, index=True, nullable=True)
    endpoint = Column(String, nullable=False, unique=True)
    p256dh = Column(String(255), nullable=False)
    auth   = Column(String(255), nullable=False)
    ua     = Column(String(255), nullable=True)

class Program(Base):
    __tablename__ = "program"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, index=True)         # owner (null = admin template)
    name = Column(String(64), nullable=False)     # e.g., "My Upper/Lower"
    created_at = Column(DateTime, default=datetime.utcnow)

class RoutineDay(Base):
    __tablename__ = "routine_day"
    id = Column(Integer, primary_key=True)
    program_id = Column(Integer, index=True)
    code = Column(String(16), index=True)         # "upper_a", "upper_b", "lower_a"...
    title = Column(String(64), nullable=False)    # "Upper A"
    order_index = Column(Integer, default=0)

class RoutineExercise(Base):
    __tablename__ = "routine_exercise"
    id = Column(Integer, primary_key=True)
    day_id = Column(Integer, index=True)
    exercise = Column(String(64), nullable=False) # e.g., "Bench press"
    sets = Column(Integer, default=3)
    reps = Column(Integer, default=10)
    target_rpe = Column(String(8), default="8")
    note = Column(String(255))

# Create any missing tables
Base.metadata.create_all(engine)

# --- Lightweight migration: add new columns to workout_log if missing -------
def _col_exists(table: str, col: str) -> bool:
    with engine.connect() as c:
        res = c.execute(text(f"PRAGMA table_info({table})"))
        return any(r[1] == col for r in res.fetchall())

def _add_column_if_missing(table: str, col: str, ddl: str):
    if not _col_exists(table, col):
        with engine.begin() as c:
            c.execute(text(f"ALTER TABLE {table} ADD COLUMN {ddl}"))

_add_column_if_missing("workout_log", "day_code", "day_code TEXT")
_add_column_if_missing("workout_log", "program_id", "program_id INTEGER")

# -----------------------------------------------------------------------------
# Auth helpers
# -----------------------------------------------------------------------------
def current_user_id():
    return session.get("uid")

def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not current_user_id():
            return redirect(url_for("login", next=request.path))
        return view_func(*args, **kwargs)
    return wrapper

# -----------------------------------------------------------------------------
# Admin helpers
# -----------------------------------------------------------------------------
def is_admin():
    uid = session.get("uid")
    if not uid:
        return False
    db = SessionLocal()
    try:
        u = db.get(User, uid)
        return bool(u and u.role == "admin")
    finally:
        db.close()

def admin_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not current_user_id():
            return redirect(url_for("login", next=request.path))
        if not is_admin():
            return render_template("403.html"), 403
        return view_func(*args, **kwargs)
    return wrapper

@app.context_processor
def inject_flags():
    return {"is_admin": session.get("role") == "admin"}

# -----------------------------------------------------------------------------
# Web Push config
# -----------------------------------------------------------------------------
VAPID_PRIVATE_FILE = os.getenv("VAPID_PRIVATE_FILE")
VAPID_PUBLIC_FILE  = os.getenv("VAPID_PUBLIC_FILE")
VAPID_SUBJECT      = os.getenv("VAPID_SUBJECT", "mailto:admin@example.com")

try:
    VAPID_PRIVATE_KEY_PEM = Path(VAPID_PRIVATE_FILE).read_text().strip() if VAPID_PRIVATE_FILE else None
    VAPID_PUBLIC_KEY_PEM  = Path(VAPID_PUBLIC_FILE).read_text().strip() if VAPID_PUBLIC_FILE else None
except Exception:
    VAPID_PRIVATE_KEY_PEM = None
    VAPID_PUBLIC_KEY_PEM  = None

def _vapid_claims():
    return {"sub": VAPID_SUBJECT}

def push_enabled():
    return bool(VAPID_PRIVATE_KEY_PEM and VAPID_PUBLIC_KEY_PEM)

def send_push_to_user(db, user_id, payload: dict):
    if not push_enabled():
        return 0, 0
    sent, failed = 0, 0
    subs = db.query(PushSubscription).filter(PushSubscription.user_id == user_id).all()
    for sub in subs:
        try:
            webpush(
                subscription_info={"endpoint": sub.endpoint,
                                   "keys": {"p256dh": sub.p256dh, "auth": sub.auth}},
                data=json.dumps(payload),
                vapid_private_key=VAPID_PRIVATE_KEY_PEM,
                vapid_claims=_vapid_claims()
            )
            sent += 1
        except WebPushException:
            failed += 1
    return sent, failed

def send_push_all(db, payload: dict):
    if not push_enabled():
        return 0, 0
    sent, failed = 0, 0
    for sub in db.query(PushSubscription).all():
        try:
            webpush(
                subscription_info={"endpoint": sub.endpoint,
                                   "keys": {"p256dh": sub.p256dh, "auth": sub.auth}},
                data=json.dumps(payload),
                vapid_private_key=VAPID_PRIVATE_KEY_PEM,
                vapid_claims=_vapid_claims()
            )
            sent += 1
        except WebPushException:
            failed += 1
    return sent, failed

# Simple categorization for Upper/Lower tracking
def categorize_exercise(name: str) -> str:
    n = (name or "").lower()
    upper_kw = ["bench","press","row","pull","curl","lat","shoulder","tricep","bicep","chest","push-up","dip"]
    lower_kw = ["squat","deadlift","leg","ham","quad","calf","glute","lunge","hip","rdl"]
    if any(k in n for k in upper_kw): return "Upper"
    if any(k in n for k in lower_kw): return "Lower"
    return "Other"

def check_pr_and_notify(db, uid: int, exercise: str, weight_kg: float):
    if not (push_enabled() and uid and exercise and (weight_kg is not None)):
        return
    prev_best = db.query(func.max(WorkoutLog.weight_kg)).filter(
        WorkoutLog.user_id == uid, WorkoutLog.exercise.ilike(exercise)
    ).scalar() or 0.0

    cat = categorize_exercise(exercise)
    prev_cat_best = 0.0
    if cat != "Other":
        all_cat = db.query(WorkoutLog.weight_kg, WorkoutLog.exercise).filter(
            WorkoutLog.user_id == uid
        ).all()
        prev_cat_best = max([w for (w, ex) in all_cat if categorize_exercise(ex) == cat and w is not None] or [0.0])

    new_exercise_pr = weight_kg > (prev_best or 0.0)
    new_cat_pr = weight_kg > (prev_cat_best or 0.0)

    if new_exercise_pr or new_cat_pr:
        lines = []
        if new_exercise_pr: lines.append(f"New PR on {exercise}: {weight_kg:g} kg")
        if new_cat_pr and cat != "Other": lines.append(f"New {cat} category best: {weight_kg:g} kg")
        payload = {"title": "🎉 New PR!", "body": " • ".join(lines), "data": {"url": "/logs"}}
        send_push_to_user(db, uid, payload)

# -----------------------------------------------------------------------------
# Pages
# -----------------------------------------------------------------------------
@app.route("/")
def root():
    return redirect(url_for("home") if current_user_id() else url_for("login"))

@app.route("/dashboard")
@app.route("/home")
def home():
    return render_template("dashboard.html")

@app.route("/workouts", methods=["GET"])
@login_required
def workouts():
    uid = current_user_id()
    db = SessionLocal()
    try:
        q = (
            db.query(WorkoutLog)
              .filter(WorkoutLog.user_id == uid)
              .order_by(WorkoutLog.id.desc())
              .limit(50)
        )
        rows = q.all()
    finally:
        db.close()
    return render_template("workouts.html", workouts=rows)

@app.post("/add_workout")
@login_required
def add_workout():
    uid = current_user_id()
    exercise = request.form["exercise"]
    reps = int(request.form["reps"])
    weight = float(request.form["weight"])
    sets = int(request.form.get("sets", 1))
    date = request.form.get("date") or datetime.today().strftime("%Y-%m-%d")
    day_code = request.form.get("day_code") or ""       # NEW (optional)
    program_id = request.form.get("program_id") or None
    try:
        program_id = int(program_id) if program_id else None
    except ValueError:
        program_id = None

    db = SessionLocal()
    try:
        log = WorkoutLog(
            user_id=uid,
            exercise=exercise,
            reps=reps,
            sets=sets,
            weight_kg=weight,
            date=date,
            day_name=datetime.strptime(date, "%Y-%m-%d").strftime("%A"),
            source="manual",
            day_code=day_code,
            program_id=program_id
        )
        db.add(log)
        db.commit()
        flash("Workout added!", "info")

        # PR notifications
        check_pr_and_notify(db, uid, exercise, weight)

        # Append to CSV for manual adds
        try:
            now_utc = datetime.now(timezone.utc)
            append_rows_to_csv([{
                "user_id": uid,
                "username": session.get("username",""),
                "timestamp": now_utc.isoformat(timespec="seconds"),
                "date": date,
                "day_name": log.day_name or "",
                "time_hhmm": now_utc.strftime("%H:%M"),
                "program": log.program or "",
                "program_id": program_id or "",
                "day_code": day_code or "",
                "session_id": log.session_id or "",
                "exercise": log.exercise or "",
                "sets": log.sets or "",
                "reps": log.reps or "",
                "weight_kg": log.weight_kg or "",
                "rpe": log.rpe or "",
                "volume_kg": log.volume_kg or "",
                "duration_min": log.duration_min or "",
                "notes": (log.notes or "").replace("\n", " "),
                "source": log.source or "manual",
            }])
        except Exception as e:
            app.logger.error(f"CSV append failed (add_workout): {e}")
    finally:
        db.close()
    return redirect(url_for("workouts"))

@app.route("/logs", strict_slashes=False)
@login_required
def logs_page():
    return render_template("logs.html")

# -----------------------------------------------------------------------------
# Auth pages
# -----------------------------------------------------------------------------
@app.get("/login")
def login():
    return render_template("login.html")

@app.post("/login")
def login_post():
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    if not username or not password:
        flash("Please enter username & password", "error")
        return redirect(url_for("login"))

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            flash("Invalid username or password", "error")
            return redirect(url_for("login"))

        if user.password_hash.startswith("scrypt:") and not HAS_SCRYPT:
            flash("Your password uses 'scrypt', which isn't supported on this system. "
                  "Ask an admin to reset your password, or create a new account.", "error")
            return redirect(url_for("login"))

        ok = False
        try:
            ok = check_password_hash(user.password_hash, password)
        except AttributeError:
            flash("Login hash method isn't supported on this system. "
                  "Please reset your password from the Admin → Users page.", "error")
            return redirect(url_for("login"))

        if not ok:
            flash("Invalid username or password", "error")
            return redirect(url_for("login"))

        session["uid"] = user.id
        session["username"] = user.username
        session["email"] = user.email
        session["role"] = user.role

        nxt = request.args.get("next")
        if not nxt or not nxt.startswith("/"):
            nxt = url_for("home")
        return redirect(nxt)
    finally:
        db.close()

@app.get("/signup")
def signup():
    return render_template("signup.html")

@app.post("/signup")
def signup_post():
    email = (request.form.get("email") or "").strip().lower()
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or ""
    confirm  = request.form.get("confirm") or ""
    if not email or not username or not password:
        flash("Email, username and password are required", "error")
        return redirect(url_for("signup"))
    if password != confirm:
        flash("Passwords do not match", "error")
        return redirect(url_for("signup"))

    db = SessionLocal()
    try:
        if db.query(User).filter(User.username == username).first():
            flash("Username already exists", "error")
            return redirect(url_for("signup"))
        if db.query(User).filter(User.email == email).first():
            flash("Email already exists", "error")
            return redirect(url_for("signup"))

        u = User(
            email=email,
            username=username,
            password_hash=generate_password_hash(password, method=PW_METHOD, salt_length=PW_SALT_LEN),
            role="user",
            created_at=datetime.now(timezone.utc).isoformat(timespec="seconds")
        )
        db.add(u)
        db.commit()
        flash("Account created. Please log in.", "info")
        return redirect(url_for("login"))
    finally:
        db.close()

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# -----------------------------------------------------------------------------
# API: Create logs from PWA page
# -----------------------------------------------------------------------------
@app.post("/api/logs")
@login_required
def api_create_logs():
    data = request.get_json(silent=True)
    if data is None:
        return jsonify({"ok": False, "error": "invalid or missing JSON"}), 400
    rows = data.get("rows")
    if not isinstance(rows, list) or not rows:
        return jsonify({"ok": False, "error": "no rows"}), 400

    uid = current_user_id()
    db = SessionLocal()
    try:
        csv_rows = []
        inserted = []

        for r in rows:
            # NEW fields
            day_code = r.get("day_code")
            program_id = r.get("program_id")
            try:
                program_id = int(program_id) if program_id is not None else None
            except (TypeError, ValueError):
                program_id = None

            rec = WorkoutLog(
                user_id=uid,
                session_id=r.get("session_id"),
                date=r.get("date"),
                day_name=r.get("day_name"),
                program=r.get("program"),
                exercise=r.get("exercise"),
                sets=r.get("sets"),
                reps=r.get("reps"),
                weight_kg=r.get("weight_kg"),
                rpe=str(r.get("rpe") or ""),
                volume_kg=r.get("volume_kg"),
                duration_min=r.get("duration_min"),
                notes=(r.get("notes") or "")[:255],
                source=r.get("source") or "pwa",
                day_code=day_code,
                program_id=program_id
            )
            db.add(rec)
            inserted.append(rec)

            # CSV time columns
            ts = r.get("timestamp")
            if ts:
                try:
                    dt = datetime.fromisoformat(ts.replace("Z",""))
                except Exception:
                    dt = datetime.now(timezone.utc)
            else:
                dt = datetime.now(timezone.utc)

            csv_rows.append({
                "user_id": uid,
                "username": session.get("username",""),
                "timestamp": dt.isoformat(timespec="seconds"),
                "date": r.get("date") or "",
                "day_name": r.get("day_name") or "",
                "time_hhmm": dt.strftime("%H:%M"),
                "program": r.get("program") or "",
                "program_id": program_id or "",
                "day_code": day_code or "",
                "session_id": r.get("session_id") or "",
                "exercise": r.get("exercise") or "",
                "sets": r.get("sets") or "",
                "reps": r.get("reps") or "",
                "weight_kg": r.get("weight_kg") or "",
                "rpe": r.get("rpe") or "",
                "volume_kg": r.get("volume_kg") or "",
                "duration_min": r.get("duration_min") or "",
                "notes": (r.get("notes") or "").replace("\n", " "),
                "source": (r.get("source") or "pwa"),
            })

        db.commit()

        # PR notifications
        for rec in inserted:
            try:
                if rec.weight_kg is not None:
                    check_pr_and_notify(db, uid, rec.exercise, rec.weight_kg)
            except Exception as _e:
                app.logger.warning(f"PR notify error: {_e}")

        try:
            append_rows_to_csv(csv_rows)
        except Exception as e:
            app.logger.error(f"CSV append failed (api/logs): {e}")

        return jsonify({"ok": True, "saved": len(rows)})
    except Exception as e:
        db.rollback()
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        db.close()

# -----------------------------------------------------------------------------
# API: list logs
# -----------------------------------------------------------------------------
@app.get("/api/logs")
@login_required
def api_list_logs():
    try:
        limit = int(request.args.get("limit", 100))
    except ValueError:
        limit = 100
    limit = min(max(limit, 1), 1000)

    uid = current_user_id()
    db = SessionLocal()
    try:
        q = (
            db.query(WorkoutLog)
              .filter(WorkoutLog.user_id == uid)
              .order_by(WorkoutLog.id.desc())
              .limit(limit)
        )
        items = [{
            "id": x.id,
            "timestamp": x.timestamp.isoformat(timespec="seconds") if isinstance(x.timestamp, datetime) else str(x.timestamp),
            "session_id": x.session_id,
            "date": x.date,
            "day_name": x.day_name,
            "program": x.program,
            "program_id": x.program_id,
            "day_code": x.day_code,
            "exercise": x.exercise,
            "sets": x.sets,
            "reps": x.reps,
            "weight_kg": x.weight_kg,
            "rpe": x.rpe,
            "volume_kg": x.volume_kg,
            "duration_min": x.duration_min,
            "notes": x.notes,
            "source": x.source,
        } for x in q]
        return jsonify({"ok": True, "items": items})
    finally:
        db.close()

# -----------------------------------------------------------------------------
# NEW: API — list programs (user + admin-templates)
# -----------------------------------------------------------------------------
@app.get("/api/programs")
@login_required
def api_list_programs():
    uid = current_user_id()
    db = SessionLocal()
    try:
        programs = []
        prog_rows = db.query(Program).filter(
            (Program.user_id == uid) | (Program.user_id.is_(None))
        ).order_by(Program.id.asc()).all()

        for p in prog_rows:
            days = db.query(RoutineDay).filter(RoutineDay.program_id == p.id).order_by(RoutineDay.order_index.asc()).all()
            program_days = []
            for d in days:
                exs = db.query(RoutineExercise).filter(RoutineExercise.day_id == d.id).order_by(RoutineExercise.id.asc()).all()
                program_days.append({
                    "id": d.id,
                    "code": d.code,
                    "title": d.title,
                    "order_index": d.order_index,
                    "exercises": [
                        {
                            "id": ex.id,
                            "exercise": ex.exercise,
                            "sets": ex.sets,
                            "reps": ex.reps,
                            "target_rpe": ex.target_rpe,
                            "note": ex.note or ""
                        }
                        for ex in exs
                    ]
                })
            programs.append({"id": p.id, "name": p.name, "user_id": p.user_id, "days": program_days})
        return jsonify({"ok": True, "programs": programs})
    finally:
        db.close()

# -----------------------------------------------------------------------------
# OPTIONAL: seed an admin template program (call once)
# -----------------------------------------------------------------------------
@app.post("/admin/seed_default_program")
@admin_required
def admin_seed_default_program():
    """
    Creates a default 4-day Upper/Lower template program (user_id = NULL) if it doesn't exist.
    """
    db = SessionLocal()
    try:
        existing = db.query(Program).filter(Program.user_id.is_(None), Program.name == "Upper/Lower (Template)").first()
        if existing:
            return jsonify({"ok": True, "created": False, "program_id": existing.id})

        p = Program(user_id=None, name="Upper/Lower (Template)")
        db.add(p); db.flush()

        spec = [
            ("upper_a", "Day 1 - Upper A", [
                ("Flat chest press", 2, 8, "8"), ("Shoulder press", 2, 10, "8"),
                ("Upper back row", 2, 10, "8"), ("Lat pulldown", 2, 10, "8"),
                ("Tricep push down", 2, 12, "8"), ("Bicep curl", 2, 12, "8")
            ]),
            ("lower_a", "Day 2 - Lower A", [
                ("Squat pattern / Leg press", 2, 8, "8"), ("Seated hammy", 2, 10, "8"),
                ("Leg extensions", 1, 12, "8"), ("Adductors", 2, 12, "8"),
                ("Calves", 2, 12, "8"), ("Abs", 2, 15, "8")
            ]),
            ("upper_b", "Day 4 - Upper B", [
                ("Upper back row", 2, 10, "8"), ("Lat biased row", 2, 10, "8"),
                ("Incline chest press", 2, 8, "8"), ("Lateral raise", 2, 12, "8"),
                ("Tricep compound (dips, JM)", 2, 8, "8"), ("Bicep curl", 2, 12, "8")
            ]),
            ("lower_b", "Day 5 - Lower B", [
                ("Hip hinge (RDL , hyperextensions)", 2, 8, "8"),
                ("Squat pattern / Leg press", 1, 8, "8"),
                ("Leg extension", 1, 12, "8"),
                ("Lying hammy", 1, 10, "8"),
                ("Adductors", 2, 12, "8"),
                ("Calves", 2, 12, "8"),
                ("Abs", 2, 15, "8")
            ]),
        ]

        for idx, (code, title, exercises) in enumerate(spec):
            d = RoutineDay(program_id=p.id, code=code, title=title, order_index=idx)
            db.add(d); db.flush()
            for (name, sets, reps, rpe) in exercises:
                db.add(RoutineExercise(
                    day_id=d.id, exercise=name, sets=sets, reps=reps, target_rpe=rpe
                ))

        db.commit()
        return jsonify({"ok": True, "created": True, "program_id": p.id})
    finally:
        db.close()

# -----------------------------------------------------------------------------
# API: export to Google Sheets (optional)
# -----------------------------------------------------------------------------
def _collect_rows_for_export(uid: int, limit: int = 100):
    db = SessionLocal()
    try:
        items = (
            db.query(WorkoutLog)
              .filter(WorkoutLog.user_id == uid)
              .order_by(WorkoutLog.id.desc())
              .limit(limit)
              .all()
        )
        return [{
            "timestamp": x.timestamp.isoformat(timespec="seconds") if isinstance(x.timestamp, datetime) else str(x.timestamp),
            "date": x.date, "day_name": x.day_name, "program": x.program,
            "program_id": x.program_id, "day_code": x.day_code,
            "session_id": x.session_id, "exercise": x.exercise, "sets": x.sets,
            "reps": x.reps, "weight_kg": x.weight_kg, "rpe": x.rpe,
            "volume_kg": x.volume_kg, "duration_min": x.duration_min,
            "notes": x.notes, "source": x.source
        } for x in items]
    finally:
        db.close()

@app.post("/api/export/google")
@login_required
def api_export_google():
    payload = request.get_json(silent=True) or {}
    rows = payload.get("rows")

    uid = current_user_id()
    username = session.get("username", "")

    if not rows:
        try:
            limit = min(int(request.args.get("limit", 100)), 1000)
        except ValueError:
            limit = 100
        rows = _collect_rows_for_export(uid, limit)

    if not rows:
        return jsonify({"ok": False, "error": "no rows to export"}), 400

    try:
        append_logs_to_sheet(rows, uid, username)
        return jsonify({"ok": True, "exported": len(rows)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# Backward-compatible alias used by an older page: GET /export/google
@app.get("/export/google")
@login_required
def export_google_alias():
    try:
        limit = min(int(request.args.get("limit", 100)), 1000)
    except ValueError:
        limit = 100
    rows = _collect_rows_for_export(current_user_id(), limit)
    if not rows:
        return jsonify({"ok": False, "error": "no rows to export"}), 400
    try:
        append_logs_to_sheet(rows, current_user_id(), session.get("username",""))
        return jsonify({"ok": True, "exported": len(rows)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# -----------------------------------------------------------------------------
# Web Push routes
# -----------------------------------------------------------------------------
@app.get("/vapid-public-key")
def vapid_public_key():
    if not VAPID_PUBLIC_KEY_PEM:
        return jsonify({"ok": False, "error": "public key not configured"}), 500
    return jsonify({"ok": True, "pem": VAPID_PUBLIC_KEY_PEM})

@app.post("/api/push/subscribe")
def api_push_subscribe():
    data = request.get_json(force=True)
    if not data or "endpoint" not in data or "keys" not in data:
        return jsonify({"ok": False, "error": "bad subscription"}), 400
    db = SessionLocal()
    try:
        uid = session.get("uid")
        existing = db.query(PushSubscription).filter_by(endpoint=data["endpoint"]).first()
        if existing:
            existing.p256dh = data["keys"].get("p256dh","")
            existing.auth   = data["keys"].get("auth","")
            existing.user_id = uid
            existing.ua = data.get("ua")
        else:
            db.add(PushSubscription(
                user_id=uid,
                endpoint=data["endpoint"],
                p256dh=data["keys"].get("p256dh",""),
                auth=data["keys"].get("auth",""),
                ua=data.get("ua")
            ))
        db.commit()
        return jsonify({"ok": True})
    finally:
        db.close()

@app.post("/api/push/unsubscribe")
def api_push_unsubscribe():
    data = request.get_json(force=True)
    ep = data.get("endpoint")
    if not ep:
        return jsonify({"ok": False, "error": "missing endpoint"}), 400
    db = SessionLocal()
    try:
        db.query(PushSubscription).filter_by(endpoint=ep).delete()
        db.commit()
        return jsonify({"ok": True})
    finally:
        db.close()

@app.post("/api/push/test")
@admin_required
def api_push_test():
    payload = {"title": "GymLogger", "body": "Push works 🎉", "data": {"url": "/"}}
    db = SessionLocal()
    try:
        sent, failed = send_push_all(db, payload)
        return jsonify({"ok": True, "sent": sent, "failed": failed})
    finally:
        db.close()

# -----------------------------------------------------------------------------
# Admin routes
# -----------------------------------------------------------------------------
@app.get("/admin")
@admin_required
def admin_index():
    db = SessionLocal()
    try:
        users = db.execute(text("SELECT COUNT(*) FROM user")).scalar() or 0
        admins = db.execute(text("SELECT COUNT(*) FROM user WHERE role='admin'")).scalar() or 0
        logs  = db.execute(text("SELECT COUNT(*) FROM workout_log")).scalar() or 0
    finally:
        db.close()
    return render_template("admin/index.html", stats={"users": users, "admins": admins, "logs": logs})

@app.get("/admin/users")
@admin_required
def admin_users():
    q = (request.args.get("q") or "").strip().lower()
    db = SessionLocal()
    try:
        query = db.query(User).order_by(User.id.asc())
        if q:
            query = query.filter(or_(User.username.ilike(f"%{q}%"),
                                     User.email.ilike(f"%{q}%")))
        users = query.limit(500).all()
    finally:
        db.close()
    return render_template("admin/users.html", users=users)

@app.post("/admin/user/<int:user_id>/role")
@admin_required
def admin_user_role(user_id):
    new_role = (request.form.get("role") or "").strip().lower()
    if new_role not in ("user", "admin"):
        flash("Invalid role.", "error")
        return redirect(url_for("admin_users"))

    db = SessionLocal()
    try:
        u = db.get(User, user_id)
        if not u:
            flash("User not found.", "error")
            return redirect(url_for("admin_users"))
        u.role = new_role
        db.commit()
        if session.get("uid") == u.id:
            session["role"] = u.role
        flash(f"Role updated: {u.username} → {new_role}", "info")
    finally:
        db.close()
    return redirect(url_for("admin_users", q=request.args.get("q", "")))

@app.post("/admin/user/<int:user_id>/reset_pw")
@admin_required
def admin_user_reset_pw(user_id):
    temp_pw = secrets.token_urlsafe(8)
    db = SessionLocal()
    try:
        u = db.get(User, user_id)
        if not u:
            flash("User not found.", "error")
            return redirect(url_for("admin_users"))
        u.password_hash = generate_password_hash(temp_pw, method=PW_METHOD, salt_length=PW_SALT_LEN)
        db.commit()
        app.logger.warning(f"[ADMIN] Temporary password for {u.username} ({u.email}): {temp_pw}")
        flash(f"Temporary password set for {u.username}: {temp_pw}", "info")
    finally:
        db.close()
    return redirect(url_for("admin_users", q=request.args.get("q", "")))

@app.get("/admin/logs")
@admin_required
def admin_logs():
    q = (request.args.get("q") or "").strip()
    user_filter = (request.args.get("user") or "").strip()
    try:
        limit = int(request.args.get("limit", 100))
    except ValueError:
        limit = 100
    limit = min(max(limit, 1), 1000)

    db = SessionLocal()
    try:
        qry = db.query(WorkoutLog).order_by(WorkoutLog.id.desc())

        if q:
            like = f"%{q}%"
            qry = qry.filter(or_(WorkoutLog.exercise.ilike(like),
                                 WorkoutLog.notes.ilike(like)))

        if user_filter:
            if user_filter.isdigit():
                qry = qry.filter(WorkoutLog.user_id == int(user_filter))
            else:
                uid_rows = db.query(User.id).filter(User.username.ilike(user_filter)).all()
                ids = [r[0] for r in uid_rows]
                if ids:
                    qry = qry.filter(WorkoutLog.user_id.in_(ids))
                else:
                    qry = qry.filter(text("1=0"))

        rows = qry.limit(limit).all()
    finally:
        db.close()

    return render_template("admin/logs.html", rows=rows)

@app.get("/admin/export/csv")
@admin_required
def admin_export_csv():
    _ensure_csv_header()
    if not CSV_PATH.exists():
        abort(404)
    return send_from_directory(str(DATA_DIR), CSV_PATH.name,
                               as_attachment=True, download_name="logs.csv")

@app.get("/routines")
@login_required
def routines_page():
    return render_template("routines.html")

# -----------------------------------------------------------------------------
# Health checks
# -----------------------------------------------------------------------------
@app.get("/health/app")
def health_app():
    return jsonify({"ok": True, "status": "up"})

@app.get("/health/db")
def health_db():
    db = SessionLocal()
    try:
        user_rows = db.execute(text("SELECT COUNT(*) FROM user")).scalar() or 0
        log_rows  = db.execute(text("SELECT COUNT(*) FROM workout_log")).scalar() or 0
        admins    = db.execute(text("SELECT COUNT(*) FROM user WHERE role='admin'")).scalar() or 0
        return jsonify({"ok": True, "counts": {"user": user_rows, "admins": admins, "workout_log": log_rows}})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        db.close()

@app.get("/health/google")
def health_google():
    try:
        sh = sheets_client().open_by_key(SPREADSHEET_ID)
        title = sh.title
        return jsonify({"ok": True, "sheet_title": title})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.get("/health/csv")
def health_csv():
    try:
        _ensure_csv_header()
        return jsonify({
            "ok": True,
            "csv_path": str(CSV_PATH),
            "exists": CSV_PATH.exists(),
            "size_bytes": CSV_PATH.stat().st_size if CSV_PATH.exists() else 0
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# -----------------------------------------------------------------------------
# PWA bits
# -----------------------------------------------------------------------------
@app.route("/sw.js")
def sw():
    """Serve the service worker with sensible cache headers."""
    try:
        resp = make_response(send_from_directory(".", "sw.js", mimetype="application/javascript"))
        # prevent aggressive CDN caching after deploys
        resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        resp.headers["Pragma"] = "no-cache"
        resp.headers["Expires"] = "0"
        return resp
    except Exception:
        abort(404)

@app.route("/favicon.ico")
def favicon():
    try:
        return send_from_directory("static", "icons/icon-192.png")
    except Exception:
        abort(404)

# -----------------------------------------------------------------------------
# Errors
# -----------------------------------------------------------------------------
@app.errorhandler(404)
def err404(_):
    return render_template("404.html"), 404

@app.errorhandler(500)
def err500(_):
    return render_template("500.html"), 500

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5001)), debug=True)