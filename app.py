import os
import csv
import secrets
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask, render_template, request, jsonify,
    send_from_directory, abort, session, redirect, url_for, flash
)

from sqlalchemy import (
    create_engine, Column, Integer, String, Float, DateTime,
    UniqueConstraint, text, or_
)
from sqlalchemy.orm import declarative_base, sessionmaker
from werkzeug.security import generate_password_hash, check_password_hash

# load .env
from dotenv import load_dotenv
load_dotenv()

# ------------ Password hashing policy ------------
# Force a portable method (your Python build lacks hashlib.scrypt)
PW_METHOD    = os.getenv("PASSWORD_HASH_METHOD", "pbkdf2:sha256")
PW_SALT_LEN  = int(os.getenv("PASSWORD_SALT_LENGTH", "16"))
HAS_SCRYPT   = hasattr(hashlib, "scrypt")  # for friendly messaging on legacy hashes
# -------------------------------------------------

# --- Google Sheets deps ---
import gspread
from google.oauth2.service_account import Credentials

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")

# --- Google Sheets config ---
SERVICE_ACCOUNT_FILE = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")  # absolute path to your JSON
SPREADSHEET_ID      = os.getenv("SHEETS_SPREADSHEET_ID")            # your sheet key
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
    """
    Append rows to the first worksheet. Ensures a single header row exists (no clearing).
    rows: list of dicts with the fields we store in DB/API.
    """
    sh = sheets_client().open_by_key(SPREADSHEET_ID)
    ws = sh.sheet1

    header = [
        "timestamp","date","day_name","program","session_id","exercise",
        "sets","reps","weight_kg","rpe","volume_kg","duration_min","notes",
        "source","user_id","username"
    ]

    # Create header only if the sheet is empty.
    first_row = ws.get_values("A1:Q1")  # Q = 17th column
    if not first_row:
        ws.append_row(header)

    # Prepare data rows
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
        ])

    if data:
        ws.append_rows(data, value_input_option="USER_ENTERED")


# --- CSV export settings + helpers ---
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
CSV_PATH = DATA_DIR / "logs.csv"

CSV_HEADER = [
    "user_id","username",
    "timestamp","date","day_name","time_hhmm",
    "program","session_id","exercise",
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


# --- DB setup ---
engine = create_engine("sqlite:///database.db", echo=False, future=True)
Base = declarative_base()
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

# --- Models ---
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

Base.metadata.create_all(engine)


# --- Auth helpers ---
def current_user_id():
    return session.get("uid")

def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not current_user_id():
            return redirect(url_for("login", next=request.path))
        return view_func(*args, **kwargs)
    return wrapper


# --- Admin helpers ---
def is_admin():
    uid = session.get("uid")
    if not uid:
        return False
    db = SessionLocal()
    try:
        u = db.query(User).get(uid)
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

# Expose a simple flag for templates
@app.context_processor
def inject_flags():
    return {"is_admin": session.get("role") == "admin"}


# --- Pages ---
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
            source="manual"
        )
        db.add(log)
        db.commit()
        flash("Workout added!", "info")

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


# --- Auth pages ---
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

        # Handle legacy scrypt hashes on systems without hashlib.scrypt
        if user.password_hash.startswith("scrypt:") and not HAS_SCRYPT:
            flash("Your password uses 'scrypt', which isn't supported on this system. "
                  "Ask an admin to reset your password, or create a new account.", "error")
            return redirect(url_for("login"))

        ok = False
        try:
            ok = check_password_hash(user.password_hash, password)
        except AttributeError as e:
            # Safety net for environments missing certain hash backends
            flash("Login hash method isn't supported on this system. "
                  "Please reset your password from the Admin → Users page.", "error")
            return redirect(url_for("login"))

        if not ok:
            flash("Invalid username or password", "error")
            return redirect(url_for("login"))

        # Success: set session (include role for template conditionals)
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


# --- API: Create logs from PWA page ---
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
        for r in rows:
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
            )
            db.add(rec)

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

# --- API: list logs ---
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

# --- API: export to Google Sheets ---
@app.post("/api/export/google")
@login_required
def api_export_google():
    """
    Accepts optional JSON: {"rows": [ ... ]}.
    If not provided, exports the latest N rows from the DB for the current user.
    """
    payload = request.get_json(silent=True) or {}
    rows = payload.get("rows")

    uid = current_user_id()
    username = session.get("username", "")

    if not rows:
        try:
            limit = min(int(request.args.get("limit", 100)), 1000)
        except ValueError:
            limit = 100
        db = SessionLocal()
        try:
            items = (
                db.query(WorkoutLog)
                  .filter(WorkoutLog.user_id == uid)
                  .order_by(WorkoutLog.id.desc())
                  .limit(limit)
                  .all()
            )
            rows = [{
                "timestamp": x.timestamp.isoformat(timespec="seconds") if isinstance(x.timestamp, datetime) else str(x.timestamp),
                "date": x.date, "day_name": x.day_name, "program": x.program,
                "session_id": x.session_id, "exercise": x.exercise, "sets": x.sets,
                "reps": x.reps, "weight_kg": x.weight_kg, "rpe": x.rpe,
                "volume_kg": x.volume_kg, "duration_min": x.duration_min,
                "notes": x.notes, "source": x.source
            } for x in items]
        finally:
            db.close()

    if not rows:
        return jsonify({"ok": False, "error": "no rows to export"}), 400

    try:
        append_logs_to_sheet(rows, uid, username)
        return jsonify({"ok": True, "exported": len(rows)})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


# ---------- ADMIN ROUTES ----------
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
        u = db.query(User).get(user_id)
        if not u:
            flash("User not found.", "error")
            return redirect(url_for("admin_users"))
        u.role = new_role
        db.commit()
        # keep my session in sync if I changed my own role
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
        u = db.query(User).get(user_id)
        if not u:
            flash("User not found.", "error")
            return redirect(url_for("admin_users"))
        # re-hash with PBKDF2 so it works everywhere
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
    """Download the consolidated CSV that the app writes to disk."""
    _ensure_csv_header()
    if not CSV_PATH.exists():
        abort(404)
    return send_from_directory(str(DATA_DIR), CSV_PATH.name,
                               as_attachment=True, download_name="logs.csv")


# --- Health checks ---
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


# --- PWA bits ---
@app.route("/sw.js")
def sw():
    try:
        return send_from_directory(".", "sw.js", mimetype="application/javascript")
    except Exception:
        abort(404)

@app.route("/favicon.ico")
def favicon():
    try:
        return send_from_directory("static", "icons/icon-192.png")
    except Exception:
        abort(404)


# --- Errors ---
@app.errorhandler(404)
def err404(_):
    return render_template("404.html"), 404

@app.errorhandler(500)
def err500(_):
    return render_template("500.html"), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)