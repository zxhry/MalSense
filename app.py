"""
MalSense web app (Flask) - pages designed to match thesis Chapter 5.
Run  : python app.py     then open http://127.0.0.1:5000
Done : Splash (5.1), Home (5.2/5.3), Register (5.4), Login (5.5), Scan results (5.6),
       scan records saved to MySQL (Fig 4.3), My History (UC05).
       Explainable AI, downloadable report (PDF/DOCX), awareness quiz (5.7-5.10),
       Admin: Users (5.11), Scan logs (5.12), ML model (5.13).
       Supervisor changes: separate "Learn" upload (AI quiz) on the home page, users can report APKs
       to the admin, admin adds reported APKs to the training data and retrains (Reports page).
Make an admin: flask --app app make-admin your@email.com
"""
import os, re, sys, uuid, time, hashlib, hmac
from datetime import datetime, timedelta, timezone
from functools import wraps
import click
from urllib.parse import quote_plus
from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, flash, abort, send_file, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect, CSRFError

load_dotenv()                                            # reads .env (keys, DB password)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from final_verdict import full_scan, VT_CONFIRM, RULES, rule_id   # model + VirusTotal + risk level
import malsense_scanner
from model_info import get_model_info, retrain
from models import db, User, Scan, Report, QuizLog
from report import report_data, build_pdf, build_docx
from quiz import new_quiz, load_quiz
from malware_type import safe_malware_type             # intents + API calls found in the APK (no AI model; list from CICMalDroid)
import new_samples
import account_security as sec
import threat_intel as ti
import csv, json
from collections import Counter
from explain import PERMISSION_TEXT
from advice import advice_for                            # "What to do next" box on the results page
import google_login as google                            # "Continue with Google" sign-in
import feedback as fb                                    # Feedback form (emails the owner)
import io

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "dev-only-change-me")
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024   # reject uploads bigger than 100 MB
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL") or (
    "mysql+pymysql://{u}:{p}@{h}:{port}/{d}".format(
        u=quote_plus(os.getenv("DB_USER", "")), p=quote_plus(os.getenv("DB_PASSWORD", "")),
        h=os.getenv("DB_HOST", "localhost"), port=os.getenv("DB_PORT", "3306"),
        d=os.getenv("DB_NAME", "malsense")))
# Online database (TiDB Cloud): it only accepts encrypted (TLS) connections and closes idle ones,
# so check each connection before using it and replace connections older than 5 minutes.
_engine = {"pool_pre_ping": True, "pool_recycle": 300}
if os.getenv("DB_SSL", "").lower() in ("1", "true", "yes"):
    import certifi                                       # trusted CA list (installed with requests)
    _engine["connect_args"] = {"ssl": {"ca": certifi.where()}}
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = _engine

# Running online on Render (Render sets RENDER=true): one proxy sits in front of MalSense, so trust its
# X-Forwarded-* headers (links in emails / Google sign-in use https://...), and only send cookies over HTTPS.
ONLINE = os.getenv("RENDER", "").lower() == "true" or os.getenv("MALSENSE_ONLINE", "") == "1"
if ONLINE:
    if app.config["SECRET_KEY"] in (None, "", "dev-only-change-me"):
        raise SystemExit("Set a long random FLASK_SECRET_KEY environment variable before going online.")
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    app.config.update(SESSION_COOKIE_SECURE=True, REMEMBER_COOKIE_SECURE=True, PREFERRED_URL_SCHEME="https")

# PUBLIC_URL (set on Render, e.g. https://malsense.onrender.com): links in emails and the Google sign-in
# return address always use the online address, even when the email is sent from a copy running on a laptop.
PUBLIC_URL = os.getenv("PUBLIC_URL", "").strip().rstrip("/")
if PUBLIC_URL:
    from flask import url_for as _flask_url_for

    def url_for(endpoint, **values):
        if values.pop("_external", False):
            values.pop("_scheme", None)
            return PUBLIC_URL + _flask_url_for(endpoint, **values)
        return _flask_url_for(endpoint, **values)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"           # extra protection for the login cookie

db.init_app(app)
# the results page uses the SAME rules and cut-off as final_verdict.py, so they can never disagree
app.jinja_env.globals.update(VT_CONFIRM=VT_CONFIRM, RULES=RULES, rule_id=rule_id, PERMISSION_TEXT=PERMISSION_TEXT,
                             attack_techniques=ti.attack_techniques, family_of=ti.family_of,
                             advice_for=advice_for,
                             # Terms of Use / Privacy Policy pages
                             LEGAL_UPDATED="3 November 2026")
csrf = CSRFProtect(app)                                  # every form needs a hidden csrf_token
# The form token normally expires after 1 hour, so a page left open (e.g. Home before uploading an APK)
# failed with "The CSRF token has expired". The token stays tied to the login session, so it is still
# protected - it just no longer runs out while the page is open.
app.config["WTF_CSRF_TIME_LIMIT"] = None


@app.errorhandler(CSRFError)
def csrf_failed(e):
    """Friendly message instead of the plain "Bad Request" page; send the user back to try again."""
    flash("This page was open for too long or your session changed. Please try again.")
    from urllib.parse import urlsplit
    ref = urlsplit(request.referrer or "")
    back = safe_next(ref.path) if ref.netloc == request.host and ref.path not in ("", "/") else ""
    return redirect(back or url_for("home"))
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to see that page."
login_manager.login_message_category = "message"

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
REPORT_DIR = os.path.join(os.path.dirname(__file__), "reported_apks")   # APKs users reported (kept for the admin)
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@login_manager.user_loader
def load_user(user_id):
    user = db.session.get(User, int(user_id))
    return user if user and user.is_active else None    # a deactivated user is logged out immediately


def admin_required(view):
    """Only admins may open admin pages (everyone else gets 403 Forbidden)."""
    @wraps(view)
    @login_required
    def wrapper(*args, **kwargs):
        if not current_user.is_admin:
            abort(403)
        return view(*args, **kwargs)
    return wrapper


@app.cli.command("make-admin")
@click.argument("email")
def make_admin(email):
    """Give an existing account the admin role:  flask --app app make-admin you@example.com"""
    user = User.query.filter_by(email=email.strip().lower()).first()
    if not user:
        print(f"No account with email {email} - register it on the website first.")
        return
    user.role = "admin"
    user.verified = True                                 # an admin made from the command line is trusted
    db.session.commit()
    print(f"{user.username} ({user.email}) is now an admin.")


# ------------------------------------------------------------------ pages
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")   # stricter email check (overrides the one above)


@app.route("/")
def splash():                                           # Figure 5.1
    return render_template("splash.html")


@app.route("/home")
def home():                                             # Figures 5.2 and 5.3
    try:                                                 # real test-set numbers for the stats strip
        metrics = get_model_info(malsense_scanner.BUNDLE)["metrics"]
    except Exception:
        metrics = None
    return render_template("index.html", metrics=metrics)


def receive_apk(folder=UPLOAD_DIR, suffix=".apk"):
    """Check the uploaded file and save it under a random name (never trust the user's file name).
    Returns (path, original file name), or (None, None) after flashing a message."""
    file = request.files.get("apk")
    if not file or file.filename == "":
        flash("Please choose an APK file first.")
        return None, None
    if not file.filename.lower().endswith(".apk"):
        flash("Only .apk files can be uploaded.")
        return None, None
    path = os.path.join(folder, f"{uuid.uuid4().hex}{suffix}")
    file.save(path)
    try:
        with open(path, "rb") as fh:
            is_zip = fh.read(2) == b"PK"                 # every real APK is a ZIP file
    except OSError as e:                                 # usually antivirus blocking/quarantining the upload
        app.logger.warning(f"Could not open uploaded file {file.filename}: {e}")
        try:
            os.remove(path)
        except OSError:
            pass
        flash("This file was blocked by antivirus on the server, so MalSense could not read it. "
              "The admin needs to add an antivirus exclusion for the uploads folder.")
        return None, None
    if not is_zip:
        os.remove(path)
        flash("This file is not a valid APK.")
        return None, None
    return path, file.filename


# ------------------------------------------------------------------ Daily limits (protect the Gemini / VirusTotal quotas)
# Each logged-in user may scan SCAN_LIMIT_PER_DAY APKs and make QUIZ_LIMIT_PER_DAY quizzes a day (default 3 each,
# 0 = no limit; change them in .env / Render without touching the code). The day resets at midnight Malaysia time.
# Admins are never limited.
SCAN_LIMIT = int(os.getenv("SCAN_LIMIT_PER_DAY", "3") or 0)
QUIZ_LIMIT = int(os.getenv("QUIZ_LIMIT_PER_DAY", "3") or 0)
# True (default) = users must log in to scan, so every scan counts toward their daily limit.
# Set REQUIRE_LOGIN_TO_SCAN=false to let guests scan (the quiz always needs an account).
REQUIRE_LOGIN_TO_SCAN = os.getenv("REQUIRE_LOGIN_TO_SCAN", "true").strip().lower() not in ("0", "false", "no", "off")
app.jinja_env.globals["REQUIRE_LOGIN_TO_SCAN"] = REQUIRE_LOGIN_TO_SCAN
MYT = timezone(timedelta(hours=8))                      # Malaysia time (no daylight saving)


def today_start():
    """Midnight today in Malaysia, in the server's own clock (the same clock scanned_at is saved in)."""
    start = datetime.now(MYT).replace(hour=0, minute=0, second=0, microsecond=0)
    return start.astimezone().replace(tzinfo=None)


def usage_today(user):
    since = today_start()
    return {"scans": Scan.query.filter(Scan.user_id == user.user_id, Scan.scanned_at >= since).count(),
            "quizzes": QuizLog.query.filter(QuizLog.user_id == user.user_id, QuizLog.created_at >= since).count()}


def limit_reached(kind):
    """A message if the current user has used up today's scans / quizzes, otherwise None."""
    limit = SCAN_LIMIT if kind == "scans" else QUIZ_LIMIT
    if not limit or not current_user.is_authenticated or current_user.is_admin:
        return None
    if usage_today(current_user)[kind] >= limit:
        what = "APK scans" if kind == "scans" else "quizzes"
        return f"You have used all {limit} {what} for today. Your limit resets at midnight (Malaysia time)."
    return None


def must_log_in(what, anchor):
    flash(f"Please log in to {what}.")
    return redirect(url_for("login", next=url_for("home", _anchor=anchor)))


@app.route("/scan", methods=["POST"])
def scan():                                             # Figure 5.6 - home section 1: "Scan an APK"
    if REQUIRE_LOGIN_TO_SCAN and not current_user.is_authenticated:   # logged-in users, so each scan counts toward their limit
        return must_log_in("analyse an APK", "scan")
    msg = limit_reached("scans")
    if msg:
        flash(msg)
        return redirect(url_for("home", _anchor="scan"))
    path, filename = receive_apk()
    if not path:
        return redirect(url_for("home"))
    start = time.time()
    try:
        result = full_scan(path)
        if result.get("risk") != "LOW":                  # 2nd AI model: what kind of malware is it?
            result["malware_type"] = safe_malware_type(path, app.logger.warning)
    except Exception as e:
        app.logger.warning(f"Could not analyse {filename}: {e}")
        flash("MalSense could not analyse this APK - it may use a format or protection our scanner does not "
              "support yet. Please report it so the admin can update MalSense"
              + ("." if current_user.is_authenticated else " (log in first)."))
        return redirect_to_report("scan_failed")
    finally:
        if os.path.exists(path):
            os.remove(path)                              # uploaded APKs are not kept

    duration = time.time() - start
    scan = save_scan(result, filename, duration)      # Figure 4.3: save scan record to MySQL
    if scan:
        # Registered users: number comes from the database (their 1st, 2nd, 3rd scan ...).
        # Guests: number is kept in this browser's session, so it also starts at 1.
        no = scan.user_scan_no if current_user.is_authenticated else remember_guest_scan(scan.scan_id)
        # Post/Redirect/Get: send the browser to a normal page, so Back/Refresh never re-uploads the APK
        return redirect(url_for("result", no=no))
    return render_template("result.html", r=result, filename=filename,           # DB unavailable:
                           duration=duration, saved=False, scan_no=None, links={},  # show result directly
                           scanned_on=datetime.now().strftime("%d %b %Y, %H:%M"))


# ------------------------------------------------------------------ per-user scan numbers
# scan_id (the MySQL primary key) is never shown in a URL. Every user sees their own
# numbers 1, 2, 3 ... so /result/3 means "MY third scan" - nobody can guess another
# person's scan, and the URL does not reveal how many scans the whole system has.
def guest_scans():
    """Guests have no account, so their numbers live in this browser's session: {"1": scan_id, ...}"""
    g = session.get("guest_scans")
    return g if isinstance(g, dict) else {}


def remember_guest_scan(scan_id):
    g = guest_scans()
    no = session.get("guest_next", 1)
    g[str(no)] = scan_id
    for old in sorted(g, key=int)[:-20]:                 # remember only the last 20 guest scans
        del g[old]
    session["guest_scans"], session["guest_next"] = g, no + 1
    return no


def find_my_scan(no):
    """Look up scan number <no> of the CURRENT visitor only. Anything else is simply 'not found'."""
    if current_user.is_authenticated:
        scan = Scan.query.filter_by(user_id=current_user.user_id, user_scan_no=no).first()
    else:
        scan_id = guest_scans().get(str(no))
        scan = db.session.get(Scan, scan_id) if scan_id else None
    if not scan:
        abort(404)
    return scan


@app.route("/result/<int:no>")
def result(no):                                         # Figure 5.6 - rebuilt from the saved scan
    scan = find_my_scan(no)
    links = {}
    if current_user.is_authenticated:
        links |= {"pdf": url_for("download_report", no=no, fmt="pdf"),
                  "docx": url_for("download_report", no=no, fmt="docx")}
    return render_result(scan, no, links)


def render_result(scan, no, links):
    d = scan.details or {}
    if not d:
        flash("Full details are not available for this older scan - please scan the file again.")
        return redirect(url_for("history"))
    try:
        size_bytes = d.get("file_size") or float(scan.file_size.split()[0]) * 1048576
    except ValueError:
        size_bytes = 0
    r = dict(d, sha256=scan.file_hash, package=scan.package_name, file_size=size_bytes,
             min_sdk=d.get("min_sdk") or (scan.sdk_version or "").replace("API ", "") or None)
    return render_template("result.html", r=r, filename=scan.filename, duration=scan.scan_duration or 0,
                           saved=current_user.is_authenticated and scan.user_id == current_user.user_id,
                           scan_no=no, links=links,
                           scanned_on=scan.scanned_at.strftime("%d %b %Y, %H:%M"))


def save_scan(r, filename, duration):
    """Store one scan in the 'scans' table. Guests are saved with user_id = NULL.
    A database problem must never stop the user from seeing their result."""
    p = r["malware_probability"]
    vt = r["virustotal"]
    user_id = current_user.user_id if current_user.is_authenticated else None
    scan = Scan(
        user_id=user_id,
        filename=filename[:255],
        file_size=f"{r['file_size'] / 1048576:.1f} MB",
        file_hash=r["sha256"],
        package_name=(r.get("package") or "")[:255] or None,
        sdk_version=f"API {r['min_sdk']}" if r.get("min_sdk") else None,
        ml_result="Malware" if r["verdict"] == "MALWARE" else "Benign",
        confidence=round((p if r["verdict"] == "MALWARE" else 1 - p) * 100, 1),
        vt_result=vt["detection_ratio"] if vt.get("status") == "found" else vt.get("status", "error").replace("_", " "),
        scan_duration=round(duration, 2),
        details={                                          # everything the downloadable report needs
            k: r.get(k) for k in ("app_name", "md5", "sha1", "malware_probability", "verdict", "risk",
                                  "reason", "action", "explanation", "dangerous_permissions",
                                  "custom_permissions", "permissions", "min_sdk", "file_size", "malware_type")} | {
            "virustotal": {k: v for k, v in vt.items()},
            "counts": {k: r["features"][k] for k in ("total_perm", "nr_permissions", "normal",
                                                       "dangerous", "signature", "nr_custom")},
            "dangerous_text": {p: PERMISSION_TEXT.get(p, "-") for p in r["dangerous_permissions"]}})
    for attempt in range(3):                             # retry if two scans of the same user collide
        try:
            if user_id:                                  # this user's next number: 1, 2, 3 ...
                last = db.session.query(db.func.max(Scan.user_scan_no)).filter(Scan.user_id == user_id).scalar()
                scan.user_scan_no = (last or 0) + 1
            db.session.add(scan)
            db.session.commit()
            return scan
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Could not save scan to database: {e}")
    return None


# ------------------------------------------------------------------ accounts (Figure 4.4)
@app.route("/register", methods=["GET", "POST"])
def register():                                         # Figure 5.4
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    form = {"name": "", "email": ""}
    field_errors = {}                                    # errors shown under a specific box
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        pw, pw2 = request.form.get("password", ""), request.form.get("confirm", "")
        form = {"name": name, "email": email}

        # 1. Input valid?
        errors = []
        if len(name) < 2:
            errors.append("Please enter your full name.")
        if not EMAIL_RE.match(email):
            errors.append("Please enter a valid email address.")
        if password_problem(pw):
            errors.append(password_problem(pw))
        if not errors and EMAIL_RE.match(email) and sec.email_problem(email):   # real-email checks
            errors.append(sec.email_problem(email))
        if not request.form.get("agree"):                # must accept the Terms of Use + Privacy Policy
            field_errors["agree"] = "Please agree to the Terms of Use and Privacy Policy to create an account."
        if not pw2:
            field_errors["confirm"] = "Please confirm your password."
        elif pw != pw2:
            field_errors["confirm"] = "Passwords do not match."
        # 2. Email taken?
        if not errors and not field_errors and User.query.filter_by(email=email).first():
            errors.append("An account with this email already exists.")
        if errors or field_errors:
            for e in errors:
                flash(e)
            return render_template("register.html", form=form, field_errors=field_errors)

        # 3. Hash password (bcrypt) and INSERT into MySQL - NOT verified yet
        user = User(username=name, email=email, role="user", verified=False)
        user.set_password(pw)
        db.session.add(user)
        db.session.commit()
        # 4. Send the verification link - the account cannot log in until it is clicked
        send_verification_email(user)
        session["pending_email"] = email
        return redirect(url_for("verify_sent"))
    return render_template("register.html", form=form, field_errors=field_errors)


@app.route("/login", methods=["GET", "POST"])
def login():                                            # Figure 5.5
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    email = ""
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        # Same message for "no such email" and "wrong password" so attackers
        # cannot find out which emails are registered
        if not user or not user.check_password(pw):
            flash("Incorrect email or password.")
            return render_template("login.html", email=email)
        if not user.is_active:
            flash("This account has been deactivated. Please contact the administrator.")
            return render_template("login.html", email=email)
        if not user.verified:                            # shown only after the correct password
            flash("Please verify your email first - check your inbox (and spam folder) for the link.")
            return render_template("login.html", email=email, unverified=True)
        login_user(user, remember=bool(request.form.get("remember")))
        user.last_login = datetime.now()
        db.session.commit()
        flash(f"Welcome back, {user.username.split()[0]}!", "success")
        nxt = request.args.get("next", "")
        if nxt.startswith("/") and not nxt.startswith("//") and "\\" not in nxt:   # only pages on this site
            return redirect(nxt)
        return redirect(url_for("admin_users" if user.is_admin else "home"))
    return render_template("login.html", email=email)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("home"))


# ------------------------------------------------------------------ "Continue with Google"
def safe_next(nxt):
    """Only allow redirects to pages on this site (stops open-redirect tricks)."""
    nxt = nxt or ""
    return nxt if nxt.startswith("/") and not nxt.startswith("//") and "\\" not in nxt else ""


@app.route("/auth/google")
def google_login():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    if not google.configured():
        flash("Google sign-in is not set up yet - please use your email and password.")
        return redirect(url_for("login"))
    callback = google.redirect_uri(url_for("google_callback", _external=True))
    url, state, verifier = google.start(callback)
    session["g_state"], session["g_verifier"] = state, verifier
    session["g_next"] = safe_next(request.args.get("next"))
    return redirect(url)


@app.route("/auth/google/callback")
def google_callback():
    import secrets
    state, verifier = session.pop("g_state", None), session.pop("g_verifier", None)
    nxt = session.pop("g_next", "")
    if request.args.get("error"):                        # user pressed Cancel on Google's page
        flash("Google sign-in was cancelled.")
        return redirect(url_for("login"))
    if not state or not verifier or not secrets.compare_digest(request.args.get("state", ""), state):
        flash("Google sign-in failed a security check. Please try again.")
        return redirect(url_for("login"))
    try:
        info = google.finish(request.args.get("code", ""), verifier,
                             google.redirect_uri(url_for("google_callback", _external=True)))
    except google.GoogleLoginError as e:
        app.logger.warning(f"Google sign-in failed: {e}")
        flash("Could not sign in with Google. Please try again.")
        return redirect(url_for("login"))

    email = (info.get("email") or "").strip().lower()
    if not email or not info.get("email_verified"):
        flash("Your Google account's email is not verified, so it cannot be used here.")
        return redirect(url_for("login"))

    user = User.query.filter_by(email=email).first()
    if user is None:                                     # first time: create the account
        name = (info.get("name") or email.split("@")[0]).strip()[:100]
        user = User(username=name, email=email, role="user", verified=True)
        user.set_password(secrets.token_urlsafe(32))     # random password nobody knows ("Forgot password" can set one)
        db.session.add(user)
        welcome = f"Welcome to MalSense, {name.split()[0]}!"
    else:
        if not user.is_active:
            flash("This account has been deactivated. Please contact the administrator.")
            return redirect(url_for("login"))
        user.verified = True                             # Google has confirmed this person owns the email
        welcome = f"Welcome back, {user.username.split()[0]}!"
    login_user(user)
    user.last_login = datetime.now()
    db.session.commit()
    flash(welcome, "success")
    if nxt:
        return redirect(nxt)
    return redirect(url_for("admin_users" if user.is_admin else "home"))


@app.route("/terms")
def terms():                                            # Terms of Use
    return render_template("terms.html")


@app.route("/privacy")
def privacy():                                          # Privacy Policy (PDPA 2010)
    return render_template("privacy.html")


@app.route("/feedback", methods=["GET", "POST"])
def feedback():                                         # enquiries / complaints -> emailed to the owner
    form = {"name": "", "email": "", "topic": request.args.get("topic", "question"), "message": ""}
    if current_user.is_authenticated:
        form.update(name=current_user.username, email=current_user.email)
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in ("name", "email", "topic", "message")}
        form["email"] = form["email"].lower()
        if request.form.get("website"):                  # hidden "trap" box - only bots fill it in
            flash("Thank you - your message has been sent.", "success")
            return redirect(url_for("feedback", sent=1))
        now = time.time()                                # max 3 messages per 10 minutes from one browser
        recent = [t for t in session.get("fb_times", []) if now - t < 600]
        errors = []
        if len(recent) >= 3:
            errors.append("You have sent several messages already - please wait a few minutes and try again.")
        if not EMAIL_RE.match(form["email"]) or any(c in form["email"] for c in "\r\n<>,;"):
            errors.append("Please enter a valid email address, so we can reply to you.")
        if form["topic"] not in fb.TOPIC_LABEL:
            form["topic"] = "question"
        if len(form["message"]) < 10:
            errors.append("Please write a little more in your message (at least 10 characters).")
        elif len(form["message"]) > fb.MAX_MESSAGE:
            errors.append(f"Your message is too long (maximum {fb.MAX_MESSAGE} characters).")
        form["name"] = form["name"][:100]
        if not errors:
            if fb.send(form["name"], form["email"], form["topic"], form["message"],
                       account=current_user if current_user.is_authenticated else None, logger=app.logger):
                session["fb_times"] = recent + [now]
                flash("Thank you - your message has been sent. We will reply to your email.", "success")
                return redirect(url_for("feedback", sent=1))
            errors.append("Sorry, your message could not be sent right now. Please try again later.")
        for e in errors:
            flash(e)
    return render_template("feedback.html", form=form, topics=fb.TOPICS, sent=request.args.get("sent"),
                           max_len=fb.MAX_MESSAGE)


@app.route("/checklist")
def checklist():                                        # Mobile Security Checklist (home page band)
    import checklist as C
    return render_template("checklist.html", sections=C.SECTIONS, total=sum(len(x["items"]) for x in C.SECTIONS))


@app.route("/amanah")
def amanah():                                           # Digital Amanah: Islamic reminder + Maqasid + safety tips
    import amanah as A
    today = datetime.now()                               # Monday = 0 ... Sunday = 6 -> a new reminder every day
    return render_template("amanah.html", intro=A.INTRO, maqasid=A.MAQASID, advice=A.ADVICE,
                           reminder=A.REMINDERS[today.weekday() % len(A.REMINDERS)],
                           day_name=today.strftime("%A"))


# ------------------------------------------------------------------ email verification + password reset
COOLDOWN = {}                                            # email -> time of last email (stops email flooding)


def password_problem(pw):
    if len(pw) < 8 or not re.search(r"[A-Za-z]", pw) or not re.search(r"\d", pw):
        return "Password must be at least 8 characters and contain letters and numbers."
    return None


def can_send(email, seconds=60):
    now = time.time()
    if now - COOLDOWN.get(email, 0) < seconds:
        return False
    COOLDOWN[email] = now
    return True


def send_verification_email(user):
    link = url_for("verify_email", token=sec.make_verify_token(app.config["SECRET_KEY"], user), _external=True)
    COOLDOWN[user.email] = time.time()
    return sec.send_verification(user, link, app.logger)


@app.route("/verify/sent")
def verify_sent():
    """'Check your inbox' page shown after registering."""
    email = session.get("pending_email")
    if not email:
        return redirect(url_for("login"))
    return render_template("verify_sent.html", email=email)


@app.route("/verify/resend", methods=["POST"])
def verify_resend():
    email = request.form.get("email", "").strip().lower()
    user = User.query.filter_by(email=email).first() if EMAIL_RE.match(email) else None
    if user and not user.verified and user.is_active and can_send(email):
        send_verification_email(user)
    # same answer whether or not the account exists, so emails cannot be discovered this way
    flash("If that account still needs verifying, a new link has been sent. It can take a minute to arrive.", "success")
    session["pending_email"] = email
    return redirect(url_for("verify_sent"))


@app.route("/verify/<token>")
def verify_email(token):
    data, err = sec.read_verify_token(app.config["SECRET_KEY"], token)
    user = db.session.get(User, data["id"]) if data else None
    if not user or user.email != data.get("email"):
        flash("This verification link has expired - log in to get a new one." if err == "expired"
              else "This verification link is not valid.")
        return redirect(url_for("login"))
    if not user.verified:
        user.verified = True
        db.session.commit()
    session.pop("pending_email", None)
    flash("Email verified - you can now log in.", "success")
    return redirect(url_for("login"))


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = User.query.filter_by(email=email).first() if EMAIL_RE.match(email) else None
        if user and user.is_active and can_send("reset:" + email):
            link = url_for("reset_password", token=sec.make_reset_token(app.config["SECRET_KEY"], user), _external=True)
            sec.send_reset(user, link, app.logger)
        # same message for every email, so attackers cannot find out which emails are registered
        flash("If an account exists for that email, a password-reset link has been sent. "
              "The link expires in 30 minutes.", "success")
        return redirect(url_for("login"))
    return render_template("forgot.html")


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    data, err = sec.read_reset_token(app.config["SECRET_KEY"], token)
    user = db.session.get(User, data["id"]) if data else None
    # the token holds part of the OLD password hash -> once the password changes, the link stops working
    if not user or not user.is_active or user.password_hash[-12:] != data.get("pw"):
        flash("This reset link has expired or was already used - please ask for a new one." if err != "invalid"
              else "This reset link is not valid - please ask for a new one.")
        return redirect(url_for("forgot"))
    error = None
    if request.method == "POST":
        pw, pw2 = request.form.get("password", ""), request.form.get("confirm", "")
        error = password_problem(pw) or ("Passwords do not match." if pw != pw2 else None)
        if not error:
            user.set_password(pw)
            user.verified = True                         # the link proved the email belongs to them
            db.session.commit()
            flash("Password changed - you can now log in with your new password.", "success")
            return redirect(url_for("login"))
    return render_template("reset.html", token=token, error=error)


# ------------------------------------------------------------------ coming in later steps
@app.route("/history")
@login_required
def history():                                          # UC05 - registered users only
    page = request.args.get("page", 1, type=int)
    mine = Scan.query.filter_by(user_id=current_user.user_id)       # only THIS user's scans
    scans = mine.order_by(Scan.scanned_at.desc()).paginate(page=page, per_page=10, error_out=False)
    stats = {"total": mine.count(),
             "malware": mine.filter_by(ml_result="Malware").count(),
             "benign": mine.filter_by(ml_result="Benign").count()}
    return render_template("history.html", scans=scans, stats=stats)


@app.route("/report/<int:no>.<fmt>")
@login_required
def download_report(no, fmt):                           # UC06 - registered users only
    return send_report(find_my_scan(no), fmt)           # users can only reach their OWN scans


def send_report(scan, fmt):
    if fmt not in ("pdf", "docx"):
        abort(404)
    if not scan.details:
        flash("A detailed report is not available for this older scan - please scan the file again.")
        return redirect(url_for("history"))
    data = report_data(scan, current_user)
    name = f"MalSense_Report_{data['report_id']}.{fmt}"
    if fmt == "pdf":
        return send_file(io.BytesIO(build_pdf(data)), mimetype="application/pdf",
                         as_attachment=True, download_name=name)
    return send_file(io.BytesIO(build_docx(data)), as_attachment=True, download_name=name,
                     mimetype="application/vnd.openxmlformats-officedocument.wordprocessingml.document")


# ------------------------------------------------------------------ Learn: awareness quiz (Figures 5.7 - 5.10)
# Home section 2. Separate from scanning (supervisor), so the result page stays uncluttered.
# The APK is analysed by the model only (no VirusTotal) and the AI GENERATES a new quiz from what was
# found - every upload gets new questions, even for the same file (questions already asked are avoided).
# The generated quiz is saved under a random id, so a page refresh or "Retry quiz" keeps the same questions.
def remember_learn(quiz_id, filename):
    """Store which quizzes this browser may open: {token: [quiz_id, filename]} (last 10 only)."""
    learned = session.get("learn")
    learned = learned if isinstance(learned, dict) else {}
    token = uuid.uuid4().hex[:12]
    learned[token] = [quiz_id, filename[:120]]
    session["learn"] = dict(list(learned.items())[-10:])
    return token


@app.route("/learn", methods=["POST"])
def learn():
    if not current_user.is_authenticated:
        return must_log_in("take an awareness quiz", "learn")
    msg = limit_reached("quizzes")
    if msg:
        flash(msg)
        return redirect(url_for("home", _anchor="learn"))
    path, filename = receive_apk()
    if not path:
        return redirect(url_for("home", _anchor="learn"))
    try:
        r = malsense_scanner.scan_apk(path)
        mtype = safe_malware_type(path, app.logger.warning) if r.get("verdict") == "MALWARE" else None
    except Exception as e:
        app.logger.warning(f"Could not analyse {filename} for a quiz: {e}")
        flash("MalSense could not read this APK, so no quiz could be made. Please report it so the admin can "
              "update MalSense" + ("." if current_user.is_authenticated else " (log in first)."))
        return redirect_to_report("scan_failed")
    finally:
        if os.path.exists(path):
            os.remove(path)
    details = {k: r.get(k) for k in ("app_name", "verdict", "malware_probability", "dangerous_permissions")}
    details["explanation"] = [{"label": e["label"], "feature": e["feature"]} for e in r.get("explanation", [])]
    details["malware_type"] = mtype                       # lets the quiz use the intents and API calls found in THIS app
    return make_quiz(details, r["sha256"], filename)


def make_quiz(details, sha256, filename):
    quiz_id, q = new_quiz(details, sha256)
    if current_user.is_authenticated:                    # counts toward the daily quiz limit
        try:
            db.session.add(QuizLog(user_id=current_user.user_id))
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            app.logger.warning(f"Could not log quiz: {e}")
    if q.get("note"):
        app.logger.warning(f"Quiz fell back to the question bank: {q['note']}")
    return redirect(url_for("learn_quiz", t=remember_learn(quiz_id, filename)))


def my_quiz(t):
    """The quiz behind token t - only if THIS browser created it."""
    item = (session.get("learn") or {}).get(t)
    if not (isinstance(item, list) and len(item) == 2):
        return None, None
    return load_quiz(item[0]), item[1]


@app.route("/learn/<t>")
def learn_quiz(t):
    q, filename = my_quiz(t)
    if not q:
        flash("That quiz could not be found - please upload the APK again.")
        return redirect(url_for("home", _anchor="learn"))
    return render_template("quiz.html", quiz=q, filename=filename, t=t, back=url_for("home", _anchor="learn"))


# ------------------------------------------------------------------ Report an APK to the admin
def redirect_to_report(reason):
    """Open the report page - guests go to Login first and come back to it afterwards."""
    target = url_for("report_apk", reason=reason)
    return redirect(target if current_user.is_authenticated else url_for("login", next=target))


# New malware appears all the time. When MalSense cannot analyse an APK (or the user thinks the result is
# wrong), the user sends it to the admin. The APK is KEPT in reported_apks/ so the admin can study it and
# add it to the training data (see admin_reports).
@app.route("/report", methods=["GET", "POST"])
@login_required                                          # only registered users can report (guests are sent to Login)
def report_apk():
    reason = request.values.get("reason", "scan_failed")
    reason = reason if reason in Report.REASONS else "other"
    form = {"reason": reason, "message": ""}
    if request.method == "POST":
        form = {"reason": reason, "message": request.form.get("message", "").strip()[:2000]}
        path, filename = receive_apk(REPORT_DIR, ".apk.quarantine")   # ".quarantine": cannot be opened by accident
        if not path:
            return render_template("report.html", form=form, reasons=Report.REASONS)
        sha = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                sha.update(chunk)
        rep = Report(user_id=current_user.user_id,
                     filename=filename[:255], stored_name=os.path.basename(path), file_hash=sha.hexdigest(),
                     file_size=os.path.getsize(path), reason=reason, message=form["message"] or None,
                     contact_email=current_user.email)
        try:
            db.session.add(rep)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            os.remove(path)
            app.logger.error(f"Could not save report: {e}")
            flash("Sorry, the report could not be sent right now. Please try again later.")
            return render_template("report.html", form=form, reasons=Report.REASONS)
        flash("Thank you! Your report was sent to the MalSense admin.", "success")
        return redirect(url_for("home"))
    return render_template("report.html", form=form, reasons=Report.REASONS)



# ------------------------------------------------------------------ admin (Figures 5.11 - 5.13)
@app.route("/admin")
@admin_required
def admin_home():
    return redirect(url_for("admin_users"))


@app.route("/admin/users")
@admin_required
def admin_users():                                      # Figure 5.11 - UC07 manage users
    q = request.args.get("q", "").strip()
    users = User.query
    if q:
        like = f"%{q}%"
        users = users.filter(db.or_(User.username.ilike(like), User.email.ilike(like)))
    counts = dict(db.session.query(Scan.user_id, db.func.count(Scan.scan_id)).group_by(Scan.user_id).all())
    return render_template("admin_users.html", users=users.order_by(User.created_at).all(), counts=counts, q=q,
                           total_users=User.query.count(), total_scans=Scan.query.count())


@app.route("/admin/users/<int:user_id>", methods=["GET", "POST"])
@admin_required
def admin_user_edit(user_id):
    user = db.session.get(User, user_id) or abort(404)
    is_self = user.user_id == current_user.user_id
    if request.method == "POST":
        action = request.form.get("action")
        if is_self and action in ("deactivate", "delete", "make_user"):
            flash("You cannot deactivate, delete or demote your own admin account.")
        elif action == "deactivate":
            user.active = False; db.session.commit(); flash(f"{user.username} has been deactivated.", "success")
        elif action == "activate":
            user.active = True; db.session.commit(); flash(f"{user.username} has been activated.", "success")
        elif action == "verify":
            user.verified = True; db.session.commit(); flash(f"{user.username}'s email is now marked as verified.", "success")
        elif action == "make_admin":
            user.role = "admin"; db.session.commit(); flash(f"{user.username} is now an admin.", "success")
        elif action == "make_user":
            user.role = "user"; db.session.commit(); flash(f"{user.username} is now a normal user.", "success")
        elif action == "delete":
            name = user.username
            Scan.query.filter_by(user_id=user.user_id).update({"user_id": None})   # keep scan logs
            db.session.delete(user); db.session.commit()
            flash(f"Account of {name} deleted. Their scan logs were kept as guest scans.", "success")
            return redirect(url_for("admin_users"))
        return redirect(url_for("admin_user_edit", user_id=user_id))
    n_scans = Scan.query.filter_by(user_id=user.user_id).count()
    return render_template("admin_user_edit.html", user=user, n_scans=n_scans, is_self=is_self)


@app.route("/admin/scans")
@admin_required
def admin_scans():                                      # Figure 5.12 - UC08 view all scan logs
    q = request.args.get("q", "").strip()
    result_f = request.args.get("result", "")
    date_f = request.args.get("date", "")
    page = request.args.get("page", 1, type=int)
    scans = Scan.query.outerjoin(User, Scan.user_id == User.user_id)
    if q:
        like = f"%{q}%"
        scans = scans.filter(db.or_(Scan.filename.ilike(like), User.username.ilike(like),
                                    User.email.ilike(like), Scan.file_hash.ilike(like)))
    if result_f in ("Malware", "Benign"):
        scans = scans.filter(Scan.ml_result == result_f)
    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    since = {"today": today, "7d": today - timedelta(days=6), "30d": today - timedelta(days=29)}.get(date_f)
    if since:
        scans = scans.filter(Scan.scanned_at >= since)
    page_obj = scans.order_by(Scan.scanned_at.desc()).paginate(page=page, per_page=15, error_out=False)
    stats = {"total": Scan.query.count(), "today": Scan.query.filter(Scan.scanned_at >= today).count(),
             "malware": Scan.query.filter_by(ml_result="Malware").count(),
             "benign": Scan.query.filter_by(ml_result="Benign").count()}
    users = {u.user_id: u for u in User.query.all()}
    return render_template("admin_scans.html", scans=page_obj, stats=stats, users=users,
                           q=q, result_f=result_f, date_f=date_f)


@app.route("/admin/scans/<int:scan_id>")
@admin_required
def admin_scan_view(scan_id):                           # admin opens ANY scan (uses the hidden scan_id)
    scan = db.session.get(Scan, scan_id) or abort(404)
    links = {"pdf": url_for("admin_scan_report", scan_id=scan_id, fmt="pdf"),
             "docx": url_for("admin_scan_report", scan_id=scan_id, fmt="docx")}
    return render_result(scan, None, links)


@app.route("/admin/scans/<int:scan_id>/report.<fmt>")
@admin_required
def admin_scan_report(scan_id, fmt):
    return send_report(db.session.get(Scan, scan_id) or abort(404), fmt)


@app.route("/admin/model")
@admin_required
def admin_model():                                      # Figure 5.13 - UC09 manage ML model
    return render_template("admin_model.html", info=get_model_info(malsense_scanner.BUNDLE))


@app.route("/admin/model/retrain", methods=["POST"])
@admin_required
def admin_retrain():
    if ONLINE:                                           # no training data online + not enough memory
        flash("Retraining is done on the local copy of MalSense, then the new model is uploaded.")
        return redirect(url_for("admin_model"))
    ok, msg = retrain()
    if ok:
        malsense_scanner.reload_bundle()                 # new scans use the new model straight away
        flash(msg, "success")
    else:
        flash(f"Retraining failed: {msg}")
    return redirect(url_for("admin_model"))


def trained_at():
    """When the current model was trained (samples added after this time are still 'waiting')."""
    try:
        return get_model_info(malsense_scanner.BUNDLE)["metrics"]["trained_at"]
    except Exception:
        return None


@app.route("/admin/reports")
@admin_required
def admin_reports():                                    # reported APKs (new feature)
    status_f = request.args.get("status", "new")
    reps = Report.query
    if status_f in Report.STATUSES:
        reps = reps.filter_by(status=status_f)
    counts = dict(db.session.query(Report.status, db.func.count(Report.report_id)).group_by(Report.status).all())
    users = {u.user_id: u for u in User.query.all()}
    return render_template("admin_reports.html", reports=reps.order_by(Report.created_at.desc()).all(),
                           counts=counts, status_f=status_f, users=users, samples=new_samples.summary(trained_at()))


@app.route("/admin/reports/<int:report_id>/download")
@admin_required
def admin_report_download(report_id):
    rep = db.session.get(Report, report_id) or abort(404)
    path = os.path.join(REPORT_DIR, rep.stored_name)
    if not os.path.exists(path):
        flash("The APK file of this report is no longer on the server.")
        return redirect(url_for("admin_reports"))
    # ".quarantine" stays on the name so it is not opened or installed by accident
    return send_file(path, as_attachment=True, download_name=f"{rep.file_hash[:16]}.apk.quarantine",
                     mimetype="application/octet-stream")


@app.route("/admin/reports/<int:report_id>", methods=["POST"])
@admin_required
def admin_report_action(report_id):
    rep = db.session.get(Report, report_id) or abort(404)
    action = request.form.get("action")
    path = os.path.join(REPORT_DIR, rep.stored_name)
    back = redirect(url_for("admin_reports", status=request.form.get("status_f", "new")))
    if action in ("analyse", "add_malware", "add_benign") and not os.path.exists(path):
        flash("The APK file of this report is no longer on the server.")
        return back
    if action == "analyse":                              # help the admin decide: model + VirusTotal
        try:
            r = full_scan(path)
            vt = r["virustotal"]
            vt_txt = vt["detection_ratio"] if vt.get("status") == "found" else vt.get("status", "").replace("_", " ")
            flash(f"#{rep.report_id} {rep.filename}: model says {r['verdict']} "
                  f"({r['malware_probability']:.0%} malware), VirusTotal: {vt_txt}, risk {r['risk']}.", "success")
        except Exception as e:
            flash(f"#{rep.report_id}: the scanner cannot read this APK ({str(e)[:150]}).")
        return back
    if action in ("add_malware", "add_benign") and ONLINE:
        # the online server forgets files when it restarts, so training data is only changed locally
        flash("Adding samples to the training data is done on the local copy of MalSense "
              "(download the APK here, then add it on your laptop).")
        return back
    if action in ("add_malware", "add_benign"):
        label = 1 if action == "add_malware" else 0
        try:
            new_samples.add_sample(path, label, rep.file_hash, source=f"report #{rep.report_id}")
        except Exception as e:
            flash(f"#{rep.report_id} could not be added: the scanner cannot extract features from this APK "
                  f"({str(e)[:150]}). It cannot be used for training.")
            return back
        rep.status, rep.reviewed_at = action.replace("add_", "added_"), datetime.now()
        db.session.commit()
        flash(f"#{rep.report_id} added to the training data as {'malware' if label else 'benign'}. "
              "Retrain the model on the ML model page to use it.", "success")
    elif action == "dismiss":
        rep.status, rep.reviewed_at = "dismissed", datetime.now()
        db.session.commit()
        flash(f"#{rep.report_id} dismissed.", "success")
    elif action == "reopen":                             # undo: also take it out of the training data again
        new_samples.remove_sample(rep.file_hash)
        rep.status, rep.reviewed_at = "new", None
        db.session.commit()
        flash(f"#{rep.report_id} moved back to New (and removed from the training data).", "success")
    return back


# ------------------------------------------------------------------ admin: threat intelligence
def _intel_rows():
    return ti.ioc_rows(Scan.query.order_by(Scan.scanned_at).all(), Report.query.all(), VT_CONFIRM)


@app.route("/admin/intel")
@admin_required
def admin_intel():
    """Threat-intelligence overview: weekly detections, families, ATT&CK techniques, IOC export."""
    iocs = _intel_rows()
    # weekly scans for the last 8 weeks (Monday to Sunday)
    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    start = today - timedelta(days=today.weekday() + 7 * 7)
    malicious = {r["sha256"] for r in iocs}
    weeks = [{"start": start + timedelta(weeks=i), "total": 0, "malware": 0} for i in range(8)]
    for sc in Scan.query.filter(Scan.scanned_at >= start).all():
        w = weeks[min((sc.scanned_at - start).days // 7, 7)]
        w["total"] += 1
        w["malware"] += sc.file_hash in malicious
    families = Counter(r["family"] for r in iocs if r["family"]).most_common(8)
    techniques = Counter(t for r in iocs for t in r["attack"].split()).most_common(8)
    perms = Counter()
    for sc in Scan.query.filter(Scan.file_hash.in_(malicious)).all() if malicious else []:
        perms.update(set((sc.details or {}).get("dangerous_permissions") or []))
    return render_template("admin_intel.html", iocs=iocs, weeks=weeks, families=families,
                           techniques=[(t, ti.TECHNIQUES[t][0], ti.technique_url(t), n) for t, n in techniques],
                           perms=perms.most_common(8), recent=iocs[:10])


@app.route("/admin/intel/iocs.<fmt>")
@admin_required
def admin_intel_export(fmt):
    rows = _intel_rows()
    stamp = datetime.now().strftime("%Y%m%d")
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=ti.IOC_COLUMNS)
        w.writeheader()
        for r in rows:
            w.writerow(dict(r, first_seen=r["first_seen"].strftime("%Y-%m-%d %H:%M:%S"),
                            last_seen=r["last_seen"].strftime("%Y-%m-%d %H:%M:%S")))
        return send_file(io.BytesIO(buf.getvalue().encode("utf-8-sig")), mimetype="text/csv",
                         as_attachment=True, download_name=f"MalSense_IOCs_{stamp}.csv")
    if fmt == "json":                                    # STIX 2.1 bundle
        data = json.dumps(ti.stix_bundle(rows), indent=2).encode("utf-8")
        return send_file(io.BytesIO(data), mimetype="application/json", as_attachment=True,
                         download_name=f"MalSense_IOCs_{stamp}.stix.json")
    abort(404)


@app.template_filter("shortname")
def shortname(name, keep=36):
    """Long file names (e.g. a 64-character hash.apk) are shortened in headings: start ... end.
    The full name is still shown on hover and in the File name row."""
    name = name or ""
    if len(name) <= keep:
        return name
    return name[:keep - 16] + "\u2026" + name[-13:]


@app.context_processor
def daily_usage():
    """How many scans / quizzes the user has left today - shown under the two upload boxes on Home."""
    if request.endpoint == "home" and current_user.is_authenticated and not current_user.is_admin:
        try:
            used = usage_today(current_user)
            return {"left": {"scans": max(SCAN_LIMIT - used["scans"], 0) if SCAN_LIMIT else None,
                             "quizzes": max(QUIZ_LIMIT - used["quizzes"], 0) if QUIZ_LIMIT else None},
                    "limits": {"scans": SCAN_LIMIT, "quizzes": QUIZ_LIMIT}}
        except Exception:
            db.session.rollback()
    return {"left": None, "limits": None}


@app.context_processor
def admin_counts():
    """Number of new reports, shown next to "Reports" in the admin sidebar."""
    if current_user.is_authenticated and current_user.is_admin:
        try:
            return {"new_reports": Report.query.filter_by(status="new").count()}
        except Exception:
            db.session.rollback()
    return {"new_reports": 0}


@app.errorhandler(403)
def forbidden(e):
    flash("You do not have permission to open that page.")
    return redirect(url_for("home"))


@app.errorhandler(404)
def not_found(e):
    flash("That page or scan could not be found.")
    return redirect(url_for("home"))


@app.errorhandler(413)
def too_large(e):
    flash("File is too large (maximum 100 MB).")
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True)                                  # local testing only
