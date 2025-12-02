import os
import base64
from datetime import datetime
from uuid import uuid4
from io import BytesIO

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, session, send_file
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from cryptography.fernet import Fernet
import pyotp

app = Flask(__name__)

# Secret key is needed for sessions and flash messages
app.config["SECRET_KEY"] = "change_this_secret_key_later"

# SQLite database file named database.db in the project folder
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Folder where we store encrypted uploaded files
UPLOAD_FOLDER = os.path.join(app.root_path, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Limit upload size to 16 MB (Flask will reject larger ones)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB

# Threat detection settings
BLOCKED_EXTENSIONS = {
    "exe", "bat", "cmd", "sh", "js", "vbs", "msi", "dll"
}
SECURITY_LOG_PATH = os.path.join(app.root_path, "security.log")

# ----------- Encryption Setup -----------

# For demo: we derive a fixed 32-byte key (all zeros) and encode it as a Fernet key.
# In a real system, you would generate a random secret and keep it safe.
BASE_KEY = b"\x00" * 32  # 32 zero bytes (NOT secure, just for learning/demo)
FERNET_KEY = base64.urlsafe_b64encode(BASE_KEY)
fernet = Fernet(FERNET_KEY)


db = SQLAlchemy(app)

# ----------- Database Models -----------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    otp_secret = db.Column(db.String(32), nullable=True)         # for 2FA
    is_2fa_enabled = db.Column(db.Boolean, default=False)        # 2FA status
    files = db.relationship("File", backref="owner", lazy=True)  # one-to-many: one user -> many files


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_name = db.Column(db.String(255), nullable=False)
    stored_name = db.Column(db.String(255), nullable=False)
    size = db.Column(db.Integer, nullable=False)  # original size in bytes
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


# ----------- Helper functions -----------

def current_user_id():
    return session.get("user_id")


def log_security_event(message: str):
    """
    Append a security event to security.log with timestamp and username (if any).
    """
    username = session.get("username", "anonymous")
    timestamp = datetime.utcnow().isoformat()
    line = f"{timestamp} | {username} | {message}\n"
    try:
        with open(SECURITY_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        # If logging fails, we don't want to crash the app
        pass


def get_extension(filename: str) -> str:
    if "." not in filename:
        return ""
    return filename.rsplit(".", 1)[1].lower()


# ----------- Error handler for large files -----------

@app.errorhandler(RequestEntityTooLarge)
def handle_large_file(e):
    flash("File too large. Maximum allowed size is 16 MB.")
    log_security_event("Blocked upload: file too large.")
    return redirect(url_for("dashboard"))


# ----------- Routes -----------

@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        # Basic validation
        if not username or not password:
            flash("Username and password are required.")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.")
            return redirect(url_for("register"))

        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username already taken. Please choose another.")
            return redirect(url_for("register"))

        # Create new user with hashed password
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password_hash=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful. Please log in.")
        return redirect(url_for("login"))

    # GET request: show the registration page
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            # If 2FA is enabled, ask for OTP first
            if user.is_2fa_enabled and user.otp_secret:
                session["pre_2fa_user_id"] = user.id
                session["pre_2fa_username"] = user.username
                return redirect(url_for("two_factor"))
            else:
                # Normal login without 2FA
                session["user_id"] = user.id
                session["username"] = user.username
                flash("Logged in successfully.")
                return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password.")
            log_security_event(f"Failed login attempt for username: {username}")
            return redirect(url_for("login"))

    # GET request: show the login page
    return render_template("login.html")


@app.route("/two_factor", methods=["GET", "POST"])
def two_factor():
    pre_user_id = session.get("pre_2fa_user_id")
    if not pre_user_id:
        flash("2FA session expired. Please log in again.")
        return redirect(url_for("login"))

    user = User.query.get(pre_user_id)
    if not user or not user.is_2fa_enabled or not user.otp_secret:
        # Something is wrong; clear and force new login
        session.pop("pre_2fa_user_id", None)
        session.pop("pre_2fa_username", None)
        flash("2FA not properly configured. Please log in again.")
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code")
        totp = pyotp.TOTP(user.otp_secret)

        if totp.verify(code):
            # Complete the login
            session["user_id"] = user.id
            session["username"] = user.username
            session.pop("pre_2fa_user_id", None)
            session.pop("pre_2fa_username", None)
            flash("Logged in with 2FA.")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid authentication code.")
            log_security_event(f"Failed 2FA login for user {user.username}")
            return redirect(url_for("two_factor"))

    # GET
    return render_template("two_factor.html")


@app.route("/enable_2fa", methods=["GET", "POST"])
def enable_2fa():
    if not current_user_id():
        flash("Please log in to configure 2FA.")
        return redirect(url_for("login"))

    user = User.query.get(current_user_id())
    if not user:
        session.clear()
        flash("User not found. Please log in again.")
        return redirect(url_for("login"))

    # GET: show page with secret and form to verify code
    if request.method == "GET":
        secret = user.otp_secret
        if not secret:
            # Generate a new secret for this user
            secret = pyotp.random_base32()
            user.otp_secret = secret
            db.session.commit()

        return render_template(
            "enable_2fa.html",
            secret=secret,
            is_enabled=user.is_2fa_enabled
        )

    # POST: user submitted a code to confirm 2FA setup
    code = request.form.get("code")

    if not user.otp_secret:
        flash("Missing 2FA secret. Please reload the page.")
        return redirect(url_for("enable_2fa"))

    totp = pyotp.TOTP(user.otp_secret)
    if totp.verify(code):
        user.is_2fa_enabled = True
        db.session.commit()
        flash("Two-factor authentication enabled successfully.")
        log_security_event("2FA enabled for this account.")
        return redirect(url_for("dashboard"))
    else:
        flash("Invalid authentication code. Please try again.")
        log_security_event("Failed 2FA setup code entry.")
        return redirect(url_for("enable_2fa"))


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for("home"))


@app.route("/dashboard")
def dashboard():
    # Simple check: if not logged in, redirect to login
    if not current_user_id():
        flash("Please log in to access the dashboard.")
        return redirect(url_for("login"))

    user_files = File.query.filter_by(owner_id=current_user_id()) \
                           .order_by(File.uploaded_at.desc()).all()

    return render_template("dashboard.html", files=user_files)


@app.route("/upload", methods=["POST"])
def upload():
    if not current_user_id():
        flash("Please log in to upload files.")
        return redirect(url_for("login"))

    if "file" not in request.files:
        flash("No file part in the request.")
        return redirect(url_for("dashboard"))

    file = request.files["file"]

    if file.filename == "":
        flash("No file selected.")
        return redirect(url_for("dashboard"))

    if file:
        # Make filename safe
        original_name = secure_filename(file.filename)
        ext = get_extension(original_name)

        # -------- Threat detection: block dangerous extensions --------
        if ext in BLOCKED_EXTENSIONS:
            flash(f"Upload blocked: files with .{ext} extension are not allowed.")
            log_security_event(f"Blocked upload of disallowed extension: .{ext} "
                               f"(filename: {original_name})")
            return redirect(url_for("dashboard"))

        # Read file bytes
        file_bytes = file.read()
        if not file_bytes:
            flash("Empty file.")
            return redirect(url_for("dashboard"))

        # -------- Threat detection: simple content scan (demo) --------
        if b"virus" in file_bytes.lower():
            flash("Upload blocked: file content looks suspicious (contains 'virus').")
            log_security_event(f"Blocked upload: suspicious content in {original_name}")
            return redirect(url_for("dashboard"))

        # Encrypt file bytes
        encrypted_bytes = fernet.encrypt(file_bytes)

        # Generate a unique stored name to avoid collisions
        stored_name = f"{uuid4().hex}_{original_name}"
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], stored_name)

        # Save encrypted data to disk
        with open(file_path, "wb") as f:
            f.write(encrypted_bytes)

        # Store original size, not encrypted size
        size = len(file_bytes)

        # Save metadata to database
        new_file = File(
            original_name=original_name,
            stored_name=stored_name,
            size=size,
            owner_id=current_user_id()
        )
        db.session.add(new_file)
        db.session.commit()

        flash("File uploaded, scanned, and encrypted successfully.")
        return redirect(url_for("dashboard"))

    flash("Something went wrong with file upload.")
    return redirect(url_for("dashboard"))


@app.route("/files/<int:file_id>/download")
def download_file(file_id):
    if not current_user_id():
        flash("Please log in to download files.")
        return redirect(url_for("login"))

    file_record = File.query.get_or_404(file_id)

    # Ensure the file belongs to the current user
    if file_record.owner_id != current_user_id():
        flash("You are not allowed to access this file.")
        log_security_event(
            f"Unauthorized download attempt for file ID {file_id} "
            f"(owner_id={file_record.owner_id})"
        )
        return redirect(url_for("dashboard"))

    file_path = os.path.join(app.config["UPLOAD_FOLDER"], file_record.stored_name)

    # Read encrypted bytes from disk
    try:
        with open(file_path, "rb") as f:
            encrypted_bytes = f.read()
    except FileNotFoundError:
        flash("File not found on server.")
        log_security_event(
            f"Missing file on disk for file ID {file_id} "
            f"(stored_name={file_record.stored_name})"
        )
        return redirect(url_for("dashboard"))

    # Decrypt
    try:
        decrypted_bytes = fernet.decrypt(encrypted_bytes)
    except Exception:
        flash("Error decrypting file.")
        log_security_event(
            f"Decryption failed for file ID {file_id} "
            f"(stored_name={file_record.stored_name})"
        )
        return redirect(url_for("dashboard"))

    # Send decrypted content as a downloadable file
    return send_file(
        BytesIO(decrypted_bytes),
        as_attachment=True,
        download_name=file_record.original_name,
        mimetype="application/octet-stream"
    )


if __name__ == "__main__":
    # Create database tables (User, File) if they don't exist
    with app.app_context():
        db.create_all()

    app.run(debug=True)