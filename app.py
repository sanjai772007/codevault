from flask import (
    Flask,
    render_template,
    request,
    redirect,
    send_from_directory,
    session,
    flash,
    url_for
)

from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import os
import mimetypes


# ==============================
# CREATE FLASK APPLICATION
# ==============================
app = Flask(__name__)


# ==============================
# CONFIGURATION
# ==============================
app.config["SECRET_KEY"] = "codevault-secret-key-2026"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["UPLOAD_FOLDER"] = "uploads"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024


# Allowed file types
ALLOWED_EXTENSIONS = {
    "py",
    "cpp",
    "c",
    "h",
    "java",
    "html",
    "css",
    "js",
    "txt",
    "pdf",
    "csv",
    "json",
    "zip",
    "jpg",
    "jpeg",
    "png",
    "gif",
    "webp"
}


# Create main uploads folder
os.makedirs(
    app.config["UPLOAD_FOLDER"],
    exist_ok=True
)


# ==============================
# DATABASE
# ==============================
db = SQLAlchemy(app)


# ==============================
# USER TABLE
# ==============================
class User(db.Model):

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    username = db.Column(
        db.String(100),
        unique=True,
        nullable=False
    )

    password = db.Column(
        db.String(255),
        nullable=False
    )


# ==============================
# HELPER FUNCTIONS
# ==============================
def allowed_file(filename):

    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


def login_required():

    return "username" in session


def get_user_folder():

    username = session.get("username", "")

    safe_username = secure_filename(username)

    user_folder = os.path.join(
        app.config["UPLOAD_FOLDER"],
        safe_username
    )

    os.makedirs(
        user_folder,
        exist_ok=True
    )

    return user_folder


def get_safe_file_path(filename):

    safe_filename = secure_filename(filename)

    user_folder = get_user_folder()

    file_path = os.path.join(
        user_folder,
        safe_filename
    )

    return safe_filename, user_folder, file_path


# ==============================
# LOGIN
# ==============================
@app.route("/", methods=["GET", "POST"])
def login():

    if login_required():
        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if not username or not password:

            flash(
                "Please enter username and password.",
                "danger"
            )

            return redirect(
                url_for("login")
            )

        user = User.query.filter_by(
            username=username
        ).first()

        if user and check_password_hash(
            user.password,
            password
        ):

            session["username"] = user.username

            flash(
                "Login successful.",
                "success"
            )

            return redirect(
                url_for("dashboard")
            )

        flash(
            "Invalid username or password.",
            "danger"
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "login.html"
    )


# ==============================
# REGISTER
# ==============================
@app.route("/register", methods=["GET", "POST"])
def register():

    if login_required():
        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if not username or not password:

            flash(
                "Username and password are required.",
                "danger"
            )

            return redirect(
                url_for("register")
            )

        if len(username) < 3:

            flash(
                "Username must contain at least 3 characters.",
                "danger"
            )

            return redirect(
                url_for("register")
            )

        if len(password) < 6:

            flash(
                "Password must contain at least 6 characters.",
                "danger"
            )

            return redirect(
                url_for("register")
            )

        existing_user = User.query.filter_by(
            username=username
        ).first()

        if existing_user:

            flash(
                "Username already exists.",
                "danger"
            )

            return redirect(
                url_for("register")
            )

        hashed_password = generate_password_hash(
            password
        )

        new_user = User(
            username=username,
            password=hashed_password
        )

        db.session.add(new_user)
        db.session.commit()

        user_folder = os.path.join(
            app.config["UPLOAD_FOLDER"],
            secure_filename(username)
        )

        os.makedirs(
            user_folder,
            exist_ok=True
        )

        flash(
            "Account created successfully. Please log in.",
            "success"
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html"
    )


# ==============================
# DASHBOARD
# ==============================
@app.route("/dashboard")
def dashboard():

    if not login_required():
        return redirect(
            url_for("login")
        )

    user_folder = get_user_folder()

    search_text = request.args.get(
        "search",
        ""
    ).strip().lower()

    files = []

    for filename in os.listdir(user_folder):

        file_path = os.path.join(
            user_folder,
            filename
        )

        if not os.path.isfile(file_path):
            continue

        if (
            search_text
            and search_text not in filename.lower()
        ):
            continue

        file_size = os.path.getsize(
            file_path
        )

        file_extension = ""

        if "." in filename:
            file_extension = (
                filename.rsplit(".", 1)[1].lower()
            )

        files.append({
            "name": filename,
            "size": file_size,
            "extension": file_extension
        })

    files.sort(
        key=lambda file: file["name"].lower()
    )

    return render_template(
        "dashboard.html",
        files=files,
        username=session["username"],
        search_text=search_text
    )


# ==============================
# UPLOAD
# ==============================
@app.route("/upload", methods=["GET", "POST"])
def upload():

    if not login_required():
        return redirect(
            url_for("login")
        )

    if request.method == "POST":

        uploaded_file = request.files.get(
            "file"
        )

        if uploaded_file is None:

            flash(
                "Please select a file.",
                "danger"
            )

            return redirect(
                url_for("upload")
            )

        if uploaded_file.filename == "":

            flash(
                "Please select a file.",
                "danger"
            )

            return redirect(
                url_for("upload")
            )

        if not allowed_file(
            uploaded_file.filename
        ):

            flash(
                "This file type is not allowed.",
                "danger"
            )

            return redirect(
                url_for("upload")
            )

        filename = secure_filename(
            uploaded_file.filename
        )

        if not filename:

            flash(
                "Invalid filename.",
                "danger"
            )

            return redirect(
                url_for("upload")
            )

        user_folder = get_user_folder()

        file_path = os.path.join(
            user_folder,
            filename
        )

        if os.path.exists(file_path):

            flash(
                "A file with this name already exists.",
                "danger"
            )

            return redirect(
                url_for("upload")
            )

        uploaded_file.save(
            file_path
        )

        flash(
            "File uploaded successfully.",
            "success"
        )

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "upload.html"
    )


# ==============================
# VIEW FILE IN BROWSER
# ==============================
@app.route("/view/<path:filename>")
def view_file(filename):

    if not login_required():
        return redirect(
            url_for("login")
        )

    safe_filename, user_folder, file_path = (
        get_safe_file_path(filename)
    )

    if not os.path.isfile(file_path):

        flash(
            "File not found.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    mime_type, encoding = mimetypes.guess_type(
        file_path
    )

    return send_from_directory(
        user_folder,
        safe_filename,
        mimetype=mime_type,
        as_attachment=False,
        download_name=safe_filename
    )


# ==============================
# DOWNLOAD FILE
# ==============================
@app.route("/download/<path:filename>")
def download_file(filename):

    if not login_required():
        return redirect(
            url_for("login")
        )

    safe_filename, user_folder, file_path = (
        get_safe_file_path(filename)
    )

    if not os.path.isfile(file_path):

        flash(
            "File not found.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    return send_from_directory(
        user_folder,
        safe_filename,
        as_attachment=True,
        download_name=safe_filename
    )


# ==============================
# DELETE FILE
# ==============================
@app.route(
    "/delete/<path:filename>",
    methods=["POST"]
)
def delete_file(filename):

    if not login_required():
        return redirect(
            url_for("login")
        )

    safe_filename, user_folder, file_path = (
        get_safe_file_path(filename)
    )

    if os.path.isfile(file_path):

        os.remove(file_path)

        flash(
            "File deleted successfully.",
            "success"
        )

    else:

        flash(
            "File not found.",
            "danger"
        )

    return redirect(
        url_for("dashboard")
    )


# ==============================
# LOGOUT
# ==============================
@app.route("/logout")
def logout():

    session.clear()

    flash(
        "You have been logged out.",
        "success"
    )

    return redirect(
        url_for("login")
    )


# ==============================
# FILE TOO LARGE ERROR
# ==============================
@app.errorhandler(413)
def file_too_large(error):

    flash(
        "File is too large. Maximum size is 16 MB.",
        "danger"
    )

    return redirect(
        url_for("upload")
    )


# ==============================
# PAGE NOT FOUND ERROR
# ==============================
@app.errorhandler(404)
def page_not_found(error):

    flash(
        "Page or file not found.",
        "danger"
    )

    if login_required():
        return redirect(
            url_for("dashboard")
        )

    return redirect(
        url_for("login")
    )


# ==============================
# START APPLICATION
# ==============================
if __name__ == "__main__":

    with app.app_context():
        db.create_all()

    app.run(
        debug=True
    )
