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


# =========================================================
# CREATE FLASK APPLICATION
# =========================================================
app = Flask(__name__)


# =========================================================
# PROJECT PATHS
# =========================================================
BASE_DIR = os.path.abspath(
    os.path.dirname(__file__)
)

UPLOAD_FOLDER = os.path.join(
    BASE_DIR,
    "uploads"
)

DATABASE_FOLDER = os.path.join(
    BASE_DIR,
    "instance"
)

DATABASE_PATH = os.path.join(
    DATABASE_FOLDER,
    "database.db"
)


# Create required folders
os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)

os.makedirs(
    DATABASE_FOLDER,
    exist_ok=True
)


# =========================================================
# APPLICATION CONFIGURATION
# =========================================================
app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "codevault-development-secret-key-2026"
)

app.config["SQLALCHEMY_DATABASE_URI"] = (
    f"sqlite:///{DATABASE_PATH}"
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Maximum upload size: 16 MB
app.config["MAX_CONTENT_LENGTH"] = (
    16 * 1024 * 1024
)


# =========================================================
# ALLOWED FILE EXTENSIONS
# =========================================================
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


# =========================================================
# DATABASE
# =========================================================
db = SQLAlchemy(app)

print("=" * 60)
print("DATABASE URI:", app.config["SQLALCHEMY_DATABASE_URI"])
print("DATABASE PATH:", DATABASE_PATH)
print("=" * 60)


# =========================================================
# USER MODEL
# =========================================================
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

    def __repr__(self):
        return f"<User {self.username}>"


# =========================================================
# CREATE DATABASE TABLES
# =========================================================
# This runs when Flask is started using:
# python app.py
#
# It also runs when Render starts:
# gunicorn app:app
with app.app_context():
    db.create_all()


# =========================================================
# HELPER FUNCTIONS
# =========================================================
def allowed_file(filename):
    """
    Check whether the uploaded file has an allowed extension.
    """

    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


def login_required():
    """
    Return True when a user is logged in.
    """

    return "username" in session


def get_user_folder():
    """
    Return the logged-in user's private upload folder.
    """

    username = session.get(
        "username",
        ""
    )

    safe_username = secure_filename(
        username
    )

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
    """
    Secure a filename and return its user-folder path.
    """

    safe_filename = secure_filename(
        filename
    )

    user_folder = get_user_folder()

    file_path = os.path.join(
        user_folder,
        safe_filename
    )

    return (
        safe_filename,
        user_folder,
        file_path
    )


# =========================================================
# LOGIN
# =========================================================
@app.route(
    "/",
    methods=["GET", "POST"]
)
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
                "Please enter your username and password.",
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

            session.clear()

            session["username"] = (
                user.username
            )

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


# =========================================================
# REGISTER
# =========================================================
@app.route(
    "/register",
    methods=["GET", "POST"]
)
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
                "This username already exists.",
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

        try:

            db.session.add(
                new_user
            )

            db.session.commit()

        except Exception:

            db.session.rollback()

            flash(
                "Unable to create the account. Please try again.",
                "danger"
            )

            return redirect(
                url_for("register")
            )

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


# =========================================================
# DASHBOARD
# =========================================================
@app.route("/dashboard")
def dashboard():

    if not login_required():

        flash(
            "Please log in to continue.",
            "warning"
        )

        return redirect(
            url_for("login")
        )

    user_folder = get_user_folder()

    search_text = request.args.get(
        "search",
        ""
    ).strip().lower()

    files = []

    for filename in os.listdir(
        user_folder
    ):

        file_path = os.path.join(
            user_folder,
            filename
        )

        if not os.path.isfile(
            file_path
        ):
            continue

        if (
            search_text
            and search_text
            not in filename.lower()
        ):
            continue

        file_size = os.path.getsize(
            file_path
        )

        file_extension = ""

        if "." in filename:

            file_extension = (
                filename
                .rsplit(".", 1)[1]
                .lower()
            )

        files.append({
            "name": filename,
            "size": file_size,
            "extension": file_extension
        })

    files.sort(
        key=lambda file:
        file["name"].lower()
    )

    return render_template(
        "dashboard.html",
        files=files,
        username=session["username"],
        search_text=search_text
    )


# =========================================================
# UPLOAD FILE
# =========================================================
@app.route(
    "/upload",
    methods=["GET", "POST"]
)
def upload():

    if not login_required():

        flash(
            "Please log in to upload files.",
            "warning"
        )

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
                "The selected filename is invalid.",
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

        if os.path.exists(
            file_path
        ):

            flash(
                "A file with this name already exists.",
                "danger"
            )

            return redirect(
                url_for("upload")
            )

        try:

            uploaded_file.save(
                file_path
            )

        except OSError:

            flash(
                "The file could not be saved.",
                "danger"
            )

            return redirect(
                url_for("upload")
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


# =========================================================
# VIEW FILE
# =========================================================
@app.route(
    "/view/<path:filename>"
)
def view_file(filename):

    if not login_required():

        flash(
            "Please log in to view files.",
            "warning"
        )

        return redirect(
            url_for("login")
        )

    safe_filename, user_folder, file_path = (
        get_safe_file_path(filename)
    )

    if not safe_filename:

        flash(
            "Invalid filename.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    if not os.path.isfile(
        file_path
    ):

        flash(
            "File not found.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    mime_type, encoding = (
        mimetypes.guess_type(
            file_path
        )
    )

    return send_from_directory(
        user_folder,
        safe_filename,
        mimetype=mime_type,
        as_attachment=False,
        download_name=safe_filename
    )


# =========================================================
# DOWNLOAD FILE
# =========================================================
@app.route(
    "/download/<path:filename>"
)
def download_file(filename):

    if not login_required():

        flash(
            "Please log in to download files.",
            "warning"
        )

        return redirect(
            url_for("login")
        )

    safe_filename, user_folder, file_path = (
        get_safe_file_path(filename)
    )

    if not safe_filename:

        flash(
            "Invalid filename.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    if not os.path.isfile(
        file_path
    ):

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


# =========================================================
# DELETE FILE
# =========================================================
@app.route(
    "/delete/<path:filename>",
    methods=["POST"]
)
def delete_file(filename):

    if not login_required():

        flash(
            "Please log in to delete files.",
            "warning"
        )

        return redirect(
            url_for("login")
        )

    safe_filename, user_folder, file_path = (
        get_safe_file_path(filename)
    )

    if not safe_filename:

        flash(
            "Invalid filename.",
            "danger"
        )

        return redirect(
            url_for("dashboard")
        )

    if os.path.isfile(
        file_path
    ):

        try:

            os.remove(
                file_path
            )

            flash(
                "File deleted successfully.",
                "success"
            )

        except OSError:

            flash(
                "The file could not be deleted.",
                "danger"
            )

    else:

        flash(
            "File not found.",
            "danger"
        )

    return redirect(
        url_for("dashboard")
    )


# =========================================================
# LOGOUT
# =========================================================
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


# =========================================================
# FILE TOO LARGE ERROR
# =========================================================
@app.errorhandler(413)
def file_too_large(error):

    flash(
        "File is too large. Maximum file size is 16 MB.",
        "danger"
    )

    return redirect(
        url_for("upload")
    )


# =========================================================
# PAGE NOT FOUND ERROR
# =========================================================
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


# =========================================================
# INTERNAL SERVER ERROR
# =========================================================
@app.errorhandler(500)
def internal_server_error(error):

    db.session.rollback()

    return render_template(
        "500.html"
    ), 500


# =========================================================
# START LOCAL DEVELOPMENT SERVER
# =========================================================
if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
