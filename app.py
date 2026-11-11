
import os
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    abort
)

from flask_sqlalchemy import SQLAlchemy

from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user
)

from flask_wtf.csrf import CSRFProtect

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


# --------------------------------------------------
# 1. APPLICATION CONFIGURATION
# --------------------------------------------------

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "development-key-change-before-deployment"
)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///secure_records.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Session and cookie security
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get(
    "COOKIE_SECURE", "False"
).lower() == "true"

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to access this page."

csrf = CSRFProtect(app)


# --------------------------------------------------
# 2. DATABASE MODELS
# --------------------------------------------------

class User(UserMixin, db.Model):

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(80),
        unique=True,
        nullable=False
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False
    )

    password = db.Column(
        db.String(255),
        nullable=False
    )

    role = db.Column(
        db.String(20),
        default="user",
        nullable=False
    )


class Record(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    title = db.Column(
        db.String(120),
        nullable=False
    )

    description = db.Column(
        db.Text,
        nullable=False
    )

    owner_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        server_default=db.func.current_timestamp()
    )

    owner = db.relationship(
        "User",
        backref="records"
    )


class AuditLog(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=True
    )

    action = db.Column(
        db.String(100),
        nullable=False
    )

    details = db.Column(
        db.String(255),
        nullable=True
    )

    timestamp = db.Column(
        db.DateTime,
        server_default=db.func.current_timestamp()
    )

    user = db.relationship("User")


# --------------------------------------------------
# 3. USER SESSION MANAGEMENT
# --------------------------------------------------

@login_manager.user_loader
def load_user(user_id):

    return db.session.get(User, int(user_id))


# --------------------------------------------------
# 4. AUDIT LOGGING
# --------------------------------------------------

def log_action(action, details=""):

    user_id = (
        current_user.id
        if current_user.is_authenticated
        else None
    )

    audit_entry = AuditLog(
        user_id=user_id,
        action=action,
        details=details
    )

    db.session.add(audit_entry)
    db.session.commit()


# --------------------------------------------------
# 5. ADMIN ACCESS DECORATOR
# --------------------------------------------------

def admin_required(function):

    @wraps(function)
    @login_required
    def decorated_function(*args, **kwargs):

        if current_user.role != "admin":
            abort(403)

        return function(*args, **kwargs)

    return decorated_function


# --------------------------------------------------
# 6. HOME PAGE
# --------------------------------------------------

@app.route("/")
def home():

    return render_template("index.html")


# --------------------------------------------------
# 7. USER REGISTRATION
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        username = request.form.get(
            "username", ""
        ).strip()

        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get(
            "password", ""
        )

        if not username or not email or not password:

            flash("Please complete all fields.", "error")
            return redirect(url_for("register"))

        if len(password) < 12:

            flash(
                "Your password must be at least 12 characters.",
                "error"
            )

            return redirect(url_for("register"))

        existing_user = User.query.filter(
            (User.username == username) |
            (User.email == email)
        ).first()

        if existing_user:

            flash(
                "Username or email is already registered.",
                "error"
            )

            return redirect(url_for("register"))

        new_user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            role="user"
        )

        db.session.add(new_user)
        db.session.commit()

        log_action(
            "User registered",
            f"New account created: {username}"
        )

        flash(
            "Account created successfully. Please log in.",
            "success"
        )

        return redirect(url_for("login"))

    return render_template("register.html")


# --------------------------------------------------
# 8. USER LOGIN
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        email = request.form.get(
            "email", ""
        ).strip().lower()

        password = request.form.get(
            "password", ""
        )

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(
            user.password, password
        ):

            login_user(user)

            log_action(
                "User login",
                f"Successful login: {user.username}"
            )

            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "error")

    return render_template("login.html")


# --------------------------------------------------
# 9. USER DASHBOARD
# --------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():

    return render_template("dashboard.html")


# --------------------------------------------------
# 10. USER LOGOUT
# --------------------------------------------------

@app.route("/logout", methods=["POST"])
@login_required
def logout():

    log_action(
        "User logout",
        f"User logged out: {current_user.username}"
    )

    logout_user()

    flash("You have been logged out.", "success")

    return redirect(url_for("home"))


# --------------------------------------------------
# 11. VIEW RECORDS
# --------------------------------------------------

@app.route("/records")
@login_required
def records():

    if current_user.role == "admin":

        all_records = Record.query.order_by(
            Record.created_at.desc()
        ).all()

    else:

        all_records = Record.query.filter_by(
            owner_id=current_user.id
        ).order_by(
            Record.created_at.desc()
        ).all()

    return render_template(
        "records.html",
        records=all_records
    )


# --------------------------------------------------
# 12. ADD RECORD
# --------------------------------------------------

@app.route("/records/add", methods=["GET", "POST"])
@login_required
def add_record():

    if request.method == "POST":

        title = request.form.get(
            "title", ""
        ).strip()

        description = request.form.get(
            "description", ""
        ).strip()

        if not title or not description:

            flash(
                "Please complete all fields.",
                "error"
            )

            return redirect(url_for("add_record"))

        if len(title) > 120:

            flash(
                "The record title must be 120 characters or fewer.",
                "error"
            )

            return redirect(url_for("add_record"))

        new_record = Record(
            title=title,
            description=description,
            owner_id=current_user.id
        )

        db.session.add(new_record)
        db.session.commit()

        log_action(
            "Record created",
            f"Record ID: {new_record.id}"
        )

        flash("Record added successfully.", "success")

        return redirect(url_for("records"))

    return render_template("add_record.html")



# --------------------------------------------------
# SUPPORT REQUEST SUBMISSION
# --------------------------------------------------

@app.route("/requests/submit", methods=["GET", "POST"])
@login_required
def submit_request():

    if request.method == "POST":

        category = request.form.get("category", "")
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()

        if category not in REQUEST_CATEGORIES:
            flash("Please select a valid request category.", "error")
            return redirect(url_for("submit_request"))

        if not title or not description:
            flash("Please complete all fields.", "error")
            return redirect(url_for("submit_request"))

        if len(title) > 120:
            flash("Your title must be 120 characters or fewer.", "error")
            return redirect(url_for("submit_request"))

        new_request = SupportRequest(
            category=category,
            title=title,
            description=description,
            user_id=current_user.id
        )

        db.session.add(new_request)
        db.session.commit()

        log_action(
            "Support request submitted",
            f"Request ID: {new_request.id}; Category: {category}"
        )

        flash("Your support request has been submitted.", "success")

        return redirect(url_for("my_requests"))

    return render_template(
        "submit_request.html",
        categories=REQUEST_CATEGORIES
    )


# --------------------------------------------------
# VIEW THE LOGGED-IN USER'S REQUESTS
# --------------------------------------------------

@app.route("/my-requests")
@login_required
def my_requests():

    user_requests = SupportRequest.query.filter_by(
        user_id=current_user.id
    ).order_by(
        SupportRequest.created_at.desc()
    ).all()

    return render_template(
        "my_requests.html",
        requests=user_requests
    )


# --------------------------------------------------
# VIEW AN INDIVIDUAL SUPPORT REQUEST
# --------------------------------------------------

@app.route("/requests/<int:request_id>")
@login_required
def view_request(request_id):

    support_request = db.session.get(
        SupportRequest,
        request_id
    )

    if support_request is None:
        abort(404)

    if (
        current_user.role != "admin"
        and support_request.user_id != current_user.id
    ):
        abort(403)

    return render_template(
        "view_request.html",
        support_request=support_request
    )


# --------------------------------------------------
# 13. VIEW INDIVIDUAL RECORD
# --------------------------------------------------

@app.route("/records/<int:record_id>")
@login_required
def view_record(record_id):

    record = db.session.get(Record, record_id)

    if record is None:
        abort(404)

    if (
        current_user.role != "admin"
        and record.owner_id != current_user.id
    ):

        abort(403)

    return render_template(
        "view_record.html",
        record=record
    )


# --------------------------------------------------
# 14. EDIT RECORD
# --------------------------------------------------

@app.route(
    "/records/<int:record_id>/edit",
    methods=["GET", "POST"]
)
@login_required
def edit_record(record_id):

    record = db.session.get(Record, record_id)

    if record is None:
        abort(404)

    if (
        current_user.role != "admin"
        and record.owner_id != current_user.id
    ):

        abort(403)

    if request.method == "POST":

        title = request.form.get(
            "title", ""
        ).strip()

        description = request.form.get(
            "description", ""
        ).strip()

        if not title or not description:

            flash(
                "Please complete all fields.",
                "error"
            )

            return redirect(
                url_for("edit_record", record_id=record.id)
            )

        if len(title) > 120:

            flash(
                "The record title must be 120 characters or fewer.",
                "error"
            )

            return redirect(
                url_for("edit_record", record_id=record.id)
            )

        record.title = title
        record.description = description

        db.session.commit()

        log_action(
            "Record updated",
            f"Record ID: {record.id}"
        )

        flash("Record updated successfully.", "success")

        return redirect(
            url_for("view_record", record_id=record.id)
        )

    return render_template(
        "edit_record.html",
        record=record
    )


# --------------------------------------------------
# 15. DELETE RECORD
# --------------------------------------------------

@app.route(
    "/records/<int:record_id>/delete",
    methods=["POST"]
)
@login_required
def delete_record(record_id):

    record = db.session.get(Record, record_id)

    if record is None:
        abort(404)

    if (
        current_user.role != "admin"
        and record.owner_id != current_user.id
    ):

        abort(403)

    record_id_to_delete = record.id

    db.session.delete(record)
    db.session.commit()

    log_action(
        "Record deleted",
        f"Record ID: {record_id_to_delete}"
    )

    flash("Record deleted successfully.", "success")

    return redirect(url_for("records"))


# --------------------------------------------------
# 16. ADMIN DASHBOARD
# --------------------------------------------------

@app.route("/admin")
@admin_required
def admin_dashboard():

    users = User.query.order_by(
        User.username
    ).all()

    all_records = Record.query.order_by(
        Record.created_at.desc()
    ).all()

    return render_template(
        "admin.html",
        users=users,
        records=all_records
    )


# --------------------------------------------------
# 17. ADMIN USER ROLE MANAGEMENT
# --------------------------------------------------

@app.route(
    "/admin/users/<int:user_id>/role",
    methods=["POST"]
)
@admin_required
def change_user_role(user_id):

    user = db.session.get(User, user_id)

    if user is None:
        abort(404)

    if user.id == current_user.id:

        flash(
            "You cannot change your own administrator role.",
            "error"
        )

        return redirect(url_for("admin_dashboard"))

    new_role = request.form.get("role", "")

    if new_role not in ["user", "admin"]:

        flash("Invalid role selected.", "error")

        return redirect(url_for("admin_dashboard"))

    user.role = new_role
    db.session.commit()

    log_action(
        "User role changed",
        f"User ID: {user.id}, new role: {new_role}"
    )

    flash("User role updated successfully.", "success")

    return redirect(url_for("admin_dashboard"))


# --------------------------------------------------
# ADMIN VIEW ALL SUPPORT REQUESTS
# --------------------------------------------------

@app.route("/admin/requests")
@admin_required
def admin_requests():

    all_requests = SupportRequest.query.order_by(
        SupportRequest.created_at.desc()
    ).all()

    return render_template(
        "admin_requests.html",
        requests=all_requests,
        statuses=REQUEST_STATUSES
    )


# --------------------------------------------------
# ADMIN UPDATE REQUEST STATUS
# --------------------------------------------------

@app.route(
    "/admin/requests/<int:request_id>/status",
    methods=["POST"]
)
@admin_required
def update_request_status(request_id):

    support_request = db.session.get(
        SupportRequest,
        request_id
    )

    if support_request is None:
        abort(404)

    new_status = request.form.get("status", "")

    if new_status not in REQUEST_STATUSES:
        abort(400)

    support_request.status = new_status
    db.session.commit()

    log_action(
        "Support request status updated",
        f"Request ID: {support_request.id}; Status: {new_status}"
    )

    flash("Request status updated successfully.", "success")

    return redirect(url_for("admin_requests"))


# --------------------------------------------------
# 18. VIEW AUDIT LOGS
# --------------------------------------------------


class SupportRequest(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    category = db.Column(
        db.String(50),
        nullable=False
    )

    title = db.Column(
        db.String(120),
        nullable=False
    )

    description = db.Column(
        db.Text,
        nullable=False
    )

    status = db.Column(
        db.String(30),
        default="Pending",
        nullable=False
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    created_at = db.Column(
        db.DateTime,
        server_default=db.func.current_timestamp()
    )

    user = db.relationship(
        "User",
        backref="support_requests"
    )


REQUEST_CATEGORIES = [
    "Wellbeing",
    "Academic Support",
    "Financial Concerns",
    "Disability Support",
    "Accommodation Issues"
]

REQUEST_STATUSES = [
    "Pending",
    "In Progress",
    "Approved",
    "Rejected",
    "Completed"
]


# --------------------------------------------------
# 19. CREATE DATABASE TABLES
# --------------------------------------------------

with app.app_context():

    db.create_all()


# --------------------------------------------------
# 20. RUN APPLICATION
# --------------------------------------------------

if __name__ == "__main__":

    app.run(debug=True)


    