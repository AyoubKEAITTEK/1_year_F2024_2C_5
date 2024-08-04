from flask import Flask, render_template, request, url_for, redirect, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from datetime import datetime
import pytz

app = Flask(_name_)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///db.sqlite"
app.config["SECRET_KEY"] = "abc"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['TIMEZONE'] = 'Europe/Copenhagen'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    last_login = db.Column(db.DateTime)
    last_logout = db.Column(db.DateTime)
    is_admin = db.Column(db.Boolean, default=False)

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

# Specific user ID that has admin rights
ADMIN_USER_ID = 8  # Replace with the actual ID from your database

@app.before_request
def check_admin_access():
    if current_user.is_authenticated and current_user.id == ADMIN_USER_ID:
        current_user.is_admin = True  # Mark the user as admin if they have the correct ID

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        print(f"Received login attempt with username: {username} and password: {password}")
        user = Users.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            user.last_login = datetime.now(pytz.timezone(app.config['TIMEZONE']))
            db.session.commit()
            print("Login successful")
            if user.id == ADMIN_USER_ID:
                return redirect(url_for("admin_dashboard"))
            else:
                return redirect(url_for("dashboard"))
        else:
            print("Invalid username or password")
    return render_template("login.html")

@app.route('/logout')
@login_required
def logout():
    current_user.last_logout = datetime.now(pytz.timezone(app.config['TIMEZONE']))
    db.session.commit()
    logout_user()
    return redirect(url_for("index"))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if current_user.is_admin:
        if request.referrer and request.referrer.startswith(request.host_url):
            return render_template("admin_dashboard.html")
        else:
            abort(403)  # Access forbidden if accessed directly
    else:
        abort(403)  # Access forbidden if not an admin

@app.route('/dashboard')
@login_required
def dashboard():
    if request.referrer and request.referrer.startswith(request.host_url):
        return render_template("dashboard.html", username=current_user.username)
    else:
        abort(403)  # Access forbidden if accessed directly

@app.errorhandler(403)
def access_forbidden(error):
    return render_template('error.html', error="403 Forbidden - Access Denied"), 403

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if password != confirm_password:
            print("Passwords do not match")
            return render_template("sign_up.html", error="Passwords do not match")

        user = Users.query.filter_by(username=username).first()
        if user:
            print("Username already exists")
            return render_template("sign_up.html", error="Username already exists")
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = Users(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        print("User registered successfully")
        return redirect(url_for('login'))
    
    return render_template("sign_up.html")

if _name_ == "_main_":
    app.run(host='0.0.0.0
', port=443, ssl_context=('mycert.crt', 'mycert.key'))
current_user.id
