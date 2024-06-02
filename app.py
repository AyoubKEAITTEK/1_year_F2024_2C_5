from flask import Flask, render_template, request, url_for, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from datetime import datetime
import pytz

app = Flask(__name__)
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

# Opret en admin-bruger ved første anmodning
admin_created = False

@app.before_request
def create_admin():
    global admin_created
    if not admin_created:
        admin = Users.query.filter_by(username='marcus').first()  
        if not admin:
            hashed_password = bcrypt.generate_password_hash('1234').decode('utf-8')
            admin = Users(username='marcus', password=hashed_password, is_admin=True)  
            db.session.add(admin)
            db.session.commit()
        admin_created = True

@app.route('/')
def index():
    return redirect(url_for('login'))

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
            if username == 'marcus' and password == '1234':
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
    return render_template("admin_dashboard.html")

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template("dashboard.html", username=current_user.username)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=443, ssl_context=('mycert.crt', 'mycert.key'))
