from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_jwt_extended import JWTManager, create_access_token
from forms import RegistrationForm, LoginForm
from models import db, User
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import pyotp
import os
import logging
from logging import FileHandler
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['JWT_SECRET_KEY'] = os.urandom(24)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = False  # Change to True in production with HTTPS
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your_email@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'your_email_password'   # Replace with your email password

db.init_app(app)
migrate = Migrate(app, db)
mail = Mail(app)
jwt = JWTManager(app)

# Enable error logging
if not app.debug:
    file_handler = FileHandler('error.log')
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)

with app.app_context():
    db.create_all()  # Create tables in the database

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            hashed_password = generate_password_hash(form.password.data)  # Using default method
            new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            app.logger.error(f'Error during registration: {e}')
            flash('An error occurred while creating the account. Please try again.', 'danger')
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):  # Verify password
            # Generate a 6-digit OTP
            totp = pyotp.TOTP(pyotp.random_base32())
            otp_code = totp.now()
            user.otp = otp_code
            user.otp_expiry = datetime.utcnow() + timedelta(minutes=5)  # OTP expires in 5 minutes
            db.session.commit()

            # Send OTP via email
            msg = Message('Your 2FA Code', sender='your_email@gmail.com', recipients=[user.email])
            msg.body = f'Your 2FA code is: {otp_code}. It will expire in 5 minutes.'
            mail.send(msg)

            flash('An OTP has been sent to your email.', 'info')
            session['user_id'] = user.id  # Store user ID in session temporarily
            return redirect(url_for('verify_otp'))
        else:
            flash('Login failed. Check your email and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'user_id' not in session:
        flash('Session expired. Please log in again.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp_code = request.form.get('otp')
        user = User.query.get(session['user_id'])

        if user and user.otp == otp_code and user.otp_expiry > datetime.utcnow():
            session.pop('user_id', None)  # Remove user_id from session
            user.otp = None  # Clear OTP field
            user.otp_expiry = None
            db.session.commit()
            
            access_token = create_access_token(identity=user.id)
            session['jwt_token'] = access_token
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid or expired OTP. Please try again.', 'danger')

    return render_template('verify_otp.html')

if __name__ == '__main__':
    app.run(debug=True, ssl_context='adhoc')
