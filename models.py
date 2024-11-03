from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    otp = db.Column(db.String(6), nullable=True)  # Store OTP
    otp_expiry = db.Column(db.DateTime, nullable=True)  # Store OTP expiration time
