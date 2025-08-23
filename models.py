from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    incidents = db.relationship('Incident', backref='user', lazy=True)

class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    description = db.Column(db.Text)
    location = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    image_filename = db.Column(db.String(100))
    
    # ✅ NEW FIELD for Complaint Status
    status = db.Column(db.String(20), default="Pending")
    # Possible values: "Pending", "Processing", "Resolved"
