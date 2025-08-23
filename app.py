from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
import os, time
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from werkzeug.utils import secure_filename
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from sqlalchemy import or_

# =======================================
# Flask App Setuppp
# =======================================
app = Flask(__name__)

# Config
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'citysahayak.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'secretkey'

# Upload folders
UPLOAD_FOLDER = os.path.join('static', 'uploads')
PROFILE_FOLDER = os.path.join('static', 'profile_pics')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['PROFILE_FOLDER'] = PROFILE_FOLDER

for folder in (UPLOAD_FOLDER, PROFILE_FOLDER):
    if not os.path.exists(folder):
        os.makedirs(folder)

# Init extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# =======================================
# Models
# =======================================
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    dob = db.Column(db.String(20))
    gender = db.Column(db.String(10))
    address = db.Column(db.String(255))
    state = db.Column(db.String(100))
    pin = db.Column(db.String(10))
    profile_image = db.Column(db.String(200))

    # ✅ Relationship: ek user ke multiple incidents
    incidents = db.relationship('Incident', backref='user', lazy=True)


class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    image = db.Column(db.String(200))
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # ab incident.user se user object milega
    # aur incident.user.name ya incident.user.email use kar paoge


class Notice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


# =======================================
# Helpers
# =======================================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename: str) -> bool:
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS

def unique_filename(original: str, prefix: str = "") -> str:
    name = secure_filename(original)
    ts = int(time.time())
    root, ext = os.path.splitext(name)
    return f"{prefix}{root}_{ts}{ext}"

def india_time(dt):
    try:
        india = ZoneInfo("Asia/Kolkata")
    except Exception:
        india = timezone.utc
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt)
        except Exception:
            dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(india).strftime("%d-%m-%Y %I:%M %p")

def parse_date_local(date_str):
    if not date_str:
        return None
    date_str = date_str.strip()
    if not date_str:
        return None
    try:
        y, m, d = map(int, date_str.split("-"))
        local = datetime(y, m, d, 0, 0, 0, tzinfo=ZoneInfo("Asia/Kolkata"))
        return local.astimezone(timezone.utc)
    except Exception:
        pass
    try:
        dt = datetime.fromisoformat(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=ZoneInfo("Asia/Kolkata"))
        return dt.astimezone(timezone.utc)
    except Exception:
        return None

def is_admin():
    return current_user.is_authenticated and current_user.email == "admincitysahayak@gmail.com"

# =======================================
# Routes
# =======================================
@app.route('/')
def index():
    return redirect(url_for('home'))

@app.route('/home')
def home():
    notices = Notice.query.order_by(Notice.timestamp.desc()).limit(10).all()
    for n in notices:
        n.formatted_time = india_time(n.timestamp)
    return render_template('home.html', notices=notices)

# ---------- Auth ----------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        hashed_pw = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        new_user = User(
            name=request.form['username'],
            email=request.form['email'],
            password=hashed_pw
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully. Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(name=request.form['username']).first()
        if user and bcrypt.check_password_hash(user.password, request.form['password']):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# ✅ अब यहाँ Admin Dashboard route डालो
@app.route('/admin')
@login_required
def admin_dashboard():
    if not is_admin():
        abort(403)
    users = User.query.all()
    incidents = Incident.query.order_by(Incident.timestamp.desc()).all()
    notices = Notice.query.order_by(Notice.timestamp.desc()).all()
    return render_template("admin_dashboard.html", users=users, incidents=incidents, notices=notices)


# ---------- Dashboard ----------
@app.route('/dashboard')
@login_required
def dashboard():
    q = request.args.get('q', '', type=str).strip()
    loc = request.args.get('loc', '', type=str).strip()
    date_from = request.args.get('date_from', '', type=str)
    date_to = request.args.get('date_to', '', type=str)
    sort = request.args.get('sort', 'newest', type=str)
    cat = request.args.get('cat', '', type=str).strip()
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 5, type=int)
    per_page = max(3, min(per_page, 20))
    sort = sort if sort in ('newest', 'oldest') else 'newest'

    query = Incident.query.filter_by(user_id=current_user.id)

    if q:
        like = f"%{q}%"
        query = query.filter(or_(Incident.title.ilike(like), Incident.description.ilike(like)))
    if loc:
        query = query.filter(Incident.location.ilike(f"%{loc}%"))
    if cat:
        query = query.filter(Incident.category == cat)

    start_dt = parse_date_local(date_from) if date_from else None
    end_dt = parse_date_local(date_to) if date_to else None
    if start_dt:
        query = query.filter(Incident.timestamp >= start_dt)
    if end_dt:
        local_end = end_dt.astimezone(ZoneInfo("Asia/Kolkata")).replace(hour=23, minute=59, second=59, microsecond=999999)
        end_dt_utc = local_end.astimezone(timezone.utc)
        query = query.filter(Incident.timestamp <= end_dt_utc)

    if sort == 'oldest':
        query = query.order_by(Incident.timestamp.asc())
    else:
        query = query.order_by(Incident.timestamp.desc())

    incidents = query.paginate(page=page, per_page=per_page, error_out=False)

    for inc in incidents.items:
        inc.formatted_time = india_time(inc.timestamp)

    return render_template('dashboard.html',
                           incidents=incidents,
                           q=q, loc=loc, date_from=date_from, date_to=date_to,
                           sort=sort, per_page=per_page, cat=cat)

# ---------- Report Incident ----------
@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        location = request.form['location']
        category = request.form['category']

        image_file = request.files.get('image')
        image_filename = None
        if image_file and image_file.filename and allowed_file(image_file.filename):
            image_filename = unique_filename(image_file.filename, prefix="inc_")
            image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))

        new_incident = Incident(
            title=title,
            description=description,
            location=location,
            category=category,
            image=image_filename,
            user_id=current_user.id
        )
        db.session.add(new_incident)
        db.session.commit()
        flash("Incident reported successfully!", "success")
        return redirect(url_for('dashboard'))

    return render_template('incident_form.html')

# ---------- Edit/Delete Incident ----------
@app.route('/incident/<int:incident_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_incident(incident_id):
    inc = Incident.query.filter_by(id=incident_id, user_id=current_user.id).first_or_404()
    if request.method == 'POST':
        inc.title = request.form['title']
        inc.description = request.form['description']
        inc.location = request.form['location']

        file = request.files.get('image')
        if file and file.filename and allowed_file(file.filename):
            image_filename = unique_filename(file.filename, prefix="inc_")
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
            inc.image = image_filename

        db.session.commit()
        flash('Incident updated.', 'success')
        return redirect(url_for('dashboard'))
    return render_template('incident_form.html', incident=inc)

@app.route('/incident/<int:incident_id>/delete', methods=['POST'])
@login_required
def delete_incident(incident_id):
    inc = Incident.query.filter_by(id=incident_id, user_id=current_user.id).first_or_404()
    if inc.image:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], inc.image))
        except Exception:
            pass
    db.session.delete(inc)
    db.session.commit()
    flash('Incident deleted.', 'info')
    return redirect(url_for('dashboard'))

# ---------- Profile ----------
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.name = request.form.get('name') or current_user.name
        current_user.email = request.form.get('email') or current_user.email
        current_user.dob = request.form.get('dob') or None
        current_user.gender = request.form.get('gender') or None
        current_user.address = request.form.get('address') or None
        current_user.state = request.form.get('state') or None
        current_user.pin = request.form.get('pin') or None

        pfile = request.files.get('profile_image')
        if pfile and pfile.filename and allowed_file(pfile.filename):
            filename = unique_filename(pfile.filename, prefix=f"user{current_user.id}_")
            save_path = os.path.join(app.config['PROFILE_FOLDER'], filename)
            pfile.save(save_path)
            if current_user.profile_image and current_user.profile_image != filename:
                try:
                    os.remove(os.path.join(app.config['PROFILE_FOLDER'], current_user.profile_image))
                except Exception:
                    pass
            current_user.profile_image = filename

        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=current_user)

# ---------- Notice System ----------
@app.route('/notices')
@login_required
def view_notices():
    notices = Notice.query.order_by(Notice.timestamp.desc()).all()
    for n in notices:
        n.formatted_time = india_time(n.timestamp)
    return render_template('notices.html', notices=notices)

@app.route('/add_notice', methods=['GET', 'POST'])
@login_required
def add_notice():
    if not is_admin():
        abort(403)
    if request.method == 'POST':
        title = request.form['title'].strip()
        content = request.form['content'].strip()
        if not title or not content:
            flash("Title and content are required.", "warning")
            return redirect(url_for('add_notice'))
        new_notice = Notice(title=title, content=content)
        db.session.add(new_notice)
        db.session.commit()
        flash("Notice added successfully!", "success")
        return redirect(url_for('view_notices'))
    return render_template('add_notice.html')

@app.route('/notice/<int:notice_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_notice(notice_id):
    if not is_admin():
        abort(403)
    notice = Notice.query.get_or_404(notice_id)
    if request.method == 'POST':
        title = request.form['title'].strip()
        content = request.form['content'].strip()
        if not title or not content:
            flash("Title and content are required.", "warning")
            return redirect(url_for('edit_notice', notice_id=notice.id))
        notice.title = title
        notice.content = content
        db.session.commit()
        flash("Notice updated successfully!", "success")
        return redirect(url_for('view_notices'))
    return render_template('add_notice.html', notice=notice)

@app.route('/notice/<int:notice_id>/delete', methods=['POST'])
@login_required
def delete_notice(notice_id):
    if not is_admin():
        abort(403)
    notice = Notice.query.get_or_404(notice_id)
    db.session.delete(notice)
    db.session.commit()
    flash("Notice deleted successfully!", "info")
    return redirect(url_for('view_notices'))

@app.route('/api/notices')
def api_notices():
    notices = Notice.query.order_by(Notice.timestamp.desc()).limit(15).all()
    data = [{"id": n.id, "title": n.title, "content": n.content, "time": india_time(n.timestamp)} for n in notices]
    return jsonify(data)

# =======================================
# Run App
# =======================================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
