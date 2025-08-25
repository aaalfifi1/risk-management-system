import os
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import pytz
import uuid
from itsdangerous import URLSafeTimedSerializer as Serializer

# =============================================================================
# App Configuration
# =============================================================================
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a_very_secret_and_strong_key_12345')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///risk_management.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')
app.config['REPORTS_UPLOAD_FOLDER'] = os.path.join(app.root_path, 'reports_uploads')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "الرجاء تسجيل الدخول للوصول إلى هذه الصفحة."
login_manager.login_message_category = "info"

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['REPORTS_UPLOAD_FOLDER'], exist_ok=True)

# =============================================================================
# Database Models
# =============================================================================
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    users = db.relationship('User', backref='role', lazy=True)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(150), nullable=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_reset_token(self):
        s = Serializer(app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token, max_age_seconds=1800):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token, max_age=max_age_seconds)['user_id']
        except:
            return None
        return User.query.get(user_id)

class Risk(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    risk_code = db.Column(db.String(50), unique=True, nullable=True)
    title = db.Column(db.String(200))
    description = db.Column(db.Text)
    category = db.Column(db.String(100))
    owner = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    source = db.Column(db.String(100))
    risk_type = db.Column(db.String(50))
    risk_location = db.Column(db.String(200))
    risk_level = db.Column(db.String(50))
    proactive_actions = db.Column(db.Text)
    immediate_actions = db.Column(db.Text)
    target_completion_date = db.Column(db.String(50))
    action_effectiveness = db.Column(db.String(50))
    linked_risk_id = db.Column(db.String(50))
    status = db.Column(db.String(50))
    attachment_filename = db.Column(db.String(300))
    business_continuity_plan = db.Column(db.Text)
    lessons_learned = db.Column(db.Text)
    was_modified = db.Column(db.Boolean, default=False)
    is_read = db.Column(db.Boolean, default=False)
    def to_dict(self): return {c.name: getattr(self, c.name) for c in self.__table__.columns}

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(300), nullable=False)
    report_type = db.Column(db.String(50), nullable=False)
    uploaded_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_archived = db.Column(db.Boolean, default=False)

class StatusOption(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

# =============================================================================
# Login Manager & Hooks
# =============================================================================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def before_request():
    session.permanent = True
    if current_user.is_authenticated:
        session.modified = True

# =============================================================================
# Authentication & Password Reset Routes
# =============================================================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.locked_until and user.locked_until > datetime.utcnow():
            remaining_time = int((user.locked_until - datetime.utcnow()).total_seconds() / 60)
            flash(f"الحساب مقفل مؤقتاً. الرجاء المحاولة مرة أخرى بعد {remaining_time} دقيقة.", "danger")
            return redirect(url_for('login'))
        if user and user.check_password(password):
            user.failed_login_attempts = 0
            user.locked_until = None
            db.session.commit()
            login_user(user, remember=True)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        else:
            if user:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                    flash("لقد تجاوزت عدد المحاولات المسموح به. تم قفل الحساب لمدة 15 دقيقة.", "danger")
                else:
                    flash("اسم المستخدم أو كلمة المرور غير صحيحة.", "danger")
                db.session.commit()
            else:
                flash("اسم المستخدم أو كلمة المرور غير صحيحة.", "danger")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("تم تسجيل خروجك بنجاح.", "success")
    return redirect(url_for('login'))

@app.route("/reset_password", methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if user:
            token = user.get_reset_token()
            print(f"Password reset link for {user.email}: {url_for('reset_with_token', token=token, _external=True)}")
            flash('تم إرسال رابط إعادة التعيين إلى بريدك الإلكتروني (تحقق من طرفية الخادم).', 'success')
        else:
            flash('البريد الإلكتروني غير مسجل.', 'warning')
    return render_template('reset_password_request.html')

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_with_token(token):
    user = User.verify_reset_token(token)
    if not user:
        flash('الرابط غير صالح أو انتهت صلاحيته.', 'danger')
        return redirect(url_for('reset_password_request'))
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        if password != confirm_password:
            flash('كلمتا المرور غير متطابقتين.', 'danger')
            return render_template('reset_password.html', token=token)
        user.set_password(password)
        db.session.commit()
        flash('تم تحديث كلمة المرور بنجاح.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)

# =============================================================================
# Main Application Routes
# =============================================================================
@app.route('/')
@login_required
def index():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/reports')
@login_required
def reports():
    return render_template('reports.html')

@app.route('/manage_users')
@login_required
def manage_users():
    if current_user.role.name != 'Admin':
        flash("ليس لديك الصلاحية للوصول لهذه الصفحة.", "danger")
        return redirect(url_for('dashboard'))
    users = User.query.order_by(User.id).all()
    roles = Role.query.all()
    return render_template('manage_users.html', users=users, roles=roles)

# =============================================================================
# API Routes
# =============================================================================

# --- User Management API ---
@app.route('/api/users', methods=['POST'])
@login_required
def add_user():
    if current_user.role.name != 'Admin': return jsonify({'success': False, 'message': 'غير مصرح لك'}), 403
    data = request.form
    username, email, password, role_id = data.get('username'), data.get('email'), data.get('password'), data.get('role_id')
    if not all([username, email, password, role_id]): return jsonify({'success': False, 'message': 'جميع الحقول مطلوبة'}), 400
    if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
        return jsonify({'success': False, 'message': 'اسم المستخدم أو البريد الإلكتروني موجود بالفعل'}), 409
    new_user = User(username=username, email=email, role_id=role_id, full_name=username)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'success': True, 'message': 'تمت إضافة المستخدم بنجاح'})

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    if current_user.role.name != 'Admin': return jsonify({'success': False, 'message': 'غير مصرح لك'}), 403
    user = User.query.get_or_404(user_id)
    data = request.form
    user.email = data.get('email', user.email)
    user.role_id = data.get('role_id', user.role_id)
    if data.get('password'): user.set_password(data.get('password'))
    db.session.commit()
    return jsonify({'success': True, 'message': 'تم تحديث المستخدم بنجاح'})

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    if current_user.role.name != 'Admin': return jsonify({'success': False, 'message': 'غير مصرح لك'}), 403
    if user_id == current_user.id: return jsonify({'success': False, 'message': 'لا يمكنك حذف نفسك'}), 400
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'success': True, 'message': 'تم حذف المستخدم بنجاح'})

# --- Risk Management API ---
@app.route('/api/risks', methods=['GET'])
@login_required
def get_risks():
    try:
        query = db.session.query(Risk, User.full_name.label('owner_name')).outerjoin(User, Risk.user_id == User.id).order_by(Risk.created_at.desc())
        risks_data = [dict(r.to_dict(), owner_name=on) for r, on in query.all()]
        all_risk_codes = [r.risk_code for r in Risk.query.with_entities(Risk.risk_code).filter(Risk.risk_code.isnot(None)).all()]
        status_options = [s.name for s in StatusOption.query.order_by(StatusOption.id).all()]
        return jsonify({"success": True, "risks": risks_data, "all_risk_codes": all_risk_codes, "status_options": status_options})
    except Exception as e: return jsonify({"success": False, "message": f"خطأ في الخادم: {e}"}), 500

@app.route('/api/risks', methods=['POST'])
@login_required
def create_risk():
    try:
        data = request.form.to_dict()
        file = request.files.get('attachment')
        filename = None
        if file and file.filename:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        last_risk = Risk.query.order_by(Risk.id.desc()).first()
        new_risk_code = f"RISK_{datetime.now().year}_{(last_risk.id if last_risk else 0) + 1:04d}"
        new_risk = Risk(risk_code=new_risk_code, user_id=current_user.id, **data)
        db.session.add(new_risk)
        db.session.commit()
        return jsonify({"success": True, "message": "تم إضافة الخطر بنجاح."})
    except Exception as e: db.session.rollback(); return jsonify({"success": False, "message": f"خطأ في الخادم: {e}"}), 500

@app.route('/api/risks/<int:risk_id>', methods=['PUT'])
@login_required
def update_risk(risk_id):
    try:
        risk = Risk.query.get_or_404(risk_id)
        data = request.form.to_dict()
        file = request.files.get('attachment')
        for key, value in data.items():
            if hasattr(risk, key): setattr(risk, key, value)
        if file and file.filename:
            if risk.attachment_filename and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], risk.attachment_filename)):
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], risk.attachment_filename))
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            risk.attachment_filename = filename
        risk.was_modified = True
        db.session.commit()
        return jsonify({"success": True, "message": "تم تحديث الخطر بنجاح."})
    except Exception as e: db.session.rollback(); return jsonify({"success": False, "message": f"خطأ في الخادم: {e}"}), 500

@app.route('/api/risks/<int:risk_id>', methods=['DELETE'])
@login_required
def delete_risk(risk_id):
    try:
        risk = Risk.query.get_or_404(risk_id)
        db.session.delete(risk)
        db.session.commit()
        return jsonify({"success": True, "message": "تم حذف الخطر بنجاح."})
    except Exception as e: db.session.rollback(); return jsonify({"success": False, "message": f"خطأ في الخادم: {e}"}), 500

# --- Reports API ---
@app.route('/api/reports/upload', methods=['POST'])
@login_required
def upload_report_file():
    if current_user.role.name not in ['Admin', 'Pioneer']: return jsonify({'success': False, 'message': 'غير مصرح لك بالرفع'}), 403
    if 'report_file' not in request.files: return jsonify({'success': False, 'message': 'لم يتم العثور على ملف'})
    file = request.files['report_file']
    report_type = request.form.get('report_type')
    if file.filename == '' or not report_type: return jsonify({'success': False, 'message': 'بيانات ناقصة'})
    try:
        original_filename = secure_filename(file.filename)
        unique_filename = str(uuid.uuid4()) + os.path.splitext(original_filename)[1]
        type_folder = os.path.join(app.config['REPORTS_UPLOAD_FOLDER'], report_type)
        os.makedirs(type_folder, exist_ok=True)
        file.save(os.path.join(type_folder, unique_filename))
        new_report = Report(filename=unique_filename, report_type=report_type, uploaded_by=current_user.id)
        db.session.add(new_report)
        db.session.commit()
        return jsonify({'success': True, 'message': 'تم رفع الملف بنجاح'})
    except Exception as e: db.session.rollback(); return jsonify({'success': False, 'message': f'حدث خطأ أثناء الحفظ: {e}'}), 500

@app.route('/api/reports/files', methods=['GET'])
@login_required
def get_report_files():
    def file_to_dict(f):
        ksa_tz = pytz.timezone('Asia/Riyadh')
        modified_date_ksa = pytz.utc.localize(f.upload_date).astimezone(ksa_tz)
        return {'id': f.id, 'name': f.filename, 'type': f.report_type, 'modified_date': modified_date_ksa.isoformat()}
    try:
        if current_user.role.name == 'Admin':
            all_files = Report.query.filter_by(is_archived=False).all()
            archived_files = Report.query.filter_by(is_archived=True).all()
            files_by_type = {
                'quarterly': [file_to_dict(f) for f in all_files if f.report_type == 'quarterly'],
                'semi_annual': [file_to_dict(f) for f in all_files if f.report_type == 'semi_annual'],
                'annual': [file_to_dict(f) for f in all_files if f.report_type == 'annual'],
                'risk_champion': [file_to_dict(f) for f in all_files if f.report_type == 'risk_champion'],
            }
            return jsonify({'success': True, 'files': files_by_type, 'archived_files': [file_to_dict(f) for f in archived_files]})
        elif current_user.role.name == 'Pioneer':
            user_files = Report.query.filter_by(uploaded_by=current_user.id, is_archived=False).all()
            return jsonify({'success': True, 'files': {'risk_champion': [file_to_dict(f) for f in user_files]}})
        else: return jsonify({'success': False, 'message': 'غير مصرح لك'}), 403
    except Exception as e: return jsonify({'success': False, 'message': f'خطأ في الخادم: {e}'}), 500

# ... (Other report actions like archive, restore, delete would go here)

# =============================================================================
# File Serving Routes
# =============================================================================
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/reports_uploads/<report_type>/<filename>')
def uploaded_report_file(report_type, filename):
    return send_from_directory(os.path.join(app.config['REPORTS_UPLOAD_FOLDER'], report_type), filename)

# =============================================================================
# Main Execution
# =============================================================================
if __name__ == '__main__':
    app.run(debug=True, port=5001)
