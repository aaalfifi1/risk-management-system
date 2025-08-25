# --- المكتبات الأساسية ---
from flask import (Flask, render_template, request, jsonify, redirect, url_for, 
                   send_from_directory, abort, Response, session, flash)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import joinedload
from flask_login import (LoginManager, UserMixin, login_user, logout_user, 
                         login_required, current_user)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os
import csv
import io
from collections import Counter
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
import traceback
from functools import wraps # [إضافة] لاستخدام المزخرف
import secrets

# =============================================================================
# App Configuration
# =============================================================================
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_very_secret_key_that_should_be_changed' # يجب تغيير هذا في بيئة الإنتاج
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///risk_management.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')
app.config['REPORTS_UPLOAD_FOLDER'] = os.path.join(app.root_path, 'reports_uploads')

# [مكتسب أمني] إعداد مدة الجلسة للخروج التلقائي
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "الرجاء تسجيل الدخول للوصول إلى هذه الصفحة."
login_manager.login_message_category = "info"

# Ensure upload folders exist
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
    password_hash = db.Column(db.String(200), nullable=False)
    full_name = db.Column(db.String(150), nullable=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    # [مكتسب أمني] حقول قفل الحساب
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Risk(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    risk_code = db.Column(db.String(50), unique=True, nullable=True)
    title = db.Column(db.String(200))
    description = db.Column(db.Text)
    category = db.Column(db.String(100))
    owner = db.Column(db.String(100)) # Kept for reporter input
    user_id = db.Column(db.Integer, db.ForeignKey('user.id')) # Link to user who created it
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
    
    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}

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
# Flask-Login Loader
# =============================================================================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# =============================================================================
# Context Processors & Before Request Handlers
# =============================================================================
@app.context_processor
def inject_user_role():
    user_role = current_user.role.name if current_user.is_authenticated else 'Guest'
    return dict(user_role=user_role)

# [مكتسب أمني] معالجة الجلسة قبل كل طلب
@app.before_request
def before_request():
    session.permanent = True
    if current_user.is_authenticated:
        session.modified = True

# =============================================================================
# Authentication Routes (Login, Logout) - With Security Features
# =============================================================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        # [مكتسب أمني] التحقق من قفل الحساب
        if user and user.locked_until and user.locked_until > datetime.utcnow():
            flash(f"الحساب مقفل مؤقتاً. الرجاء المحاولة مرة أخرى بعد {int((user.locked_until - datetime.utcnow()).total_seconds() / 60)} دقيقة.", "danger")
            return redirect(url_for('login'))

        if user and user.check_password(password):
            user.failed_login_attempts = 0
            user.locked_until = None
            db.session.commit()
            login_user(user, remember=True)
            return redirect(url_for('dashboard'))
        else:
            if user:
                # [مكتسب أمني] زيادة عدد المحاولات الفاشلة وقفل الحساب
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

# =============================================================================
# Main Application Routes (Dashboard, Reports, etc.)
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

# [مكتسب] صفحة إدارة المستخدمين
@app.route('/manage_users')
@login_required
def manage_users():
    if current_user.role.name != 'Admin':
        flash("ليس لديك الصلاحية للوصول لهذه الصفحة.", "danger")
        return redirect(url_for('dashboard'))
    users = User.query.all()
    roles = Role.query.all()
    return render_template('manage_users.html', users=users, roles=roles)

# =============================================================================
# API Routes - Users Management
# =============================================================================
@app.route('/api/users', methods=['POST'])
@login_required
def add_user():
    if current_user.role.name != 'Admin':
        return jsonify({'success': False, 'message': 'غير مصرح لك'}), 403
    
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    full_name = data.get('full_name')
    role_id = data.get('role_id')

    if not all([username, password, full_name, role_id]):
        return jsonify({'success': False, 'message': 'جميع الحقول مطلوبة'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'success': False, 'message': 'اسم المستخدم موجود بالفعل'}), 409

    new_user = User(username=username, full_name=full_name, role_id=role_id)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'success': True, 'message': 'تمت إضافة المستخدم بنجاح'})

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    if current_user.role.name != 'Admin':
        return jsonify({'success': False, 'message': 'غير مصرح لك'}), 403
    
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    
    user.full_name = data.get('full_name', user.full_name)
    user.role_id = data.get('role_id', user.role_id)
    
    new_password = data.get('password')
    if new_password:
        user.set_password(new_password)
    
    db.session.commit()
    return jsonify({'success': True, 'message': 'تم تحديث المستخدم بنجاح'})

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    if current_user.role.name != 'Admin':
        return jsonify({'success': False, 'message': 'غير مصرح لك'}), 403
    
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        return jsonify({'success': False, 'message': 'لا يمكنك حذف المستخدم الحالي'}), 400
    
    db.session.delete(user)
    db.session.commit()
    return jsonify({'success': True, 'message': 'تم حذف المستخدم بنجاح'})

# =============================================================================
# API Routes - Risk Management
# =============================================================================

# [إصلاح] دالة جلب المخاطر المحدثة
@app.route('/api/risks', methods=['GET'])
@login_required
def get_risks():
    try:
        query = db.session.query(Risk, User.full_name.label('owner_name')) \
                          .outerjoin(User, Risk.user_id == User.id) \
                          .order_by(Risk.created_at.desc())
        
        risks_data = []
        for risk, owner_name in query.all():
            risk_dict = risk.to_dict()
            risk_dict['owner_name'] = owner_name
            risks_data.append(risk_dict)

        all_risk_codes = [r.risk_code for r in Risk.query.with_entities(Risk.risk_code).filter(Risk.risk_code.isnot(None)).all()]
        status_options = [s.name for s in StatusOption.query.order_by(StatusOption.id).all()]

        return jsonify({
            "success": True,
            "risks": risks_data,
            "all_risk_codes": all_risk_codes,
            "status_options": status_options
        })
    except Exception as e:
        print(f"Error in get_risks: {e}")
        return jsonify({"success": False, "message": "خطأ في الخادم عند جلب المخاطر."}), 500

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

        # Generate risk_code
        last_risk = Risk.query.order_by(Risk.id.desc()).first()
        last_id = last_risk.id if last_risk else 0
        new_risk_code = f"RISK_{datetime.now().year}_{last_id + 1:04d}"

        new_risk = Risk(
            risk_code=new_risk_code,
            title=data.get('title'),
            description=data.get('description'),
            category=data.get('category'),
            owner=data.get('owner'),
            user_id=current_user.id,
            source=data.get('source'),
            risk_type=data.get('risk_type'),
            risk_location=data.get('risk_location'),
            risk_level=data.get('risk_level'),
            proactive_actions=data.get('proactive_actions'),
            immediate_actions=data.get('immediate_actions'),
            target_completion_date=data.get('target_completion_date'),
            action_effectiveness=data.get('action_effectiveness'),
            linked_risk_id=data.get('linked_risk_id'),
            status=data.get('status'),
            attachment_filename=filename,
            business_continuity_plan=data.get('business_continuity_plan'),
            lessons_learned=data.get('lessons_learned')
        )
        db.session.add(new_risk)
        db.session.commit()
        return jsonify({"success": True, "message": "تم إضافة الخطر بنجاح."})
    except Exception as e:
        db.session.rollback()
        print(f"Error creating risk: {e}")
        return jsonify({"success": False, "message": "خطأ في الخادم عند إضافة الخطر."}), 500

@app.route('/api/risks/<int:risk_id>', methods=['PUT'])
@login_required
def update_risk(risk_id):
    try:
        risk = Risk.query.get_or_404(risk_id)
        data = request.form.to_dict()
        file = request.files.get('attachment')

        # Update fields
        for key, value in data.items():
            if hasattr(risk, key):
                setattr(risk, key, value)
        
        # Handle attachment update
        if file and file.filename:
            # Delete old file if exists
            if risk.attachment_filename and os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], risk.attachment_filename)):
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], risk.attachment_filename))
            
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            risk.attachment_filename = filename
        
        risk.was_modified = True # Mark as modified
        db.session.commit()
        return jsonify({"success": True, "message": "تم تحديث الخطر بنجاح."})
    except Exception as e:
        db.session.rollback()
        print(f"Error updating risk: {e}")
        return jsonify({"success": False, "message": "خطأ في الخادم عند تحديث الخطر."}), 500

@app.route('/api/risks/<int:risk_id>', methods=['DELETE'])
@login_required
def delete_risk(risk_id):
    try:
        risk = Risk.query.get_or_404(risk_id)
        # For now, we'll just delete. In a real app, you might archive.
        db.session.delete(risk)
        db.session.commit()
        return jsonify({"success": True, "message": "تم حذف الخطر بنجاح."})
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting risk: {e}")
        return jsonify({"success": False, "message": "خطأ في الخادم عند حذف الخطر."}), 500

@app.route('/api/risks/<int:risk_id>/update_action', methods=['PUT'])
@login_required
def update_risk_action_field(risk_id):
    try:
        risk = Risk.query.get_or_404(risk_id)
        data = request.get_json()
        field = data.get('field')
        new_value = data.get('value')

        if field in ['proactive_actions', 'immediate_actions']:
            # Append new value as improvement
            current_text = getattr(risk, field) or ''
            # Check if it already contains an improvement part
            if "||IMPROVEMENT||" in current_text:
                parts = current_text.split("||IMPROVEMENT||")
                setattr(risk, field, f"{parts[0]}||IMPROVEMENT||{new_value}")
            else:
                setattr(risk, field, f"{current_text}||IMPROVEMENT||{new_value}")
            
            db.session.commit()
            return jsonify({'success': True, 'message': 'تم تحديث الحقل بنجاح', 'newValue': getattr(risk, field)})
        
        return jsonify({'success': False, 'message': 'الحقل غير صالح للتحديث.'}), 400
    except Exception as e:
        db.session.rollback()
        print(f"Error updating risk action field: {e}")
        return jsonify({'success': False, 'message': 'خطأ في الخادم عند تحديث الحقل.'}), 500

@app.route('/api/risks/<int:risk_id>/delete_attachment', methods=['DELETE'])
@login_required
def delete_risk_attachment(risk_id):
    try:
        risk = Risk.query.get_or_404(risk_id)
        if risk.attachment_filename:
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], risk.attachment_filename)
            if os.path.exists(filepath):
                os.remove(filepath)
            risk.attachment_filename = None
            db.session.commit()
            return jsonify({'success': True, 'message': 'تم حذف المرفق بنجاح.'})
        return jsonify({'success': False, 'message': 'لا يوجد مرفق لحذفه.'}), 404
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting risk attachment: {e}")
        return jsonify({'success': False, 'message': 'خطأ في الخادم عند حذف المرفق.'}), 500

# =============================================================================
# API Routes - Reports Management
# =============================================================================

# [إصلاح] دالة رفع التقارير المحدثة
@app.route('/api/reports/upload', methods=['POST'])
@login_required
def upload_report_file():
    if current_user.role.name not in ['Admin', 'Pioneer']:
        return jsonify({'success': False, 'message': 'غير مصرح لك بالرفع'}), 403
    
    if 'report_file' not in request.files:
        return jsonify({'success': False, 'message': 'لم يتم العثور على ملف'})
    
    file = request.files['report_file']
    report_type = request.form.get('report_type')

    if file.filename == '' or not report_type:
        return jsonify({'success': False, 'message': 'بيانات ناقصة'})

    try:
        # Use UUID to ensure unique filenames and prevent overwrites
        original_filename = secure_filename(file.filename)
        file_extension = os.path.splitext(original_filename)[1]
        unique_filename = str(uuid.uuid4()) + file_extension

        type_folder = os.path.join(app.config['REPORTS_UPLOAD_FOLDER'], report_type)
        os.makedirs(type_folder, exist_ok=True)
        filepath = os.path.join(type_folder, unique_filename)
        file.save(filepath)

        new_report = Report(
            filename=unique_filename, # Save unique filename to DB
            report_type=report_type,
            uploaded_by=current_user.id
        )
        db.session.add(new_report)
        db.session.commit()
        return jsonify({'success': True, 'message': 'تم رفع الملف بنجاح'})
    except Exception as e:
        db.session.rollback()
        print(f"Error uploading report: {e}")
        return jsonify({'success': False, 'message': 'حدث خطأ أثناء الحفظ.'}), 500

# [إصلاح] دالة جلب ملفات التقارير المحدثة
@app.route('/api/reports/files', methods=['GET'])
@login_required
def get_report_files():
    def file_to_dict(f):
        ksa_tz = pytz.timezone('Asia/Riyadh')
        modified_date_utc = pytz.utc.localize(f.upload_date)
        modified_date_ksa = modified_date_utc.astimezone(ksa_tz)
        return {
            'id': f.id, 
            'name': f.filename, # This is the unique filename stored
            'original_name': f.filename, # You might want to store original name too
            'type': f.report_type, 
            'modified_date': modified_date_ksa.isoformat()
        }

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
            return jsonify({
                'success': True, 
                'files': files_by_type, 
                'archived_files': [file_to_dict(f) for f in archived_files]
            })
        elif current_user.role.name == 'Pioneer':
            user_files = Report.query.filter_by(uploaded_by=current_user.id, is_archived=False).all()
            files_by_type = {
                'risk_champion': [file_to_dict(f) for f in user_files]
            }
            return jsonify({'success': True, 'files': files_by_type})
        else:
            return jsonify({'success': False, 'message': 'غير مصرح لك'}), 403
    except Exception as e:
        print(f"Error getting report files: {e}")
        return jsonify({'success': False, 'message': 'خطأ في الخادم'}), 500

@app.route('/api/reports/<int:report_id>/archive', methods=['POST'])
@login_required
def archive_report(report_id):
    if current_user.role.name != 'Admin':
        return jsonify({'success': False, 'message': 'غير مصرح لك'}), 403
    report = Report.query.get_or_404(report_id)
    report.is_archived = True
    db.session.commit()
    return jsonify({'success': True, 'message': 'تم أرشفة الملف بنجاح.'})

@app.route('/api/reports/<int:report_id>/restore', methods=['POST'])
@login_required
def restore_report(report_id):
    if current_user.role.name != 'Admin':
        return jsonify({'success': False, 'message': 'غير مصرح لك'}), 403
    report = Report.query.get_or_404(report_id)
    report.is_archived = False
    db.session.commit()
    return jsonify({'success': True, 'message': 'تم استعادة الملف بنجاح.'})

@app.route('/api/reports/<int:report_id>/delete', methods=['DELETE'])
@login_required
def delete_report(report_id):
    if current_user.role.name != 'Admin':
        return jsonify({'success': False, 'message': 'غير مصرح لك'}), 403
    report = Report.query.get_or_404(report_id)
    try:
        # Delete file from disk
        filepath = os.path.join(app.config['REPORTS_UPLOAD_FOLDER'], report.report_type, report.filename)
        if os.path.exists(filepath):
            os.remove(filepath)
        db.session.delete(report)
        db.session.commit()
        return jsonify({'success': True, 'message': 'تم حذف الملف نهائياً.'})
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting report file: {e}")
        return jsonify({'success': False, 'message': 'خطأ في الخادم عند حذف الملف.'}), 500

# Route to serve uploaded files
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
    with app.app_context():
        db.create_all()
        # Initial setup for roles and a default admin user if they don't exist
        if not Role.query.first():
            admin_role = Role(name='Admin')
            pioneer_role = Role(name='Pioneer')
            reporter_role = Role(name='Reporter')
            db.session.add_all([admin_role, pioneer_role, reporter_role])
            db.session.commit()

            # Create a default admin user
            if not User.query.filter_by(username='admin').first():
                admin_user = User(username='admin', full_name='مدير النظام', role=admin_role)
                admin_user.set_password('adminpass') # يجب تغيير هذا في بيئة الإنتاج
                db.session.add(admin_user)
                db.session.commit()
            
            # Create a default pioneer user
            if not User.query.filter_by(username='pioneer').first():
                pioneer_user = User(username='pioneer', full_name='رائد المخاطر', role=pioneer_role)
                pioneer_user.set_password('pioneerpass') # يجب تغيير هذا في بيئة الإنتاج
                db.session.add(pioneer_user)
                db.session.commit()

            # Create a default reporter user
            if not User.query.filter_by(username='reporter').first():
                reporter_user = User(username='reporter', full_name='المبلغ', role=reporter_role)
                reporter_user.set_password('reporterpass') # يجب تغيير هذا في بيئة الإنتاج
                db.session.add(reporter_user)
                db.session.commit()

        # Initial setup for status options if they don't exist
        if not StatusOption.query.first():
            status_options = ['جديد', 'تحت المراجعة', 'نشط', 'مُراقب', 'مُصعَّد', 'مغلق']
            for status_name in status_options:
                db.session.add(StatusOption(name=status_name))
            db.session.commit()

    app.run(debug=True, port=5001)

