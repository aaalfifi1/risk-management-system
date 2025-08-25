import os
import json
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, redirect, url_for, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from functools import wraps

# --- إعدادات التطبيق الأساسية ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'a_very_secret_key_that_should_be_changed'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///risk_management.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')
app.config['REPORTS_UPLOAD_FOLDER'] = os.path.join(app.root_path, 'reports_uploads')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "الرجاء تسجيل الدخول للوصول إلى هذه الصفحة."
login_manager.login_message_category = "info"

# --- نماذج قاعدة البيانات (مع الأدوار) ---
class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    users = db.relationship('User', backref='role', lazy=True)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role_id = db.Column(db.Integer, db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False))
    risks = db.relationship('Risk', backref='reporter_user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Risk(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    risk_code = db.Column(db.String(50), unique=True, nullable=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(100), nullable=True)
    risk_level = db.Column(db.String(50), nullable=True)
    owner = db.Column(db.String(100), nullable=True)
    status = db.Column(db.String(50), default='جديد')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    was_modified = db.Column(db.Boolean, default=False)
    probability = db.Column(db.Integer, nullable=True)
    impact = db.Column(db.Integer, nullable=True)
    risk_location = db.Column(db.String(200), nullable=True)
    proactive_actions = db.Column(db.Text, nullable=True)
    immediate_actions = db.Column(db.Text, nullable=True)
    target_completion_date = db.Column(db.String(20), nullable=True)
    action_effectiveness = db.Column(db.String(50), nullable=True)
    linked_risk_id = db.Column(db.String(50), nullable=True)
    business_continuity_plan = db.Column(db.Text, nullable=True)
    lessons_learned = db.Column(db.Text, nullable=True)
    attachment_filename = db.Column(db.String(255), nullable=True)
    risk_type = db.Column(db.String(50), default='تهديد')

class ReportFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    modified_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_archived = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --- دوال مساعدة ومزخرفات الصلاحيات ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def role_required(role_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role.name != role_name:
                return redirect(url_for('unauthorized'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def roles_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role.name not in roles:
                return redirect(url_for('unauthorized'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- طرق العرض (Routes) ---
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="اسم المستخدم أو كلمة المرور غير صحيحة")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/reports')
@login_required
@roles_required(['Admin', 'Pioneer'])
def reports():
    return render_template('reports.html')

@app.route('/unauthorized')
def unauthorized():
    return "<h1>ليس لديك الصلاحية للوصول لهذه الصفحة</h1>"

@app.context_processor
def inject_user_info():
    if current_user.is_authenticated:
        return dict(
            userRole=current_user.role.name,
            isAdmin=current_user.role.name == 'Admin',
            currentUserId=current_user.id
        )
    return dict(userRole='Guest', isAdmin=False, currentUserId=None)

# --- واجهات برمجة التطبيقات (APIs) ---

# API للمخاطر
@app.route('/api/risks', methods=['GET'])
@login_required
@roles_required(['Admin', 'Pioneer'])
def get_risks():
    risks_query = Risk.query.order_by(Risk.created_at.desc()).all()
    all_risk_codes = [r.risk_code for r in risks_query if r.risk_code]
    risks_data = [{
        'id': risk.id, 'risk_code': risk.risk_code, 'title': risk.title, 'description': risk.description,
        'category': risk.category, 'risk_level': risk.risk_level, 'owner': risk.owner, 'status': risk.status,
        'created_at': risk.created_at.isoformat(), 'user_id': risk.user_id, 'is_read': risk.is_read,
        'was_modified': risk.was_modified, 'probability': risk.probability, 'impact': risk.impact,
        'risk_location': risk.risk_location, 'proactive_actions': risk.proactive_actions,
        'immediate_actions': risk.immediate_actions, 'target_completion_date': risk.target_completion_date,
        'action_effectiveness': risk.action_effectiveness, 'linked_risk_id': risk.linked_risk_id,
        'business_continuity_plan': risk.business_continuity_plan, 'lessons_learned': risk.lessons_learned,
        'attachment_filename': risk.attachment_filename, 'risk_type': risk.risk_type
    } for risk in risks_query]
    return jsonify({'success': True, 'risks': risks_data, 'all_risk_codes': all_risk_codes})

@app.route('/api/risks', methods=['POST'])
@login_required
def add_risk():
    if current_user.role.name not in ['Admin', 'Pioneer', 'Reporter']:
        return jsonify({'success': False, 'message': 'ليس لديك الصلاحية لإضافة خطر'}), 403
    
    data = request.form
    new_risk = Risk(
        title=data.get('title', 'بلاغ جديد'),
        description=data.get('description'),
        category=data.get('category'),
        owner=data.get('owner'),
        risk_location=data.get('risk_location'),
        user_id=current_user.id,
        status='جديد',
        is_read=False,
        risk_type=data.get('risk_type', 'تهديد')
    )
    
    if current_user.role.name in ['Admin', 'Pioneer']:
        new_risk.probability = data.get('probability')
        new_risk.impact = data.get('impact')
        new_risk.proactive_actions = data.get('proactive_actions')
        new_risk.immediate_actions = data.get('immediate_actions')
        new_risk.target_completion_date = data.get('target_completion_date')
        new_risk.action_effectiveness = data.get('action_effectiveness')
        new_risk.linked_risk_id = data.get('linked_risk_id')
        new_risk.business_continuity_plan = data.get('business_continuity_plan')
        new_risk.lessons_learned = data.get('lessons_learned')
        
        # حساب مستوى الخطورة
        try:
            prob = int(data.get('probability', 0))
            imp = int(data.get('impact', 0))
            matrix_value = prob * imp
            if matrix_value >= 15: new_risk.risk_level = 'مرتفع جدا / كارثي'
            elif matrix_value >= 10: new_risk.risk_level = 'مرتفع'
            elif matrix_value >= 5: new_risk.risk_level = 'متوسط'
            elif matrix_value >= 3: new_risk.risk_level = 'منخفض'
            else: new_risk.risk_level = 'منخفض جدا'
        except (ValueError, TypeError):
            new_risk.risk_level = 'غير محدد'

    if 'attachment' in request.files:
        file = request.files['attachment']
        if file.filename != '':
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            new_risk.attachment_filename = filename

    db.session.add(new_risk)
    db.session.commit()

    # إنشاء كود الخطر بعد الحفظ للحصول على ID
    new_risk.risk_code = f"RSK_{datetime.now().year}_{new_risk.id:04d}"
    db.session.commit()

    return jsonify({'success': True, 'message': 'تمت إضافة الخطر بنجاح'})

@app.route('/api/risks/<int:risk_id>', methods=['PUT'])
@login_required
def update_risk(risk_id):
    risk = Risk.query.get_or_404(risk_id)
    if current_user.role.name != 'Admin' and risk.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'ليس لديك الصلاحية لتعديل هذا الخطر'}), 403
    
    data = request.form
    risk.title = data.get('title', risk.title)
    risk.description = data.get('description', risk.description)
    risk.category = data.get('category', risk.category)
    risk.owner = data.get('owner', risk.owner)
    risk.status = data.get('status', risk.status)
    risk.risk_location = data.get('risk_location', risk.risk_location)
    risk.proactive_actions = data.get('proactive_actions', risk.proactive_actions)
    risk.immediate_actions = data.get('immediate_actions', risk.immediate_actions)
    risk.target_completion_date = data.get('target_completion_date', risk.target_completion_date)
    risk.action_effectiveness = data.get('action_effectiveness', risk.action_effectiveness)
    risk.linked_risk_id = data.get('linked_risk_id', risk.linked_risk_id)
    risk.business_continuity_plan = data.get('business_continuity_plan', risk.business_continuity_plan)
    risk.lessons_learned = data.get('lessons_learned', risk.lessons_learned)
    risk.risk_type = data.get('risk_type', risk.risk_type)
    risk.was_modified = True

    try:
        risk.probability = int(data.get('probability', risk.probability))
        risk.impact = int(data.get('impact', risk.impact))
        matrix_value = risk.probability * risk.impact
        if matrix_value >= 15: risk.risk_level = 'مرتفع جدا / كارثي'
        elif matrix_value >= 10: risk.risk_level = 'مرتفع'
        elif matrix_value >= 5: risk.risk_level = 'متوسط'
        elif matrix_value >= 3: risk.risk_level = 'منخفض'
        else: risk.risk_level = 'منخفض جدا'
    except (ValueError, TypeError):
        pass

    if 'attachment' in request.files:
        file = request.files['attachment']
        if file.filename != '':
            if risk.attachment_filename:
                try: os.remove(os.path.join(app.config['UPLOAD_FOLDER'], risk.attachment_filename))
                except OSError: pass
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            risk.attachment_filename = filename

    db.session.commit()
    return jsonify({'success': True, 'message': 'تم تحديث الخطر بنجاح'})

@app.route('/api/risks/<int:risk_id>', methods=['DELETE'])
@login_required
@roles_required(['Admin', 'Pioneer'])
def archive_risk(risk_id):
    risk = Risk.query.get_or_404(risk_id)
    if current_user.role.name != 'Admin' and risk.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'ليس لديك الصلاحية لحذف هذا الخطر'}), 403
    
    # يمكنك هنا إضافة منطق الأرشفة بدلاً من الحذف الفعلي إذا أردت
    db.session.delete(risk)
    db.session.commit()
    return jsonify({'success': True, 'message': 'تم حذف (أرشفة) الخطر بنجاح'})

@app.route('/api/risks/<int:risk_id>/delete_attachment', methods=['DELETE'])
@login_required
def delete_attachment(risk_id):
    risk = Risk.query.get_or_404(risk_id)
    if current_user.role.name != 'Admin' and risk.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'ليس لديك الصلاحية لحذف المرفق'}), 403
    
    if risk.attachment_filename:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], risk.attachment_filename))
            risk.attachment_filename = None
            db.session.commit()
            return jsonify({'success': True, 'message': 'تم حذف المرفق بنجاح'})
        except OSError as e:
            return jsonify({'success': False, 'message': f'خطأ في حذف الملف: {e}'}), 500
    return jsonify({'success': False, 'message': 'لا يوجد مرفق لحذفه'}), 404

@app.route('/api/risks/<int:risk_id>/update_action', methods=['PUT'])
@login_required
@roles_required(['Admin', 'Pioneer'])
def update_action_field(risk_id):
    risk = Risk.query.get_or_404(risk_id)
    data = request.get_json()
    field_name = data.get('field')
    new_value = data.get('value')

    if field_name not in ['proactive_actions', 'immediate_actions']:
        return jsonify({'success': False, 'message': 'حقل غير صالح'}), 400

    original_value = getattr(risk, field_name, "").split("||IMPROVEMENT||")[0]
    updated_full_value = f"{original_value}||IMPROVEMENT||{new_value}"
    setattr(risk, field_name, updated_full_value)
    
    db.session.commit()
    return jsonify({'success': True, 'message': 'تم التحديث', 'newValue': updated_full_value})

# API للتقارير
@app.route('/api/reports/upload', methods=['POST'])
@login_required
@roles_required(['Admin', 'Pioneer'])
def upload_report():
    if 'report_file' not in request.files:
        return jsonify({'success': False, 'message': 'لم يتم إرسال أي ملف'}), 400
    file = request.files['report_file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'لم يتم اختيار أي ملف'}), 400
    
    report_type = request.form.get('report_type')
    if not report_type:
        return jsonify({'success': False, 'message': 'نوع التقرير مطلوب'}), 400

    # صلاحيات الرفع
    if report_type == 'risk_champion' and current_user.role.name != 'Pioneer':
        return jsonify({'success': False, 'message': 'ليس لديك الصلاحية لرفع هذا النوع من التقارير'}), 403
    if report_type != 'risk_champion' and current_user.role.name != 'Admin':
        return jsonify({'success': False, 'message': 'ليس لديك الصلاحية لرفع هذا النوع من التقارير'}), 403

    type_folder = os.path.join(app.config['REPORTS_UPLOAD_FOLDER'], report_type)
    os.makedirs(type_folder, exist_ok=True)
    
    filename = secure_filename(file.filename)
    file.save(os.path.join(type_folder, filename))
    
    new_report = ReportFile(name=filename, type=report_type, user_id=current_user.id)
    db.session.add(new_report)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'تم رفع الملف بنجاح'})

@app.route('/api/reports/files')
@login_required
@roles_required(['Admin', 'Pioneer'])
def get_report_files():
    files_by_type = {'quarterly': [], 'semi_annual': [], 'annual': [], 'risk_champion': []}
    archived_files = []

    if current_user.role.name == 'Admin':
        all_files = ReportFile.query.order_by(ReportFile.modified_date.desc()).all()
    else: # Pioneer
        all_files = ReportFile.query.filter_by(user_id=current_user.id).order_by(ReportFile.modified_date.desc()).all()

    for file in all_files:
        file_data = {'id': file.id, 'name': file.name, 'type': file.type, 'modified_date': file.modified_date.isoformat()}
        if file.is_archived:
            if current_user.role.name == 'Admin':
                archived_files.append(file_data)
        elif file.type in files_by_type:
            files_by_type[file.type].append(file_data)
            
    return jsonify({'success': True, 'files': files_by_type, 'archived_files': archived_files})

@app.route('/api/reports/<int:report_id>/archive', methods=['POST'])
@login_required
@roles_required(['Admin', 'Pioneer'])
def archive_report(report_id):
    report = ReportFile.query.get_or_404(report_id)
    if current_user.role.name != 'Admin' and report.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'ليس لديك الصلاحية'}), 403
    report.is_archived = True
    db.session.commit()
    return jsonify({'success': True, 'message': 'تمت أرشفة الملف'})

@app.route('/api/reports/<int:report_id>/restore', methods=['POST'])
@login_required
@role_required('Admin')
def restore_report(report_id):
    report = ReportFile.query.get_or_404(report_id)
    report.is_archived = False
    db.session.commit()
    return jsonify({'success': True, 'message': 'تمت استعادة الملف'})

@app.route('/api/reports/<int:report_id>/delete', methods=['DELETE'])
@login_required
@role_required('Admin')
def delete_report(report_id):
    report = ReportFile.query.get_or_404(report_id)
    try:
        file_path = os.path.join(app.config['REPORTS_UPLOAD_FOLDER'], report.type, report.name)
        if os.path.exists(file_path):
            os.remove(file_path)
        db.session.delete(report)
        db.session.commit()
        return jsonify({'success': True, 'message': 'تم حذف الملف نهائياً'})
    except Exception as e:
        return jsonify({'success': False, 'message': f'خطأ: {e}'}), 500

# طرق عرض لخدمة الملفات المرفوعة
@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/reports_uploads/<report_type>/<filename>')
@login_required
def uploaded_report_file(report_type, filename):
    return send_from_directory(os.path.join(app.config['REPORTS_UPLOAD_FOLDER'], report_type), filename)

# --- إعداد قاعدة البيانات والتشغيل ---
def setup_database(app):
    with app.app_context():
        db.create_all()
        # إنشاء الأدوار إذا لم تكن موجودة
        if not Role.query.filter_by(name='Admin').first():
            db.session.add(Role(name='Admin'))
        if not Role.query.filter_by(name='Pioneer').first():
            db.session.add(Role(name='Pioneer'))
        if not Role.query.filter_by(name='Reporter').first():
            db.session.add(Role(name='Reporter'))
        db.session.commit()

        # إنشاء المستخدمين الافتراضيين إذا لم يكونوا موجودين
        if not User.query.filter_by(username='admin').first():
            admin_role = Role.query.filter_by(name='Admin').first()
            admin_user = User(username='admin', role_id=admin_role.id)
            admin_user.set_password('123')
            db.session.add(admin_user)

        if not User.query.filter_by(username='pioneer').first():
            pioneer_role = Role.query.filter_by(name='Pioneer').first()
            pioneer_user = User(username='pioneer', role_id=pioneer_role.id)
            pioneer_user.set_password('123')
            db.session.add(pioneer_user)

        if not User.query.filter_by(username='reporter').first():
            reporter_role = Role.query.filter_by(name='Reporter').first()
            reporter_user = User(username='reporter', role_id=reporter_role.id)
            reporter_user.set_password('123')
            db.session.add(reporter_user)
        
        db.session.commit()
        
        # إنشاء مجلدات الرفع
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        os.makedirs(app.config['REPORTS_UPLOAD_FOLDER'], exist_ok=True)

if __name__ == '__main__':
    setup_database(app)
    app.run(debug=True, host='0.0.0.0', port=5001)
