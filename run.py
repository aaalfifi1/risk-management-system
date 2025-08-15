# --- المكتبات الأساسية ---
from flask import (Flask, render_template, request, jsonify, redirect, url_for, 
                   send_from_directory, abort, Response, session, flash)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import joinedload
from flask_login import (LoginManager, UserMixin, login_user, logout_user, 
                         login_required, current_user)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import csv
import io

# --- مكتبات إرسال البريد ---
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

# --- تهيئة التطبيق ---
app = Flask(__name__)

# --- إعدادات التطبيق ومتغيرات البيئة ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-default-fallback-secret-key-for-local-dev')
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['REPORTS_UPLOAD_FOLDER'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'reports_uploads')
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')

# --- تهيئة الإضافات ---
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'الرجاء تسجيل الدخول للوصول إلى هذه الصفحة.'
login_manager.login_message_category = 'info'

# --- نماذج قاعدة البيانات (Models) ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    risks = db.relationship('Risk', backref='user', lazy=True)
    logs = db.relationship('AuditLog', backref='user', lazy=True)
    reports = db.relationship('Report', backref='uploaded_by', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Risk(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    risk_code = db.Column(db.String(20), unique=True, nullable=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(100), nullable=False)
    probability = db.Column(db.Integer, nullable=False)
    impact = db.Column(db.Integer, nullable=False)
    risk_level = db.Column(db.String(50), nullable=False)
    owner = db.Column(db.String(100), nullable=True)
    risk_location = db.Column(db.String(100), nullable=True)
    proactive_actions = db.Column(db.Text, nullable=True)
    immediate_actions = db.Column(db.Text, nullable=True)
    action_effectiveness = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(50), default='جديد', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    residual_risk = db.Column(db.String(50), nullable=True)
    attachment_filename = db.Column(db.String(255), nullable=True)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    lessons_learned = db.Column(db.Text, nullable=True)
    was_modified = db.Column(db.Boolean, default=False, nullable=False)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    details = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    risk_id = db.Column(db.Integer, nullable=True)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    report_type = db.Column(db.String(50), nullable=False)
    uploaded_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    is_archived = db.Column(db.Boolean, default=False, nullable=False)

# --- الدوال المساعدة ---
def send_email(to_email, subject, html_content):
    api_key = os.environ.get('SENDGRID_API_KEY')
    sender_email = os.environ.get('SENDER_EMAIL')
    if not api_key or not sender_email:
        print("ERROR: Email environment variables not set. Email not sent.")
        return
    message = Mail(from_email=sender_email, to_emails=to_email, subject=subject, html_content=html_content)
    try:
        sg = SendGridAPIClient(api_key)
        response = sg.send(message)
        print(f"Email sent to {to_email}, Status Code: {response.status_code}")
    except Exception as e:
        print(f"Error sending email: {e}")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def calculate_risk_level(probability, impact):
    score = int(probability) * int(impact)
    if score >= 20: return 'مرتفع جدا / كارثي'
    if score >= 15: return 'مرتفع'
    if score >= 10: return 'متوسط'
    if score >= 5: return 'منخفض'
    return 'منخفض جدا'

def calculate_residual_risk(effectiveness):
    if effectiveness in ['ممتاز', 'جيد']: return 'لا يوجد'
    elif effectiveness in ['متوسط', 'ضعيف', 'غير مرضي']: return 'إجراءات إضافية'
    return ''

# --- مسارات الصفحات الرئيسية (Routes) ---
@app.route('/')
@login_required
def home():
    if current_user.username == 'reporter':
        return redirect(url_for('risk_register'))
    return redirect(url_for('stats'))

@app.route('/stats')
@login_required
def stats():
    if current_user.username == 'reporter':
        abort(403)
    return render_template('stats.html')

@app.route('/risk-register')
@login_required
def risk_register():
    return render_template('dashboard.html')

@app.route('/reports')
@login_required
def reports():
    if current_user.username not in ['admin', 'testuser']:
        abort(403)
    if current_user.username == 'admin':
        try:
            Report.query.filter_by(is_read=False).update({'is_read': True})
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Error marking reports as read: {e}")
    return render_template('reports.html')

@app.route('/audit_log')
@login_required
def audit_log():
    if current_user.username != 'admin':
        abort(403)
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('audit_log.html', logs=logs)

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/reports_uploads/<report_type>/<filename>')
@login_required
def uploaded_report_file(report_type, filename):
    report_path = os.path.join(app.config['REPORTS_UPLOAD_FOLDER'], report_type)
    return send_from_directory(report_path, filename)

# --- مسارات المصادقة (Authentication) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and user.check_password(request.form['password']):
            login_user(user)
            session['is_admin'] = (user.username == 'admin')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('home'))
        flash('فشل تسجيل الدخول. يرجى التحقق من اسم المستخدم وكلمة المرور.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('is_admin', None)
    logout_user()
    return redirect(url_for('login'))

# --- دالة تحميل سجل المخاطر ---
@app.route('/download-risk-log')
@login_required
def download_risk_log():
    if current_user.username not in ['admin', 'testuser']:
        abort(403)
    output = io.StringIO()
    writer = csv.writer(output)
    headers = ['Risk Code', 'Title', 'Description', 'Category', 'Probability', 'Impact', 'Risk Level', 'Status', 'Owner', 'Risk Location', 'Proactive Actions', 'Immediate Actions', 'Action Effectiveness', 'Residual Risk', 'Lessons Learned', 'Created At', 'Reporter']
    writer.writerow(headers)
    risks = Risk.query.filter_by(is_deleted=False).order_by(Risk.created_at.asc()).all()
    for risk in risks:
        reporter_username = risk.user.username if risk.user else 'N/A'
        writer.writerow([risk.risk_code or risk.id, risk.title, risk.description, risk.category, risk.probability, risk.impact, risk.risk_level, risk.status, risk.owner, risk.risk_location, risk.proactive_actions, risk.immediate_actions, risk.action_effectiveness, risk.residual_risk, risk.lessons_learned, risk.created_at.strftime('%Y-%m-%d %H:%M:%S'), reporter_username])
    output.seek(0)
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=risk_log.csv"})

# --- مسارات واجهة برمجة التطبيقات (API) ---
@app.route('/api/risks', methods=['POST'])
@login_required
def add_risk():
    try:
        data = request.form
        user_role = current_user.username
        is_read_status = (user_role == 'admin')
        if user_role == 'reporter':
            if not data.get('description') or not data.get('risk_location'):
                return jsonify({'success': False, 'message': 'وصف الخطر وموقعه حقول مطلوبة.'}), 400
            new_risk = Risk(title="", description=data['description'], category="", probability=1, impact=1, risk_level="", owner=data.get('owner', 'لم يتم توفيره'), risk_location=data['risk_location'], user_id=current_user.id, status='جديد', is_read=is_read_status)
        else:
            prob = int(data.get('probability', 1)); imp = int(data.get('impact', 1))
            effectiveness = data.get('action_effectiveness'); residual = calculate_residual_risk(effectiveness)
            new_risk = Risk(title=data['title'], description=data.get('description'), category=data['category'], probability=prob, impact=imp, risk_level=calculate_risk_level(prob, imp), owner=data.get('owner'), risk_location=data.get('risk_location'), proactive_actions=data.get('proactive_actions'), immediate_actions=data.get('immediate_actions'), action_effectiveness=effectiveness, user_id=current_user.id, status=data.get('status', 'نشط'), residual_risk=residual, is_read=is_read_status, lessons_learned=data.get('lessons_learned'))
        
        upload_folder = app.config['UPLOAD_FOLDER']
        if not os.path.exists(upload_folder): os.makedirs(upload_folder)
        if 'attachment' in request.files:
            file = request.files['attachment']
            if file and file.filename != '':
                filename = secure_filename(file.filename)
                file.save(os.path.join(upload_folder, filename))
                new_risk.attachment_filename = filename
        
        db.session.add(new_risk)
        db.session.flush()
        source_code = {'admin': 'ADM', 'testuser': 'RPN'}.get(user_role, 'REP')
        new_risk.risk_code = f"{source_code}_{new_risk.created_at.year}_{new_risk.id:04d}"
        log_entry = AuditLog(user_id=current_user.id, action='إضافة', details=f"إضافة خطر جديد بكود: '{new_risk.risk_code}'", risk_id=new_risk.id)
        db.session.add(log_entry)
        db.session.commit()

        if user_role != 'admin':
            admin_user = User.query.filter_by(username='admin').first()
            if admin_user and admin_user.email:
                subject = f"بلاغ خطر جديد: {new_risk.risk_code}"
                html_content = f"<div dir='rtl' style='font-family: Arial, sans-serif; text-align: right;'><h2>تنبيه بنشاط جديد في نظام إدارة المخاطر</h2><p>مرحباً يا مدير النظام،</p><p>تم تسجيل نشاط جديد من قبل المستخدم: <strong>{current_user.username}</strong></p><hr><h3>تفاصيل الخطر:</h3><ul><li><strong>كود الخطر:</strong> {new_risk.risk_code}</li><li><strong>الوصف:</strong> {new_risk.description}</li><li><strong>الموقع:</strong> {new_risk.risk_location}</li></ul><hr><p>الرجاء الدخول إلى النظام لمراجعة التفاصيل واتخاذ الإجراء اللازم.</p><p>شكراً لك.</p></div>"
                send_email(to_email=admin_user.email, subject=subject, html_content=html_content)

        message = 'تم إرسال بلاغك بنجاح. شكراً لك!' if user_role == 'reporter' else 'تمت إضافة الخطر بنجاح'
        return jsonify({'success': True, 'message': message}), 201
    except Exception as e:
        db.session.rollback()
        print(f"An error occurred in add_risk: {e}")
        return jsonify({'success': False, 'message': f'حدث خطأ غير متوقع: {str(e)}'}), 500

@app.route('/api/risks/<int:risk_id>', methods=['PUT'])
@login_required
def update_risk(risk_id):
    try:
        risk = Risk.query.get_or_404(risk_id)
        if current_user.username != 'admin' and risk.user_id != current_user.id:
            return jsonify({'success': False, 'message': 'غير مصرح لك بتعديل هذا الخطر'}), 403
        data = request.form
        was_modified_before = risk.was_modified
        risk.proactive_actions = data.get('proactive_actions', risk.proactive_actions)
        risk.immediate_actions = data.get('immediate_actions', risk.immediate_actions)
        prob = int(data.get('probability', risk.probability)); imp = int(data.get('impact', risk.impact))
        effectiveness = data.get('action_effectiveness', risk.action_effectiveness); residual = calculate_residual_risk(effectiveness)
        risk.title = data.get('title', risk.title); risk.description = data.get('description', risk.description); risk.category = data.get('category', risk.category); risk.probability = prob; risk.impact = imp; risk.risk_level = calculate_risk_level(prob, imp); risk.owner = data.get('owner', risk.owner); risk.risk_location = data.get('risk_location', risk.risk_location)
        risk.action_effectiveness = effectiveness; risk.status = data.get('status', risk.status); risk.residual_risk = residual; risk.lessons_learned = data.get('lessons_learned', risk.lessons_learned)
        if current_user.username != 'admin':
            risk.is_read = False
            risk.was_modified = True
        else:
            risk.is_read = True
        upload_folder = app.config['UPLOAD_FOLDER']
        if not os.path.exists(upload_folder): os.makedirs(upload_folder)
        if 'attachment' in request.files:
            file = request.files['attachment']
            if file.filename != '':
                filename = secure_filename(file.filename)
                file.save(os.path.join(upload_folder, filename))
                risk.attachment_filename = filename
        log_entry = AuditLog(user_id=current_user.id, action='تعديل', details=f"تعديل الخطر بكود: '{risk.risk_code}'", risk_id=risk.id)
        db.session.add(log_entry)
        db.session.commit()
        if current_user.username != 'admin' and not was_modified_before:
            admin_user = User.query.filter_by(username='admin').first()
            if admin_user and admin_user.email:
                subject = f"تحديث على الخطر: {risk.risk_code}"
                html_content = f"<div dir='rtl' style='font-family: Arial, sans-serif; text-align: right;'><h2>تنبيه بتحديث في نظام إدارة المخاطر</h2><p>مرحباً يا مدير النظام،</p><p>قام المستخدم <strong>{current_user.username}</strong> بتحديث الخطر ذو الكود: <strong>{risk.risk_code}</strong>.</p><hr><p>الرجاء الدخول إلى النظام لمراجعة التحديثات.</p><p>شكراً لك.</p></div>"
                send_email(to_email=admin_user.email, subject=subject, html_content=html_content)
        return jsonify({'success': True, 'message': 'تم تحديث الخطر بنجاح'})
    except Exception as e:
        db.session.rollback()
        print(f"An error occurred in update_risk: {e}")
        return jsonify({'success': False, 'message': f'حدث خطأ غير متوقع: {str(e)}'}), 500

@app.route('/api/reports/upload', methods=['POST'])
@login_required
def upload_report():
    if 'report_file' not in request.files: return jsonify({'success': False, 'message': 'لم يتم العثور على ملف'}), 400
    file = request.files['report_file']
    report_type = request.form.get('report_type')
    if file.filename == '' or not report_type: return jsonify({'success': False, 'message': 'بيانات الطلب ناقصة'}), 400
    try:
        filename = secure_filename(file.filename)
        report_type_path = os.path.join(app.config['REPORTS_UPLOAD_FOLDER'], report_type)
        if not os.path.exists(report_type_path): os.makedirs(report_type_path)
        file.save(os.path.join(report_type_path, filename))
        new_report = Report(filename=filename, report_type=report_type, uploaded_by_id=current_user.id, is_read=False)
        db.session.add(new_report)
        db.session.commit()
        return jsonify({'success': True, 'message': 'تم رفع الملف بنجاح'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'حدث خطأ: {str(e)}'}), 500

@app.route('/api/risks', methods=['GET'])
@login_required
def get_risks():
    query = Risk.query.filter_by(is_deleted=False)
    if current_user.username != 'admin':
        query = query.filter_by(user_id=current_user.id)
    risks = query.order_by(Risk.created_at.desc()).all()
    risk_list = [{'id': r.id, 'risk_code': r.risk_code, 'title': r.title, 'description': r.description, 'category': r.category, 'probability': r.probability, 'impact': r.impact, 'risk_level': r.risk_level, 'owner': r.owner, 'risk_location': r.risk_location, 'proactive_actions': r.proactive_actions, 'immediate_actions': r.immediate_actions, 'action_effectiveness': r.action_effectiveness, 'status': r.status, 'created_at': r.created_at.isoformat(), 'residual_risk': r.residual_risk, 'attachment_filename': r.attachment_filename, 'user_id': r.user_id, 'lessons_learned': r.lessons_learned, 'is_read': r.is_read, 'was_modified': r.was_modified} for r in risks]
    return jsonify({'success': True, 'risks': risk_list})

@app.route('/api/risks/<int:risk_id>', methods=['DELETE'])
@login_required
def delete_risk(risk_id):
    risk = Risk.query.get_or_404(risk_id)
    if current_user.username != 'admin' and risk.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'غير مصرح لك بحذف هذا الخطر'}), 403
    risk.is_deleted = True
    log_entry = AuditLog(user_id=current_user.id, action='حذف', details=f"حذف الخطر بكود: '{risk.risk_code}'", risk_id=risk.id)
    db.session.add(log_entry)
    db.session.commit()
    return jsonify({'success': True, 'message': 'تم حذف الخطر (أرشفته) بنجاح'})

@app.route('/api/risks/<int:risk_id>/restore', methods=['POST'])
@login_required
def restore_risk(risk_id):
    if current_user.username != 'admin':
        return jsonify({'success': False, 'message': 'غير مصرح لك'}), 403
    risk = Risk.query.filter_by(id=risk_id, is_deleted=True).first_or_404()
    risk.is_deleted = False
    log_to_delete = AuditLog.query.filter_by(risk_id=risk_id, action='حذف').first()
    if log_to_delete:
        db.session.delete(log_to_delete)
    restore_log = AuditLog(user_id=current_user.id, action='استعادة', details=f"استعادة الخطر بكود: '{risk.risk_code}'", risk_id=risk.id)
    db.session.add(restore_log)
    db.session.commit()
    return jsonify({'success': True, 'message': 'تمت استعادة الخطر بنجاح'})

@app.route('/api/risks/<int:risk_id>/permanent', methods=['DELETE'])
@login_required
def permanent_delete_risk(risk_id):
    if current_user.username != 'admin':
        return jsonify({'success': False, 'message': 'غير مصرح لك بالحذف النهائي'}), 403
    risk = Risk.query.get_or_404(risk_id)
    AuditLog.query.filter_by(risk_id=risk_id).delete()
    if risk.attachment_filename:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], risk.attachment_filename)
        if os.path.exists(file_path):
            os.remove(file_path)
    db.session.delete(risk)
    db.session.commit()
    return jsonify({'success': True, 'message': 'تم حذف الخطر نهائياً من النظام.'})

@app.route('/api/risks/<int:risk_id>/delete_attachment', methods=['DELETE'])
@login_required
def delete_attachment(risk_id):
    risk = Risk.query.get_or_404(risk_id)
    if current_user.username != 'admin' and risk.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'غير مصرح لك'}), 403
    if risk.attachment_filename:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], risk.attachment_filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        risk.attachment_filename = None
        log_entry = AuditLog(user_id=current_user.id, action='تعديل', details=f"حذف مرفق من الخطر بكود: '{risk.risk_code}'", risk_id=risk.id)
        db.session.add(log_entry)
        db.session.commit()
        return jsonify({'success': True, 'message': 'تم حذف المرفق بنجاح'})
    return jsonify({'success': False, 'message': 'لا يوجد مرفق لحذفه'}), 404

@app.route('/api/stats', methods=['GET'])
@login_required
def get_stats_api():
    query = Risk.query.filter_by(is_deleted=False)
    if current_user.username != 'admin':
        query = query.filter_by(user_id=current_user.id)
    risks = query.all()
    total = len(risks)
    active = len([r for r in risks if r.status != 'مغلق'])
    closed = total - active
    by_category = {}
    for r in risks:
        if r.category: by_category[r.category] = by_category.get(r.category, 0) + 1
    by_level = {}
    for r in risks:
        if r.risk_level: by_level[r.risk_level] = by_level.get(r.risk_level, 0) + 1
    stats_data = {'total_risks': total, 'active_risks': active, 'closed_risks': closed, 'by_category': by_category, 'by_level': by_level}
    return jsonify({'success': True, 'stats': stats_data})

@app.route('/api/notifications')
@login_required
def get_notifications():
    if current_user.username != 'admin':
        return jsonify({'success': True, 'notifications': [], 'count': 0})
    unread_risks = Risk.query.options(joinedload(Risk.user)).filter_by(is_read=False, is_deleted=False).order_by(Risk.created_at.desc()).all()
    notifications = []
    for r in unread_risks:
        title = r.title or 'بلاغ جديد'
        if r.was_modified: title = f"(تعديل) {title}"
        notifications.append({'id': r.id, 'title': title, 'user': r.user.username, 'timestamp': r.created_at.isoformat()})
    return jsonify({'success': True, 'notifications': notifications, 'count': len(unread_risks)})

@app.route('/api/notifications/mark-as-read', methods=['POST'])
@login_required
def mark_as_read():
    if current_user.username != 'admin': abort(403)
    data = request.get_json()
    risk_id = data.get('risk_id')
    try:
        if risk_id:
            risk = Risk.query.get(risk_id)
            if risk: risk.is_read = True
        else:
            Risk.query.filter_by(is_read=False, is_deleted=False).update({'is_read': True})
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        print(f"Error in mark_as_read: {e}")
        return jsonify({'success': False, 'message': 'An error occurred'}), 500

@app.route('/api/reports/files', methods=['GET'])
@login_required
def get_report_files():
    query = Report.query
    if current_user.username == 'testuser':
        query = query.filter_by(uploaded_by_id=current_user.id)
    all_reports = query.order_by(Report.uploaded_at.desc()).all()
    files_by_type = {'quarterly': [], 'semi_annual': [], 'annual': [], 'risk_champion': []}
    archived_files = []
    for report in all_reports:
        file_data = {'id': report.id, 'name': report.filename, 'type': report.report_type, 'modified_date': report.uploaded_at.strftime('%Y-%m-%d %H:%M')}
        if report.is_archived:
            if current_user.username == 'admin': archived_files.append(file_data)
        else:
            if report.report_type in files_by_type: files_by_type[report.report_type].append(file_data)
    return jsonify({'success': True, 'files': files_by_type, 'archived_files': archived_files})

@app.route('/api/reports/<int:report_id>/archive', methods=['POST'])
@login_required
def archive_report(report_id):
    report = Report.query.get_or_404(report_id)
    if current_user.username != 'admin' and report.uploaded_by_id != current_user.id:
        return jsonify({'success': False, 'message': 'غير مصرح لك'}), 403
    report.is_archived = True
    db.session.commit()
    return jsonify({'success': True, 'message': 'تمت أرشفة الملف بنجاح'})

@app.route('/api/reports/<int:report_id>/restore', methods=['POST'])
@login_required
def restore_report(report_id):
    if current_user.username != 'admin': 
        return jsonify({'success': False, 'message': 'غير مصرح لك'}), 403
    report = Report.query.get_or_404(report_id)
    report.is_archived = False
    db.session.commit()
       
    return jsonify({'success': True, 'message': 'تمت استعادة الملف بنجاح'})

@app.route('/api/reports/<int:report_id>/delete', methods=['DELETE'])
@login_required
def delete_report(report_id):
    if current_user.username != 'admin': 
        return jsonify({'success': False, 'message': 'غير مصرح لك بالحذف النهائي'}), 403
    report = Report.query.get_or_404(report_id)
    try:
        file_path = os.path.join(app.config['REPORTS_UPLOAD_FOLDER'], report.report_type, report.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        db.session.delete(report)
        db.session.commit()
        return jsonify({'success': True, 'message': 'تم حذف الملف نهائياً'})
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting report file: {e}")
        return jsonify({'success': False, 'message': f'خطأ أثناء حذف الملف: {e}'}), 500

@app.route('/api/reports/unread_status', methods=['GET'])
@login_required
def get_unread_reports_status():
    if current_user.username != 'admin':
        return jsonify({'has_unread': False})
    unread_count = Report.query.filter_by(is_read=False, is_archived=False).count()
    return jsonify({'has_unread': unread_count > 0})

# --- قسم التشغيل (للبيئة المحلية فقط) ---
if __name__ == '__main__':
    app.run(debug=True, port=5001)
