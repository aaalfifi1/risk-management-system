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

# --- نماذج قاعدة البيانات (مع إعادة الأعمدة المحذوفة خطأً) ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    risks = db.relationship('Risk', backref='user', lazy=True)
    logs = db.relationship('AuditLog', backref='user', lazy=True)
    reports = db.relationship('Report', backref='uploaded_by', lazy=True)
    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

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
    
    # [إصلاح] إعادة الأعمدة التي حذفتها عن طريق الخطأ
    target_completion_date = db.Column(db.DateTime, nullable=True)
    
    action_effectiveness = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(50), default='جديد', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    residual_risk = db.Column(db.String(50), nullable=True)
    attachment_filename = db.Column(db.String(255), nullable=True)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    
    # [إصلاح] إعادة الأعمدة التي حذفتها عن طريق الخطأ
    business_continuity_plan = db.Column(db.Text, nullable=True)
    
    lessons_learned = db.Column(db.Text, nullable=True)
    was_modified = db.Column(db.Boolean, default=False, nullable=False)
    
    # [إصلاح] إعادة الأعمدة التي حذفتها عن طريق الخطأ
    linked_risk_id = db.Column(db.String(20), nullable=True)

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

# --- الدوال المساعدة (بدون تغيير) ---
def send_email(to_email, subject, html_content):
    # ... (الكود كما هو)
    pass

@login_manager.user_loader
def load_user(user_id): return User.query.get(int(user_id))

def calculate_risk_level(probability, impact):
    # ... (الكود كما هو)
    pass

def calculate_residual_risk(effectiveness):
    # ... (الكود كما هو)
    pass

# --- مسارات الصفحات الرئيسية (بدون تغيير) ---
@app.route('/')
@login_required
def home():
    # ... (الكود كما هو)
    pass

# ... (جميع مسارات الصفحات تبقى كما هي) ...

# --- [إصلاح] دالة تحميل سجل المخاطر مع الأعمدة الجديدة ---
@app.route('/download-risk-log')
@login_required
def download_risk_log():
    if current_user.username not in ['admin', 'testuser']: abort(403)
    output = io.StringIO()
    writer = csv.writer(output)
    headers = [
        'Risk Code', 'Title', 'Description', 'Category', 'Probability', 'Impact', 'Risk Level', 'Status', 
        'Owner', 'Risk Location', 'Proactive Actions', 'Immediate Actions', 'Target Completion Date', 
        'Action Effectiveness', 'Residual Risk', 'Linked Risk', 'Business Continuity Plan', 
        'Lessons Learned', 'Created At', 'Reporter'
    ]
    writer.writerow(headers)
    risks = Risk.query.filter_by(is_deleted=False).order_by(Risk.created_at.asc()).all()
    for risk in risks:
        reporter_username = risk.user.username if risk.user else 'N/A'
        completion_date = risk.target_completion_date.strftime('%Y-%m-%d') if risk.target_completion_date else ''
        writer.writerow([
            risk.risk_code or risk.id, risk.title, risk.description, risk.category, risk.probability, 
            risk.impact, risk.risk_level, risk.status, risk.owner, risk.risk_location, 
            risk.proactive_actions, risk.immediate_actions, completion_date, risk.action_effectiveness, 
            risk.residual_risk, risk.linked_risk_id, risk.business_continuity_plan, risk.lessons_learned, 
            risk.created_at.strftime('%Y-%m-%d %H:%M:%S'), reporter_username
        ])
    output.seek(0)
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=risk_log.csv"})

# --- [إصلاح] مسارات واجهة برمجة التطبيقات (API) مع الأعمدة الجديدة ---
@app.route('/api/risks', methods=['POST'])
@login_required
def add_risk():
    # ... (الكود الكامل الذي يدعم الأعمدة الجديدة، كما كان في النسخة المستقرة)
    pass

@app.route('/api/risks/<int:risk_id>', methods=['PUT'])
@login_required
def update_risk(risk_id):
    # ... (الكود الكامل الذي يدعم الأعمدة الجديدة، كما كان في النسخة المستقرة)
    pass

# --- [إصلاح] دالة جلب المخاطر مع الأعمدة الجديدة ---
@app.route('/api/risks', methods=['GET'])
@login_required
def get_risks():
    all_risk_codes = [r.risk_code for r in Risk.query.filter(Risk.risk_code.isnot(None), Risk.is_deleted==False).all()]
    query = Risk.query.filter_by(is_deleted=False)
    if current_user.username != 'admin': 
        query = query.filter_by(user_id=current_user.id)
    risks = query.order_by(Risk.created_at.desc()).all()
    risk_list = []
    for r in risks:
        risk_data = {
            'id': r.id, 'risk_code': r.risk_code, 'title': r.title, 'description': r.description, 
            'category': r.category, 'probability': r.probability, 'impact': r.impact, 
            'risk_level': r.risk_level, 'owner': r.owner, 'risk_location': r.risk_location, 
            'proactive_actions': r.proactive_actions, 'immediate_actions': r.immediate_actions, 
            'action_effectiveness': r.action_effectiveness, 'status': r.status, 
            'created_at': r.created_at.isoformat(), 'residual_risk': r.residual_risk, 
            'attachment_filename': r.attachment_filename, 'user_id': r.user_id, 
            'lessons_learned': r.lessons_learned, 'is_read': r.is_read, 'was_modified': r.was_modified,
            'target_completion_date': r.target_completion_date.strftime('%Y-%m-%d') if r.target_completion_date else None,
            'business_continuity_plan': r.business_continuity_plan,
            'linked_risk_id': r.linked_risk_id
        }
        risk_list.append(risk_data)
    return jsonify({'success': True, 'risks': risk_list, 'all_risk_codes': all_risk_codes})

# ... (بقية دوال الـ API تبقى كما هي) ...

# --- [إصلاح] دالة إحصائيات لوحة التحكم مع النسب المئوية ---
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
    
    active_percentage = (active / total * 100) if total > 0 else 0
    closed_percentage = (closed / total * 100) if total > 0 else 0
    
    by_category = {}
    for r in risks:
        if r.category: by_category[r.category] = by_category.get(r.category, 0) + 1
    by_level = {}
    for r in risks:
        if r.risk_level: by_level[r.risk_level] = by_level.get(r.risk_level, 0) + 1
        
    stats_data = {
        'total_risks': total, 
        'active_risks': active, 
        'closed_risks': closed,
        'active_risks_percentage': active_percentage,
        'closed_risks_percentage': closed_percentage,
        'by_category': by_category, 
        'by_level': by_level
    }
    return jsonify({'success': True, 'stats': stats_data})

# ... (بقية الكود من الإشعارات والتقارير وقسم التشغيل يبقى كما هو) ...
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
        
        report_type_arabic = {'quarterly': 'تقارير ربع سنوية', 'semi_annual': 'تقارير نصف سنوية', 'annual': 'تقارير سنوية', 'risk_champion': 'تقارير رائد المخاطر'}.get(report_type, report_type)
        log_details = f"رفع الملف '{filename}' إلى قسم '{report_type_arabic}'."
        log_entry = AuditLog(user_id=current_user.id, action='رفع تقرير', details=log_details, risk_id=None)
        db.session.add(log_entry)
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'تم رفع الملف بنجاح'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'حدث خطأ: {str(e)}'}), 500

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
    
    report_type_arabic = {'quarterly': 'تقارير ربع سنوية', 'semi_annual': 'تقارير نصف سنوية', 'annual': 'تقارير سنوية', 'risk_champion': 'تقارير رائد المخاطر'}.get(report.report_type, report.report_type)
    log_details = f"أرشفة الملف '{report.filename}' من قسم '{report_type_arabic}'."
    log_entry = AuditLog(user_id=current_user.id, action='أرشفة تقرير', details=log_details, risk_id=None)
    db.session.add(log_entry)
    
    db.session.commit()
    return jsonify({'success': True, 'message': 'تمت أرشفة الملف بنجاح'})

@app.route('/api/reports/<int:report_id>/restore', methods=['POST'])
@login_required
def restore_report(report_id):
    if current_user.username != 'admin': 
        return jsonify({'success': False, 'message': 'غير مصرح لك'}), 403
    report = Report.query.get_or_404(report_id)
    report.is_archived = False
    
    report_type_arabic = {'quarterly': 'تقارير ربع سنوية', 'semi_annual': 'تقارير نصف سنوية', 'annual': 'تقارير سنوية', 'risk_champion': 'تقارير رائد المخاطر'}.get(report.report_type, report.report_type)
    log_details = f"استعادة الملف '{report.filename}' إلى قسم '{report_type_arabic}'."
    log_entry = AuditLog(user_id=current_user.id, action='استعادة تقرير', details=log_details, risk_id=None)
    db.session.add(log_entry)
    
    db.session.commit()
    return jsonify({'success': True, 'message': 'تمت استعادة الملف بنجاح'})

@app.route('/api/reports/<int:report_id>/delete', methods=['DELETE'])
@login_required
def delete_report(report_id):
    if current_user.username != 'admin': 
        return jsonify({'success': False, 'message': 'غير مصرح لك بالحذف النهائي'}), 403
    report = Report.query.get_or_404(report_id)
    try:
        filename = report.filename
        report_type = report.report_type
        
        file_path = os.path.join(app.config['REPORTS_UPLOAD_FOLDER'], report.report_type, report.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        
        db.session.delete(report)
        
        report_type_arabic = {'quarterly': 'تقارير ربع سنوية', 'semi_annual': 'تقارير نصف سنوية', 'annual': 'تقارير سنوية', 'risk_champion': 'تقارير رائد المخاطر'}.get(report_type, report_type)
        log_details = f"حذف الملف '{filename}' نهائياً من قسم '{report_type_arabic}'."
        log_entry = AuditLog(user_id=current_user.id, action='حذف تقرير نهائي', details=log_details, risk_id=None)
        db.session.add(log_entry)
        
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
