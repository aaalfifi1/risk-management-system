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

# --- تهيئة التطبيق ---
app = Flask(__name__)

# --- إعدادات التطبيق ومتغيرات البيئة ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'a-default-fallback-secret-key-for-local-dev')
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL or 'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'risk_management.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['REPORTS_UPLOAD_FOLDER'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'reports_uploads')
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'uploads')

# --- تهيئة الإضافات ---
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'الرجاء تسجيل الدخول للوصول إلى هذه الصفحة.'
login_manager.login_message_category = 'info'

# --- نماذج قاعدة البيانات (لا تغيير هنا) ---
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
    risk_type = db.Column(db.String(20), default='تهديد', nullable=False)
    category = db.Column(db.String(100), nullable=False)
    probability = db.Column(db.Integer, nullable=False)
    impact = db.Column(db.Integer, nullable=False)
    risk_level = db.Column(db.String(50), nullable=False)
    owner = db.Column(db.String(100), nullable=True)
    risk_location = db.Column(db.String(100), nullable=True)
    proactive_actions = db.Column(db.Text, nullable=True)
    immediate_actions = db.Column(db.Text, nullable=True)
    target_completion_date = db.Column(db.DateTime, nullable=True)
    action_effectiveness = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(50), default='جديد', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    residual_risk = db.Column(db.String(50), nullable=True)
    attachment_filename = db.Column(db.String(255), nullable=True)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    business_continuity_plan = db.Column(db.Text, nullable=True)
    lessons_learned = db.Column(db.Text, nullable=True)
    was_modified = db.Column(db.Boolean, default=False, nullable=False)
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

# --- دوال مساعدة (لا تغيير هنا) ---
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
def load_user(user_id): return User.query.get(int(user_id))

def calculate_risk_level(probability, impact):
    score = int(probability) * int(impact)
    if score >= 20: return 'مرتفع جدا / كارثي'
    if score >= 15: return 'مرتفع'
    if score >= 10: return 'متوسط'
    if score >= 5: return 'منخفض'
    return 'منخفض جدا'

# --- مسارات الصفحات (لا تغيير هنا) ---
@app.route('/')
@login_required
def home():
    if current_user.username == 'reporter': return redirect(url_for('risk_register'))
    return redirect(url_for('stats'))

@app.route('/stats')
@login_required
def stats():
    if current_user.username == 'reporter': abort(403)
    return render_template('stats.html')

# ... (باقي المسارات تبقى كما هي بدون تغيير) ...
# --- [بداية الإصلاح] دالة get_stats_api المصححة بالكامل ---
@app.route('/api/stats', methods=['GET'])
@login_required
def get_stats_api():
    # الخطوة 1: جلب كل البيانات الأساسية التي لا تتأثر بالفلترة
    base_query = Risk.query.filter_by(is_deleted=False)
    if current_user.username != 'admin': 
        base_query = base_query.filter_by(user_id=current_user.id)
    
    all_risks = base_query.all()

    # الخطوة 2: حساب مؤشرات الأداء الرئيسية (KPIs) من البيانات الكاملة
    today = datetime.utcnow().date()
    kpi_active_risks = [r for r in all_risks if r.status != 'مغلق']
    
    avg_risk_age = 0
    if kpi_active_risks:
        total_age = sum([(today - r.created_at.date()).days for r in kpi_active_risks])
        avg_risk_age = round(total_age / len(kpi_active_risks)) if len(kpi_active_risks) > 0 else 0

    first_day_of_month = today.replace(day=1)
    closed_this_month_count = len([r for r in all_risks if r.status == 'مغلق' and r.created_at.date() >= first_day_of_month])
    opened_this_month_count = len([r for r in all_risks if r.created_at.date() >= first_day_of_month])
    closure_rate_this_month = round((closed_this_month_count / opened_this_month_count) * 100) if opened_this_month_count > 0 else 0

    category_scores = {}
    for r in kpi_active_risks:
        score = r.probability * r.impact
        category_scores[r.category] = category_scores.get(r.category, 0) + score
    most_dangerous_category = max(category_scores, key=category_scores.get) if category_scores else "لا يوجد"

    linked_risks_count = len([r for r in all_risks if r.linked_risk_id is not None and r.linked_risk_id != 'لا يوجد'])

    # الخطوة 3: تطبيق الفلاتر على البيانات
    filtered_risks = all_risks
    filter_category = request.args.get('category')
    filter_level = request.args.get('level')
    filter_type = request.args.get('type')
    filter_status = request.args.get('status')
    filter_code = request.args.get('code')

    if filter_category:
        filtered_risks = [r for r in filtered_risks if r.category == filter_category]
    if filter_level:
        filtered_risks = [r for r in filtered_risks if r.risk_level == filter_level]
    if filter_type:
        filtered_risks = [r for r in filtered_risks if r.risk_type == filter_type]
    if filter_status:
        filtered_risks = [r for r in filtered_risks if r.status == filter_status]
    if filter_code:
        filtered_risks = [r for r in filtered_risks if r.risk_code == filter_code]

    # الخطوة 4: حساب الإحصائيات العادية بناءً على البيانات المفلترة
    total = len(filtered_risks)
    active = len([r for r in filtered_risks if r.status != 'مغلق'])
    threats = len([r for r in filtered_risks if r.risk_type == 'تهديد'])
    
    total_unfiltered = len(all_risks)
    threats_percentage = (threats / total_unfiltered * 100) if total_unfiltered > 0 else 0
    opportunities_percentage = ((total - threats) / total_unfiltered * 100) if total_unfiltered > 0 else 0
    active_percentage = (active / total_unfiltered * 100) if total_unfiltered > 0 else 0
    closed_percentage = ((total - active) / total_unfiltered * 100) if total_unfiltered > 0 else 0
    
    matrix_data = [{'x': r.probability, 'y': r.impact, 'type': r.risk_type, 'title': r.title, 'code': r.risk_code} for r in filtered_risks]
    
    risk_level_order = ['مرتفع جدا / كارثي', 'مرتفع', 'متوسط', 'منخفض', 'منخفض جدا']
    categories = sorted(list(set(r.category for r in all_risks if r.category)))
    by_category_stacked = {level: [0] * len(categories) for level in risk_level_order}
    for risk in filtered_risks:
        if risk.category in categories:
            cat_index = categories.index(risk.category)
            if risk.risk_level in by_category_stacked:
                by_category_stacked[risk.risk_level][cat_index] += 1

    by_level_nested = { 'labels': risk_level_order, 'datasets': { 'threats': [0] * len(risk_level_order), 'opportunities': [0] * len(risk_level_order) } }
    for risk in filtered_risks:
        if risk.risk_level in risk_level_order:
            level_index = risk_level_order.index(risk.risk_level)
            if risk.risk_type == 'تهديد': by_level_nested['datasets']['threats'][level_index] += 1
            else: by_level_nested['datasets']['opportunities'][level_index] += 1

    status_counts = Counter(r.status for r in filtered_risks)

    overdue_risks_count, on_time_risks_count = 0, 0
    active_risks_for_timeliness = [r for r in filtered_risks if r.status != 'مغلق']
    for risk in active_risks_for_timeliness:
        if risk.target_completion_date and risk.target_completion_date.date() < today:
            overdue_risks_count += 1
        else:
            on_time_risks_count += 1

    # الخطوة 5: تجميع كل البيانات في قاموس واحد لإرسالها
    stats_data = {
        'total_risks': total, 'active_risks': active, 'closed_risks': total - active,
        'active_risks_percentage': active_percentage, 'closed_risks_percentage': closed_percentage,
        'total_threats': threats, 'total_opportunities': total - threats,
        'threats_percentage': threats_percentage, 'opportunities_percentage': opportunities_percentage,
        'matrix_data': matrix_data,
        'by_category_stacked': { 'labels': categories, 'datasets': by_category_stacked },
        'by_level_nested': by_level_nested,
        'by_status': { 'labels': list(status_counts.keys()), 'data': list(status_counts.values()) },
        'timeliness': { 'labels': ['ملتزم بالوقت', 'متأخر'], 'data': [on_time_risks_count, overdue_risks_count] },
        'top_risks': [
            { 'code': r.risk_code, 'title': r.title, 'level': r.risk_level }
            for r in sorted(
                [risk for risk in all_risks if risk.status != 'مغلق' and risk.risk_level in ['مرتفع', 'مرتفع جدا / كارثي']], 
                key=lambda x: (x.probability * x.impact, x.created_at), 
                reverse=True
            )
        ][:5],
        # هذا هو الإصلاح الجذري: إضافة قاموس المؤشرات إلى البيانات المرسلة
        'kpi_data': {
            'avg_risk_age': avg_risk_age,
            'closure_rate_this_month': closure_rate_this_month,
            'most_dangerous_category': most_dangerous_category,
            'linked_risks_count': linked_risks_count
        }
    }
    
    return jsonify({'success': True, 'stats': stats_data})
# --- [نهاية الإصلاح] ---

# ... (باقي الملف يبقى كما هو بدون أي تغيير) ...


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
    return jsonify({'success': True,'notifications': notifications, 'count': len(unread_risks)})

@app.route('/api/notifications/mark-as-read', methods=['POST'])
@login_required
def mark_as_read():
    if current_user.username != 'admin': abort(403)
    data = request.get_json()
    risk_id = data.get('risk_id')
    try:
        if risk_id:
            risk = Risk.query.get(risk_id)
            if risk:
                risk.is_read = True
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
    with app.app_context():
        db.create_all() 
        
        users_to_create = {
            'admin': ('Admin@2025', 'twag1212@gmail.com'),
            'testuser': ('Test@1234', 'testuser@example.com'),
            'reporter': ('Reporter@123', 'reporter@example.com')
        }
        for username, (password, email) in users_to_create.items():
            user = User.query.filter_by(username=username).first()
            if not user:
                new_user = User(username=username, email=email)
                new_user.set_password(password)
                db.session.add(new_user)
        db.session.commit()
        
    app.run(debug=True, port=5001)








