# --- المكتبات الأساسية ---
from flask import (Flask, render_template, request, jsonify, redirect, url_for, 
                   send_from_directory, abort, Response, session, flash)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import joinedload
from flask_login import (LoginManager, UserMixin, login_user, logout_user, 
                         login_required, current_user)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta # <-- إضافة timedelta
import os
import csv
import io
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

# --- نماذج قاعدة البيانات ---
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
    
    # --- العمود الجديد 1: تاريخ إكمال الإجراءات ---
    target_completion_date = db.Column(db.DateTime, nullable=True)
    
    action_effectiveness = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(50), default='جديد', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    residual_risk = db.Column(db.String(50), nullable=True)
    attachment_filename = db.Column(db.String(255), nullable=True)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    
    # --- العمود الجديد 2: خطة استعادة العمل ---
    business_continuity_plan = db.Column(db.Text, nullable=True)
    
    lessons_learned = db.Column(db.Text, nullable=True)
    was_modified = db.Column(db.Boolean, default=False, nullable=False)
    
    # --- العمود الجديد 3: ارتباط الخطر ---
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

# --- دوال مساعدة ---
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

# --- مسارات الصفحات الرئيسية ---
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
    logs = AuditLog.query.options(joinedload(AuditLog.user)).order_by(AuditLog.timestamp.desc()).all()
    return render_template('audit_log.html', logs=logs)

# --- مسارات الملفات والمصادقة ---
@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/reports_uploads/<filename>')
@login_required
def uploaded_report_file(filename):
    return send_from_directory(app.config['REPORTS_UPLOAD_FOLDER'], filename)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('اسم المستخدم أو كلمة المرور غير صحيحة', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- واجهة برمجة التطبيقات (API) ---
@app.route('/api/risks', methods=['GET'])
@login_required
def get_risks():
    query = Risk.query.filter_by(is_deleted=False).order_by(Risk.created_at.desc())
    risks = query.all()
    
    all_risk_codes = [r.risk_code for r in Risk.query.filter(Risk.risk_code.isnot(None), Risk.is_deleted==False).all()]

    status_options = ['جديد', 'تحت المراجعة', 'تحت التنفيذ', 'مغلق', 'مرفوض']
    if current_user.username == 'admin':
        status_options.append('مؤرشف')

    risks_data = [{
        'id': risk.id,
        'risk_code': risk.risk_code,
        'title': risk.title,
        'description': risk.description,
        'category': risk.category,
        'probability': risk.probability,
        'impact': risk.impact,
        'risk_level': risk.risk_level,
        'owner': risk.owner,
        'risk_location': risk.risk_location,
        'proactive_actions': risk.proactive_actions,
        'immediate_actions': risk.immediate_actions,
        'action_effectiveness': risk.action_effectiveness,
        'status': risk.status,
        'created_at': risk.created_at.isoformat(),
        'user_id': risk.user_id,
        'residual_risk': risk.residual_risk,
        'attachment_filename': risk.attachment_filename,
        'is_read': risk.is_read,
        'was_modified': risk.was_modified,
        'lessons_learned': risk.lessons_learned,
        'target_completion_date': risk.target_completion_date.strftime('%Y-%m-%d') if risk.target_completion_date else None,
        'business_continuity_plan': risk.business_continuity_plan,
        'linked_risk_id': risk.linked_risk_id
    } for risk in risks]
    
    return jsonify({
        'success': True, 
        'risks': risks_data, 
        'status_options': status_options,
        'all_risk_codes': all_risk_codes
    })

@app.route('/api/risks', methods=['POST'])
@login_required
def add_risk():
    data = request.form
    
    target_date_str = data.get('target_completion_date')
    target_date = datetime.strptime(target_date_str, '%Y-%m-%d') if target_date_str else None
    linked_risk = data.get('linked_risk_id') if data.get('linked_risk_id') != 'لا يوجد' else None

    new_risk = Risk(
        title=data['title'],
        description=data.get('description'),
        category=data.get('category', 'غير محدد'),
        probability=data.get('probability', 1),
        impact=data.get('impact', 1),
        risk_level=calculate_risk_level(data.get('probability', 1), data.get('impact', 1)),
        owner=data.get('owner'),
        risk_location=data.get('risk_location'),
        proactive_actions=data.get('proactive_actions'),
        immediate_actions=data.get('immediate_actions'),
        status='جديد',
        user_id=current_user.id,
        is_read=False,
        target_completion_date=target_date,
        business_continuity_plan=data.get('business_continuity_plan'),
        linked_risk_id=linked_risk
    )

    if 'attachment' in request.files:
        file = request.files['attachment']
        if file.filename != '':
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            new_risk.attachment_filename = filename

    db.session.add(new_risk)
    db.session.commit()

    if current_user.username != 'reporter':
        category_prefix = new_risk.category[:3].upper()
        year = datetime.utcnow().year
        new_risk.risk_code = f"{category_prefix}_{year}_{new_risk.id:04d}"
    
    log = AuditLog(user_id=current_user.id, action='إضافة', details=f"إضافة خطر جديد بعنوان: {new_risk.title}", risk_id=new_risk.id)
    db.session.add(log)
    db.session.commit()

    admin_user = User.query.filter_by(username='admin').first()
    if admin_user and admin_user.email:
        email_subject = f"بلاغ خطر جديد: {new_risk.title}"
        email_body = f"""
        <p dir="rtl">مرحباً،</p>
        <p dir="rtl">تم تسجيل بلاغ خطر جديد في النظام.</p>
        <ul dir="rtl">
            <li><strong>العنوان:</strong> {new_risk.title}</li>
            <li><strong>المُبلغ:</strong> {current_user.username}</li>
            <li><strong>التاريخ:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M')}</li>
        </ul>
        <p dir="rtl">الرجاء مراجعة البلاغ في لوحة التحكم.</p>
        """
        send_email(admin_user.email, email_subject, email_body)

    return jsonify({'message': 'تم إضافة الخطر بنجاح!', 'risk_id': new_risk.id}), 201

@app.route('/api/risks/<int:risk_id>', methods=['PUT'])
@login_required
def update_risk(risk_id):
    risk = Risk.query.get_or_404(risk_id)
    data = request.form

    target_date_str = data.get('target_completion_date')
    risk.target_completion_date = datetime.strptime(target_date_str, '%Y-%m-%d') if target_date_str else None
    risk.business_continuity_plan = data.get('business_continuity_plan')
    linked_risk = data.get('linked_risk_id')
    risk.linked_risk_id = linked_risk if linked_risk and linked_risk != 'لا يوجد' else None

    risk.title = data['title']
    risk.description = data.get('description')
    risk.category = data['category']
    risk.probability = data['probability']
    risk.impact = data['impact']
    risk.risk_level = calculate_risk_level(risk.probability, risk.impact)
    risk.owner = data.get('owner')
    risk.risk_location = data.get('risk_location')
    risk.proactive_actions = data.get('proactive_actions')
    risk.immediate_actions = data.get('immediate_actions')
    risk.action_effectiveness = data.get('action_effectiveness')
    risk.status = data.get('status', risk.status)
    risk.lessons_learned = data.get('lessons_learned')
    risk.residual_risk = calculate_residual_risk(risk.action_effectiveness)
    risk.was_modified = True

    if 'attachment' in request.files:
        file = request.files['attachment']
        if file.filename != '':
            if risk.attachment_filename:
                try: os.remove(os.path.join(app.config['UPLOAD_FOLDER'], risk.attachment_filename))
                except OSError: pass
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            risk.attachment_filename = filename

    log = AuditLog(user_id=current_user.id, action='تعديل', details=f"تعديل بيانات الخطر: {risk.risk_code or risk.title}", risk_id=risk.id)
    db.session.add(log)
    db.session.commit()
    return jsonify({'message': 'تم تحديث الخطر بنجاح!'})

@app.route('/api/risks/<int:risk_id>', methods=['DELETE'])
@login_required
def delete_risk(risk_id):
    if current_user.username != 'admin': abort(403)
    risk = Risk.query.get_or_404(risk_id)
    risk.is_deleted = True
    log = AuditLog(user_id=current_user.id, action='حذف', details=f"حذف (أرشفة) الخطر: {risk.risk_code or risk.title}", risk_id=risk.id)
    db.session.add(log)
    db.session.commit()
    return jsonify({'success': True, 'message': 'تم حذف الخطر (أرشفته) بنجاح.'})

@app.route('/api/risks/<int:risk_id>/delete_attachment', methods=['DELETE'])
@login_required
def delete_attachment(risk_id):
    risk = Risk.query.get_or_404(risk_id)
    if risk.attachment_filename:
        try:
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], risk.attachment_filename))
            risk.attachment_filename = None
            db.session.commit()
            return jsonify({'success': True, 'message': 'تم حذف المرفق بنجاح.'})
        except OSError as e:
            return jsonify({'success': False, 'message': f'خطأ في حذف الملف: {e}'}), 500
    return jsonify({'success': False, 'message': 'لا يوجد مرفق لحذفه.'}), 404

@app.route('/download_risk_log')
@login_required
def download_risk_log():
    if current_user.username not in ['admin', 'testuser']: abort(403)
    
    risks = Risk.query.filter_by(is_deleted=False).order_by(Risk.created_at.desc()).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    headers = [
        'كود الخطر', 'عنوان الخطر', 'وصف الخطر', 'فئة الخطر', 'الاحتمالية', 'التأثير', 
        'مستوى الخطر', 'مالك الخطر', 'موقع الخطر', 'الإجراءات الإستباقية', 'الإجراءات الفورية',
        'تاريخ إكمال الإجراءات', 'فعالية الإجراءات', 'الحالة', 'تاريخ الإنشاء', 'الخطر المتبقي',
        'ارتباط الخطر', 'خطة استعادة العمل', 'الدروس المستفادة'
    ]
    writer.writerow(headers)
    
    for risk in risks:
        # --- [تعديل التوقيت] تحويل الوقت إلى توقيت السعودية (UTC+3) ---
        created_at_ksa = risk.created_at + timedelta(hours=3)

        row = [
            risk.risk_code, risk.title, risk.description, risk.category, risk.probability, risk.impact,
            risk.risk_level, risk.owner, risk.risk_location, risk.proactive_actions, risk.immediate_actions,
            risk.target_completion_date.strftime('%Y-%m-%d') if risk.target_completion_date else '',
            risk.action_effectiveness, risk.status, 
            created_at_ksa.strftime('%Y-%m-%d %H:%M:%S'), # <-- استخدام الوقت المحول
            risk.residual_risk,
            risk.linked_risk_id or 'لا يوجد',
            risk.business_continuity_plan,
            risk.lessons_learned
        ]
        writer.writerow(row)
    
    output.seek(0)
    
    return Response(
        "\ufeff" + output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=risk_log_{datetime.now().strftime('%Y%m%d')}.csv"}
    )

# --- API للإشعارات والتقارير (بدون تغيير) ---
@app.route('/api/notifications', methods=['GET'])
@login_required
def get_notifications():
    if current_user.username != 'admin': abort(403)
    unread_risks = Risk.query.filter_by(is_read=False, is_deleted=False).order_by(Risk.created_at.desc()).limit(10).all()
    count = Risk.query.filter_by(is_read=False, is_deleted=False).count()
    notifications = [{'id': r.id, 'title': r.title, 'user': r.user.username, 'timestamp': r.created_at.isoformat()} for r in unread_risks]
    return jsonify({'success': True, 'count': count, 'notifications': notifications})

@app.route('/api/notifications/mark-as-read', methods=['POST'])
@login_required
def mark_as_read():
    if current_user.username != 'admin': abort(403)
    data = request.get_json()
    risk_id = data.get('risk_id')
    try:
        if risk_id:
            Risk.query.filter_by(id=risk_id).update({'is_read': True})
        else:
            Risk.query.filter_by(is_read=False).update({'is_read': True})
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/reports/upload', methods=['POST'])
@login_required
def upload_report():
    if current_user.username not in ['admin', 'testuser']: abort(403)
    if 'report_file' not in request.files: return jsonify({'success': False, 'message': 'لم يتم العثور على ملف'}), 400
    file = request.files['report_file']
    report_type = request.form.get('report_type')
    if file.filename == '' or not report_type: return jsonify({'success': False, 'message': 'معلومات ناقصة'}), 400
    
    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config['REPORTS_UPLOAD_FOLDER'], filename))
    
    new_report = Report(filename=filename, report_type=report_type, uploaded_by_id=current_user.id)
    db.session.add(new_report)
    log = AuditLog(user_id=current_user.id, action='رفع تقرير', details=f"رفع تقرير جديد: {filename} من نوع {report_type}")
    db.session.add(log)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'تم رفع التقرير بنجاح'})

@app.route('/api/reports/list', methods=['GET'])
@login_required
def list_reports():
    reports = Report.query.order_by(Report.uploaded_at.desc()).all()
    reports_data = [{
        'id': r.id, 'filename': r.filename, 'report_type': r.report_type,
        'uploaded_by': r.uploaded_by.username, 'uploaded_at': r.uploaded_at.isoformat(),
        'is_archived': r.is_archived
    } for r in reports]
    return jsonify({'success': True, 'reports': reports_data})

@app.route('/api/reports/<int:report_id>/toggle_archive', methods=['POST'])
@login_required
def toggle_archive_report(report_id):
    if current_user.username != 'admin': abort(403)
    report = Report.query.get_or_404(report_id)
    report.is_archived = not report.is_archived
    action = 'أرشفة تقرير' if report.is_archived else 'استعادة تقرير'
    log = AuditLog(user_id=current_user.id, action=action, details=f"{action}: {report.filename}")
    db.session.add(log)
    db.session.commit()
    return jsonify({'success': True, 'message': f'تمت العملية بنجاح', 'is_archived': report.is_archived})

@app.route('/api/reports/<int:report_id>', methods=['DELETE'])
@login_required
def delete_report_permanently(report_id):
    if current_user.username != 'admin': abort(403)
    report = Report.query.get_or_404(report_id)
    if not report.is_archived: return jsonify({'success': False, 'message': 'يجب أرشفة التقرير أولاً قبل حذفه نهائياً'}), 400
    
    try: os.remove(os.path.join(app.config['REPORTS_UPLOAD_FOLDER'], report.filename))
    except OSError: pass
    
    log = AuditLog(user_id=current_user.id, action='حذف تقرير نهائي', details=f"حذف نهائي للتقرير: {report.filename}")
    db.session.add(log)
    db.session.delete(report)
    db.session.commit()
    return jsonify({'success': True, 'message': 'تم حذف التقرير نهائياً'})

@app.route('/api/reports/unread_status', methods=['GET'])
@login_required
def get_unread_reports_status():
    if current_user.username != 'admin': return jsonify({'has_unread': False})
    count = Report.query.filter_by(is_read=False).count()
    return jsonify({'has_unread': count > 0})

# --- نقطة بداية التطبيق ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
