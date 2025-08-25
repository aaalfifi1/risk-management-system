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
import secrets # لإنشاء رموز آمنة

# --- تهيئة التطبيق ---
app = Flask(__name__)

# --- إعدادات التطبيق ومتغيرات البيئة ---
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)
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
    
    # ▼▼▼ [التعديل الوحيد هنا] إضافة حقول جديدة ▼▼▼
    reset_token = db.Column(db.String(100), unique=True, nullable=True)
    reset_token_expiration = db.Column(db.DateTime, nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime, nullable=True)
    # ▲▲▲ نهاية التعديل ▲▲▲

    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password): return check_password_hash(self.password_hash, password)

class Risk(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    risk_code = db.Column(db.String(20), unique=True, nullable=True)
    source = db.Column(db.String(20), nullable=True)
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
    closed_at = db.Column(db.DateTime, nullable=True)

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
def load_user(user_id): return User.query.get(int(user_id))

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

# --- مسارات الصفحات ---
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

@app.route('/risk-register')
@login_required
def risk_register(): return render_template('dashboard.html')

@app.route('/reports')
@login_required
def reports():
    if current_user.username not in ['admin', 'testuser']: abort(403)
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
    logs_from_db = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    processed_logs = []
    for log in logs_from_db:
        log.timestamp_ksa = (log.timestamp + timedelta(hours=3)).strftime('%Y-%m-%d %H:%M:%S')
        processed_logs.append(log)
    return render_template('audit_log.html', logs=processed_logs)

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename): return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/reports_uploads/<report_type>/<filename>')
@login_required
def uploaded_report_file(report_type, filename):
    report_path = os.path.join(app.config['REPORTS_UPLOAD_FOLDER'], report_type)
    return send_from_directory(report_path, filename)

# ▼▼▼ [تعديل] استبدال دالة login القديمة بالكامل ▼▼▼
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        # 1. التحقق إذا كان الحساب مقفلاً
        if user and user.account_locked_until and user.account_locked_until > datetime.utcnow():
            remaining_time = user.account_locked_until - datetime.utcnow()
            minutes_left = (remaining_time.seconds // 60) + 1
            flash(f'تم قفل الحساب مؤقتاً بسبب كثرة المحاولات الفاشلة. يرجى المحاولة مرة أخرى بعد {minutes_left} دقيقة.', 'danger')
            return render_template('login.html')

        # 2. التحقق من صحة كلمة المرور
        if user and user.check_password(password):
            # تسجيل دخول ناجح: إعادة تعيين عداد الفشل وتسجيل الدخول
            user.failed_login_attempts = 0
            user.account_locked_until = None
            db.session.commit()
            
            login_user(user)
            session.permanent = True 
            session['is_admin'] = (user.username == 'admin')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('home'))
        else:
            # تسجيل دخول فاشل
            if user:
                user.failed_login_attempts += 1
                if user.failed_login_attempts >= 5:
                    user.account_locked_until = datetime.utcnow() + timedelta(minutes=15)
                    user.failed_login_attempts = 0
                    flash('لقد تجاوزت عدد المحاولات المسموح بها. تم قفل الحساب لمدة 15 دقيقة.', 'danger')
                else:
                    remaining_attempts = 5 - user.failed_login_attempts
                    flash(f'فشل تسجيل الدخول. يرجى التحقق من اسم المستخدم وكلمة المرور. (متبقي {remaining_attempts} محاولات)', 'warning')
                db.session.commit()
            else:
                flash('فشل تسجيل الدخول. يرجى التحقق من اسم المستخدم وكلمة المرور.', 'danger')
            
            return render_template('login.html')

    return render_template('login.html')
# ▲▲▲ نهاية التعديل ▲▲▲

@app.route('/logout')
@login_required
def logout():
    session.pop('is_admin', None)
    logout_user()
    return redirect(url_for('login'))

# ▼▼▼ [إضافة] مسارات استعادة كلمة المرور الجديدة ▼▼▼
@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            user.reset_token_expiration = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()
            reset_url = url_for('reset_with_token', token=token, _external=True)
            subject = "طلب إعادة تعيين كلمة المرور - نظام إدارة المخاطر"
            html_content = f"""
            <div dir='rtl' style='font-family: Arial, sans-serif; text-align: right;'>
                <h2>طلب إعادة تعيين كلمة المرور</h2>
                <p>مرحباً {user.username},</p>
                <p>لقد طلبت إعادة تعيين كلمة المرور الخاصة بك في نظام إدارة المخاطر.</p>
                <p>اضغط على الرابط التالي لتعيين كلمة مرور جديدة. هذا الرابط صالح لمدة ساعة واحدة فقط:</p>
                <p style='text-align: center;'><a href='{reset_url}' style='background-color: #ffc107; color: #000; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-weight: bold;'>إعادة تعيين كلمة المرور</a></p>
                <p>إذا لم تطلب أنت هذا الإجراء، يرجى تجاهل هذه الرسالة.</p>
            </div>
            """
            send_email(to_email=user.email, subject=subject, html_content=html_content)
            flash('تم إرسال تعليمات إعادة تعيين كلمة المرور إلى بريدك الإلكتروني.', 'success')
            return redirect(url_for('login'))
        else:
            flash('البريد الإلكتروني غير مسجل في النظام.', 'danger')
    return render_template('reset_password_request.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_with_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.query.filter_by(reset_token=token).first()
    if not user or user.reset_token_expiration < datetime.utcnow():
        flash('رابط إعادة تعيين كلمة المرور غير صالح أو انتهت صلاحيته.', 'danger')
        return redirect(url_for('reset_password_request'))
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        if password != confirm_password:
            flash('كلمتا المرور غير متطابقتين.', 'danger')
            return render_template('reset_password.html', token=token)
        user.set_password(password)
        user.reset_token = None
        user.reset_token_expiration = None
        db.session.commit()
        flash('تم تغيير كلمة المرور بنجاح. يمكنك الآن تسجيل الدخول.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)
# ▲▲▲ نهاية الإضافة ▲▲▲

# --- دالة تصدير CSV ---
@app.route('/download-risk-log')
@login_required
def download_risk_log():
    if current_user.username not in ['admin', 'testuser']:
        abort(403)
    
    query = Risk.query.filter_by(is_deleted=False)

    if current_user.username != 'admin':
        query = query.filter_by(user_id=current_user.id)

    risks = query.order_by(Risk.created_at.asc()).all()

    output = io.StringIO()
    writer = csv.writer(output, delimiter=';')
    headers = [
        'Risk Code', 'Title', 'Description', 'Category', 'Probability', 'Impact', 'Risk Level', 'Status', 
        'Owner', 'Risk Location', 'Proactive Actions', 'Immediate Actions', 'Target Completion Date', 
        'Action Effectiveness', 'Residual Risk', 'Linked Risk', 'Business Continuity Plan', 
        'Lessons Learned', 'Created At', 'Reporter'
    ]
    writer.writerow(headers)
    for risk in risks:
        reporter_username = risk.user.username if risk.user else 'N/A'
        completion_date = risk.target_completion_date.strftime('%Y-%m-%d') if risk.target_completion_date else ''
        created_at_ksa = risk.created_at + timedelta(hours=3)
        
        proactive_cleaned = (risk.proactive_actions or '').replace('||IMPROVEMENT||', ' (إجراء تحسيني): ')
        immediate_cleaned = (risk.immediate_actions or '').replace('||IMPROVEMENT||', ' (إجراء تحسيني): ')

        writer.writerow([
            risk.risk_code or risk.id, risk.title, risk.description, risk.category, risk.probability, 
            risk.impact, risk.risk_level, risk.status, risk.owner, risk.risk_location, 
            proactive_cleaned, immediate_cleaned, completion_date, risk.action_effectiveness, 
            risk.residual_risk, risk.linked_risk_id, risk.business_continuity_plan, risk.lessons_learned, 
            created_at_ksa.strftime('%Y-%m-%d %H:%M:%S'),
            reporter_username
        ])
    final_output = output.getvalue().encode('utf-8-sig')
    output.close()
    return Response(final_output, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=risk_log.csv"})

# --- دوال الـ API ---
@app.route('/api/risks', methods=['POST'])
@login_required
def add_risk():
    try:
        data = request.form
        user_role = current_user.username
        is_read_status = (user_role == 'admin')
        target_date = None
        if data.get('target_completion_date'):
            try:
                target_date = datetime.strptime(data.get('target_completion_date'), '%Y-%m-%d')
            except ValueError:
                pass

        if user_role == 'reporter':
            if not data.get('description') or not data.get('risk_location'): return jsonify({'success': False, 'message': 'وصف الخطر وموقعه حقول مطلوبة.'}), 400
            new_risk = Risk(title="", description=data['description'], category="", probability=1, impact=1, risk_level="", owner=data.get('owner', 'لم يتم توفيره'), risk_location=data['risk_location'], user_id=current_user.id, status='جديد', is_read=is_read_status)
        else:
            prob = int(data.get('probability', 1)); imp = int(data.get('impact', 1))
            effectiveness = data.get('action_effectiveness'); residual = calculate_residual_risk(effectiveness)
            new_risk = Risk(
                title=data['title'], 
                description=data.get('description'), 
                risk_type=data.get('risk_type', 'تهديد'),
                source=data.get('source'),
                category=data['category'], 
                probability=prob, 
                impact=imp, 
                risk_level=calculate_risk_level(prob, imp), 
                owner=data.get('owner'), 
                risk_location=data.get('risk_location'), 
                proactive_actions=data.get('proactive_actions'), 
                immediate_actions=data.get('immediate_actions'), 
                action_effectiveness=effectiveness, 
                user_id=current_user.id, 
                status=data.get('status', 'نشط'), 
                residual_risk=residual, 
                is_read=is_read_status, 
                lessons_learned=data.get('lessons_learned'),
                target_completion_date=target_date,
                business_continuity_plan=data.get('business_continuity_plan'),
                linked_risk_id=data.get('linked_risk_id') if data.get('linked_risk_id') != 'لا يوجد' else None
            )
        
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
                send_email(to_email=admin_user.email, subject=subject,html_content=html_content)
        
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
        
        old_status = risk.status
        new_status = data.get('status', risk.status)
        
        IMPROVEMENT_SEPARATOR = "||IMPROVEMENT||"
        
        def preserve_improvements(old_value, new_value_from_form):
            if old_value and IMPROVEMENT_SEPARATOR in old_value:
                parts = old_value.split(IMPROVEMENT_SEPARATOR)
                return f"{new_value_from_form}{IMPROVEMENT_SEPARATOR}{parts[1]}"
            return new_value_from_form

        risk.proactive_actions = preserve_improvements(risk.proactive_actions, data.get('proactive_actions', ''))
        risk.immediate_actions = preserve_improvements(risk.immediate_actions, data.get('immediate_actions', ''))

        prob = int(data.get('probability', risk.probability))
        imp = int(data.get('impact', risk.impact))
        effectiveness = data.get('action_effectiveness', risk.action_effectiveness)
        residual = calculate_residual_risk(effectiveness)
        
        risk.title = data.get('title', risk.title)
        risk.description = data.get('description', risk.description)
        risk.risk_type = data.get('risk_type', risk.risk_type)
        risk.source = data.get('source', risk.source)
        risk.category = data.get('category', risk.category)
        risk.probability = prob
        risk.impact = imp
        risk.risk_level = calculate_risk_level(prob, imp)
        risk.owner = data.get('owner', risk.owner)
        risk.risk_location = data.get('risk_location', risk.risk_location)
        risk.action_effectiveness = effectiveness
        risk.status = new_status
        risk.residual_risk = residual
        risk.lessons_learned = data.get('lessons_learned', risk.lessons_learned)
        
        target_date = None
        if data.get('target_completion_date'):
            try:
                target_date = datetime.strptime(data.get('target_completion_date'), '%Y-%m-%d')
            except (ValueError, TypeError):
                target_date = None
        risk.target_completion_date = target_date
        
        if new_status == 'مغلق' and old_status != 'مغلق':
            risk.closed_at = datetime.utcnow()
        elif new_status != 'مغلق':
            risk.closed_at = None
        
        risk.business_continuity_plan = data.get('business_continuity_plan', risk.business_continuity_plan)
        
        linked_risk_value = data.get('linked_risk_id')
        risk.linked_risk_id = linked_risk_value if linked_risk_value and linked_risk_value != 'لا يوجد' else None

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

@app.route('/api/risks/<int:risk_id>/update_action', methods=['PUT'])
@login_required
def update_risk_action(risk_id):
    try:
        risk = Risk.query.get_or_404(risk_id)
        if current_user.username != 'admin' and risk.user_id != current_user.id:
            return jsonify({'success': False, 'message': 'غير مصرح لك بتعديل هذا الخطر'}), 403

        data = request.get_json()
        field_to_update = data.get('field')
        new_value = data.get('value')

        if field_to_update not in ['proactive_actions', 'immediate_actions']:
            return jsonify({'success': False, 'message': 'حقل غير صالح للتحديث'}), 400

        IMPROVEMENT_SEPARATOR = "||IMPROVEMENT||"
        
        current_db_value = getattr(risk, field_to_update) or ""
        original_text = current_db_value.split(IMPROVEMENT_SEPARATOR)[0]

        final_value = f"{original_text}{IMPROVEMENT_SEPARATOR}{new_value}"
        
        setattr(risk, field_to_update, final_value)
        
        if current_user.username != 'admin':
            risk.is_read = False
            risk.was_modified = True

        log_details = f"إضافة/تعديل إجراء تحسيني في حقل '{field_to_update}' للخطر بكود: '{risk.risk_code}'"
        log_entry = AuditLog(user_id=current_user.id, action='إجراء تحسيني', details=log_details, risk_id=risk.id)
        db.session.add(log_entry)
        
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'تم تحديث الإجراء بنجاح', 'newValue': final_value})

    except Exception as e:
        db.session.rollback()
        print(f"An error occurred in update_risk_action: {e}")
        return jsonify({'success': False, 'message': f'حدث خطأ غير متوقع: {str(e)}'}), 500

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
            'id': r.id, 
            'risk_code': r.risk_code, 
            'title': r.title, 
            'description': r.description, 
            'risk_type': r.risk_type,
            'source': r.source,
            'category': r.category, 
            'probability': r.probability, 
            'impact': r.impact, 
            'risk_level': r.risk_level, 
            'owner': r.owner, 
            'risk_location': r.risk_location, 
            'proactive_actions': r.proactive_actions, 
            'immediate_actions': r.immediate_actions, 
            'action_effectiveness': r.action_effectiveness, 
            'status': r.status, 
            'created_at': r.created_at.isoformat(),
            'residual_risk': r.residual_risk, 
            'attachment_filename': r.attachment_filename, 
            'user_id': r.user_id, 
            'lessons_learned': r.lessons_learned, 
            'is_read': r.is_read, 
            'was_modified': r.was_modified,
            'target_completion_date': r.target_completion_date.strftime('%Y-%m-%d') if r.target_completion_date else None,
            'business_continuity_plan': r.business_continuity_plan,
            'linked_risk_id': r.linked_risk_id
        }
        risk_list.append(risk_data)
    return jsonify({'success': True, 'risks': risk_list, 'all_risk_codes': all_risk_codes})

@app.route('/api/risks/<int:risk_id>', methods=['DELETE'])
@login_required
def delete_risk(risk_id):
    risk = Risk.query.get_or_404(risk_id)
    if current_user.username != 'admin' and risk.user_id != current_user.id: return jsonify({'success': False, 'message': 'غير مصرح لك بحذف هذا الخطر'}), 403
    risk.is_deleted = True
    log_entry = AuditLog(user_id=current_user.id, action='حذف', details=f"حذف الخطر بكود: '{risk.risk_code}'", risk_id=risk.id)
    db.session.add(log_entry)
    db.session.commit()
    return jsonify({'success': True, 'message': 'تم حذف الخطر (أرشفته) بنجاح'})

@app.route('/api/risks/<int:risk_id>/restore', methods=['POST'])
@login_required
def restore_risk(risk_id):
    if current_user.username != 'admin': return jsonify({'success': False, 'message': 'غير مصرح لك'}), 403
    risk = Risk.query.filter_by(id=risk_id, is_deleted=True).first_or_404()
    risk.is_deleted = False
    log_to_delete = AuditLog.query.filter_by(risk_id=risk_id, action='حذف').first()
    if log_to_delete: db.session.delete(log_to_delete)
    restore_log = AuditLog(user_id=current_user.id, action='استعادة', details=f"استعادة الخطر بكود: '{risk.risk_code}'", risk_id=risk.id)
    db.session.add(restore_log)
    db.session.commit()
    return jsonify({'success': True, 'message': 'تمت استعادة الخطر بنجاح'})

@app.route('/api/risks/<int:risk_id>/permanent', methods=['DELETE'])
@login_required
def permanent_delete_risk(risk_id):
    if current_user.username != 'admin': return jsonify({'success': False, 'message': 'غير مصرح لك بالحذف النهائي'}), 403
    risk = Risk.query.get_or_404(risk_id)
    AuditLog.query.filter_by(risk_id=risk_id).delete()
    if risk.attachment_filename:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], risk.attachment_filename)
        if os.path.exists(file_path): os.remove(file_path)
    db.session.delete(risk)
    db.session.commit()
    return jsonify({'success': True, 'message': 'تم حذف الخطر نهائياً من النظام.'})

@app.route('/api/risks/<int:risk_id>/delete_attachment', methods=['DELETE'])
@login_required
def delete_attachment(risk_id):
    risk = Risk.query.get_or_404(risk_id)
    if current_user.username != 'admin' and risk.user_id != current_user.id: return jsonify({'success': False, 'message': 'غير مصرح لك'}),403
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
    try:
        # الاستعلام الأول: شامل وغير مفلتر (لحساب مؤشرات الشريط)
        base_query_for_kpi = Risk.query.filter_by(is_deleted=False)
        if current_user.username != 'admin':
            base_query_for_kpi = base_query_for_kpi.filter_by(user_id=current_user.id)
        
        all_risks_for_kpi = base_query_for_kpi.all()

        kpi_data = []
        if all_risks_for_kpi:
            # 1. حساب المؤشرات القديمة
            linked_risks_count = sum(1 for r in all_risks_for_kpi if r.linked_risk_id)
            secondary_risks_count = sum(1 for r in all_risks_for_kpi if r.title and r.title.startswith('(خطر ثانوي)'))
            residual_risks_count = sum(1 for r in all_risks_for_kpi if r.title and r.title.startswith('(خطر متبقٍ)'))

            # 2. حساب المؤشرات الأخرى
            effectiveness_counts = Counter(r.action_effectiveness for r in all_risks_for_kpi if r.action_effectiveness)
            status_counts_kpi = Counter(r.status for r in all_risks_for_kpi if r.status)
            owner_counts = Counter(r.owner for r in all_risks_for_kpi if r.owner)

            # 3. حساب الفئة الأكثر خطورة
            high_risk_levels = ['مرتفع', 'مرتفع جدا / كارثي']
            high_risks = [r for r in all_risks_for_kpi if r.risk_level in high_risk_levels]
            
            # 4. استخلاص القيم للمؤشرات البسيطة
            most_common_effectiveness = effectiveness_counts.most_common(1)[0][0] if effectiveness_counts else "لا يوجد"
            most_common_status = status_counts_kpi.most_common(1)[0][0] if status_counts_kpi else "لا يوجد"
            most_common_owner = owner_counts.most_common(1)[0][0] if owner_counts else "لا يوجد"

            # 5. حساب أعداد المخاطر حسب المستوى المجمع
            high_level_count = sum(1 for r in all_risks_for_kpi if r.risk_level in ['مرتفع', 'مرتفع جدا / كارثي'])
            medium_level_count = sum(1 for r in all_risks_for_kpi if r.risk_level == 'متوسط')
            low_level_count = sum(1 for r in all_risks_for_kpi if r.risk_level in ['منخفض', 'منخفض جدا'])

            # 6. حساب الالتزام الزمني من القائمة الكاملة للمخاطر
            kpi_overdue_risks_count = 0
            kpi_on_time_risks_count = 0
            today_for_kpi = datetime.utcnow().date()
            active_risks_for_kpi = [r for r in all_risks_for_kpi if r.status != 'مغلق']
            for risk in active_risks_for_kpi:
                if risk.target_completion_date and risk.target_completion_date.date() < today_for_kpi:
                    kpi_overdue_risks_count += 1
                else:
                    kpi_on_time_risks_count += 1
            
            # 7. تحديد الفئة الأكثر خطورة بذكاء
            most_dangerous_category = "لا يوجد"
            if high_risks:
                categories_data = {}
                for r in high_risks:
                    if r.category not in categories_data:
                        categories_data[r.category] = []
                    categories_data[r.category].append(r)

                category_scores = []
                for category, risks_in_cat in categories_data.items():
                    avg_score = sum(r.probability * r.impact for r in risks_in_cat) / len(risks_in_cat)
                    very_high_count = sum(1 for r in risks_in_cat if r.risk_level == 'مرتفع جدا / كارثي')
                    total_high_count = len(risks_in_cat)
                    category_scores.append({
                        'name': category,
                        'avg_score': avg_score,
                        'very_high_count': very_high_count,
                        'total_high_count': total_high_count
                    })

                if category_scores:
                    sorted_categories = sorted(
                        category_scores, 
                        key=lambda x: (x['very_high_count'], x['avg_score'], x['total_high_count']), 
                        reverse=True
                    )
                    
                    top_score_tuple = (
                        sorted_categories[0]['very_high_count'], 
                        sorted_categories[0]['avg_score'], 
                        sorted_categories[0]['total_high_count']
                    )
                    winners = [
                        cat['name'] for cat in sorted_categories 
                        if (cat['very_high_count'], cat['avg_score'], cat['total_high_count']) == top_score_tuple
                    ]
                    
                    if len(winners) == 1:
                        most_dangerous_category = winners[0]
                    elif len(winners) == 2:
                        most_dangerous_category = f"{winners[0]}, {winners[1]}"
                    else:
                        most_dangerous_category = f"{len(winners)} فئات"

            # 8. بناء قائمة المؤشرات النهائية بالترتيب المطلوب
            kpi_data.extend([
                {'label': 'المخاطر المترابطة:', 'value': str(linked_risks_count)},
                {'label': 'المخاطر الثانوية:', 'value': str(secondary_risks_count)},
                {'label': 'المخاطر المتبقية:', 'value': str(residual_risks_count)},
                {'label': 'فعالية الإجراءات الأكثر تكراراً:', 'value': most_common_effectiveness},
                {'label': 'الحالة الأكثر تكراراً:', 'value': most_common_status},
                {'label': 'المالك الأكثر تكليفاً:', 'value': most_common_owner},
                {'label': 'الفئة الأكثر خطورة:', 'value': most_dangerous_category},
                {'label': 'المخاطر المرتفعة:', 'value': str(high_level_count)},
                {'label': 'المخاطر المتوسطة:', 'value': str(medium_level_count)},
                {'label': 'المخاطر المنخفضة:', 'value': str(low_level_count)},
                {'label': 'مخاطر ملتزمة زمنياً:', 'value': str(kpi_on_time_risks_count)},
                {'label': 'مخاطر متأخرة زمنياً:', 'value': str(kpi_overdue_risks_count)}
            ])

        # الاستعلام الثاني: تفاعلي ومفلتر (لحساب الرسوم البيانية)
        query_for_charts = Risk.query.filter_by(is_deleted=False)
        if current_user.username != 'admin':
            query_for_charts = query_for_charts.filter_by(user_id=current_user.id)

        filter_category = request.args.get('category')
        if filter_category: query_for_charts = query_for_charts.filter(Risk.category == filter_category)
        
        filter_level = request.args.get('level')
        if filter_level: query_for_charts = query_for_charts.filter(Risk.risk_level == filter_level)
        
        filter_type = request.args.get('type')
        if filter_type: query_for_charts = query_for_charts.filter(Risk.risk_type == filter_type)
        
        filter_status = request.args.get('status')
        if filter_status: query_for_charts = query_for_charts.filter(Risk.status == filter_status)
        
        filter_code = request.args.get('code')
        if filter_code: query_for_charts = query_for_charts.filter(Risk.risk_code == filter_code)
        
        risks_for_charts = query_for_charts.all()

        total = len(risks_for_charts)
        active_risks_list = [r for r in risks_for_charts if r.status != 'مغلق']
        active = len(active_risks_list)
        closed = total - active
        
        threats = len([r for r in risks_for_charts if r.risk_type == 'تهديد'])
        opportunities = len([r for r in risks_for_charts if r.risk_type == 'فرصة'])
        
        threats_percentage = (threats / total * 100) if total > 0 else 0
        opportunities_percentage = (opportunities / total * 100) if total > 0 else 0
        
        matrix_data = [{'x': r.probability, 'y': r.impact, 'type': r.risk_type, 'title': r.title, 'code': r.risk_code} for r in risks_for_charts]
        
        active_percentage = (active / total * 100) if total > 0 else 0
        closed_percentage = (closed / total * 100) if total > 0 else 0
        
        risk_level_order = ['مرتفع جدا / كارثي', 'مرتفع', 'متوسط', 'منخفض', 'منخفض جدا']
        categories = sorted(list(set(r.category for r in risks_for_charts if r.category)))
        by_category_stacked = {level: [0] * len(categories) for level in risk_level_order}
        for risk in risks_for_charts:
            if risk.category and risk.category in categories:
                cat_index = categories.index(risk.category)
                by_category_stacked[risk.risk_level][cat_index] += 1

        by_level_nested = {'threats': [0] * 5, 'opportunities': [0] * 5}
        for risk in risks_for_charts:
            if risk.risk_level in risk_level_order:
                level_index = risk_level_order.index(risk.risk_level)
                if risk.risk_type == 'تهديد':
                    by_level_nested['threats'][level_index] += 1
                else:
                    by_level_nested['opportunities'][level_index] += 1

        status_counts = Counter(r.status for r in risks_for_charts)

        overdue_risks_count = 0
        on_time_risks_count = 0
        today = datetime.utcnow().date()
        for risk in active_risks_list:
            if risk.target_completion_date and risk.target_completion_date.date() < today:
                overdue_risks_count += 1
            else:
                on_time_risks_count += 1

        stats_data = {
            'total_risks': total, 'active_risks': active, 'closed_risks': closed, 
            'active_risks_percentage': active_percentage, 'closed_risks_percentage': closed_percentage,
            'total_threats': threats, 'total_opportunities': opportunities,
            'threats_percentage': threats_percentage, 'opportunities_percentage': opportunities_percentage,
            'matrix_data': matrix_data,
            'by_category_stacked': {'labels': categories, 'datasets': by_category_stacked},
            'by_level_nested': {'labels': risk_level_order, 'datasets': by_level_nested},
            'by_status': {'labels': list(status_counts.keys()), 'data': list(status_counts.values())},
            'timeliness': {'labels': ['ملتزم بالوقت', 'متأخر'], 'data': [on_time_risks_count, overdue_risks_count]},
            'top_risks': [{'code': r.risk_code, 'title': r.title, 'level': r.risk_level, 'score': r.probability * r.impact} for r in sorted([risk for risk in risks_for_charts if risk.status != 'مغلق' and risk.risk_level in ['مرتفع', 'مرتفع جدا / كارثي']], key=lambda x: (x.probability * x.impact, x.created_at), reverse=True)[:5]],
            'kpi_ticker_data': kpi_data
        }
        return jsonify({'success': True, 'stats': stats_data})

    except Exception as e:
        print(f"!!!!!!!!!!!!!!!!! ERROR IN get_stats_api !!!!!!!!!!!!!!!\n{traceback.format_exc()}\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        return jsonify({'success': False, 'message': 'Internal Server Error'}), 500


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

