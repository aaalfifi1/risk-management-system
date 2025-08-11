# المسار: src/routes/routes.py

from flask import Blueprint, jsonify, render_template, request, current_app, send_from_directory
from werkzeug.utils import secure_filename
import os
from sqlalchemy import func
from ..models import db, Risk

main_bp = Blueprint('main', __name__)

# --- مسارات الواجهة الأمامية ---
@main_bp.route('/')
def home():
    """يعرض صفحة سجل المخاطر الرئيسية."""
    return render_template('dashboard.html')

@main_bp.route('/stats')
def stats():
    """يحسب الإحصائيات ويعرض صفحة لوحة التحكم."""
    try:
        total_risks = db.session.query(func.count(Risk.id)).scalar()
        closed_risks = db.session.query(func.count(Risk.id)).filter(Risk.status == 'مغلق').scalar()
        active_risks = total_risks - closed_risks
        risk_distribution_query = db.session.query(Risk.risk_level, func.count(Risk.id)).group_by(Risk.risk_level).all()
        risk_distribution = {level or "غير محدد": count for level, count in risk_distribution_query}
        stats_data = {'total': total_risks, 'active': active_risks, 'closed': closed_risks, 'distribution': risk_distribution}
        return render_template('stats_dashboard.html', stats=stats_data)
    except Exception as e:
        print(f"Error calculating stats: {e}")
        return render_template('stats_dashboard.html', stats={'total': 0, 'active': 0, 'closed': 0, 'distribution': {}})

# --- مسار لخدمة الملفات المرفوعة ---
@main_bp.route('/uploads/<path:filename>')
def uploaded_file(filename):
    """يوفر رابطًا لتحميل وعرض الملفات المرفوعة."""
    return send_from_directory(current_app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


# --- مسارات الـ API ---

# GET: جلب كل المخاطر
@main_bp.route('/api/risks', methods=['GET'])
def get_risks():
    try:
        risks = Risk.query.order_by(Risk.created_at.desc()).all()
        return jsonify({'success': True, 'risks': [risk.to_dict() for risk in risks]})
    except Exception as e:
        return jsonify({'success': False, 'message': f'حدث خطأ: {str(e)}'}), 500

# GET: جلب خطر واحد
@main_bp.route('/api/risks/<int:risk_id>', methods=['GET'])
def get_risk(risk_id):
    try:
        risk = db.session.get(Risk, risk_id)
        if not risk: return jsonify({'success': False, 'message': 'لم يتم العثور على الخطر'}), 404
        return jsonify({'success': True, 'risk': risk.to_dict()})
    except Exception as e:
        return jsonify({'success': False, 'message': f'حدث خطأ: {str(e)}'}), 500

# POST: إضافة خطر جديد
@main_bp.route('/api/risks', methods=['POST'])
def add_risk():
    try:
        data = request.form
        if not data or 'title' not in data or 'category' not in data:
            return jsonify({'success': False, 'message': 'العنوان والفئة حقول مطلوبة'}), 400

        new_risk = Risk(
            title=data['title'],
            description=data.get('description', ''),
            category=data['category'],
            probability=int(data.get('probability', 1)),
            impact=int(data.get('impact', 1)),
            owner=data.get('owner', ''),
            risk_location=data.get('risk_location', ''),
            immediate_actions=data.get('immediate_actions', ''),
            action_effectiveness=data.get('action_effectiveness', ''),
            status=data.get('status', 'جديد')
        )
        
        if 'attachment' in request.files:
            file = request.files['attachment']
            if file and file.filename:
                filename = secure_filename(file.filename)
                upload_folder = current_app.config['UPLOAD_FOLDER']
                if not os.path.exists(upload_folder): os.makedirs(upload_folder)
                file.save(os.path.join(upload_folder, filename))
                new_risk.attachment_filename = filename

        new_risk.risk_level = new_risk.calculate_risk_level()
        db.session.add(new_risk)
        db.session.commit()
        
        # [الإصلاح الحاسم] إرجاع رسالة موحدة وبدون بيانات إضافية
        # الواجهة الأمامية ستقوم بتحديث الجدول عبر fetchRisks()
        return jsonify({'success': True, 'message': 'تمت إضافة الخطر بنجاح!'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'حدث خطأ: {str(e)}'}), 500

# PUT: تعديل خطر موجود
@main_bp.route('/api/risks/<int:risk_id>', methods=['PUT'])
def update_risk(risk_id):
    try:
        risk = db.session.get(Risk, risk_id)
        if not risk: return jsonify({'success': False, 'message': 'لم يتم العثور على الخطر'}), 404
        
        data = request.get_json()
        
        risk.title = data.get('title', risk.title)
        risk.description = data.get('description', risk.description)
        risk.category = data.get('category', risk.category)
        risk.probability = int(data.get('probability', risk.probability))
        risk.impact = int(data.get('impact', risk.impact))
        risk.owner = data.get('owner', risk.owner)
        risk.risk_location = data.get('risk_location', risk.risk_location)
        risk.immediate_actions = data.get('immediate_actions', risk.immediate_actions)
        risk.action_effectiveness = data.get('action_effectiveness', risk.action_effectiveness)
        risk.status = data.get('status', risk.status)
        
        risk.risk_level = risk.calculate_risk_level()
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'تم تحديث الخطر بنجاح!'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'حدث خطأ: {str(e)}'}), 500

# DELETE: حذف خطر
@main_bp.route('/api/risks/<int:risk_id>', methods=['DELETE'])
def delete_risk(risk_id):
    try:
        risk = db.session.get(Risk, risk_id)
        if not risk: return jsonify({'success': False, 'message': 'لم يتم العثور على الخطر'}), 404
        
        if risk.attachment_filename:
            file_path = os.path.join(current_app.config['UPLOAD_FOLDER'], risk.attachment_filename)
            if os.path.exists(file_path): os.remove(file_path)

        db.session.delete(risk)
        db.session.commit()
        return jsonify({'success': True, 'message': 'تم حذف الخطر بنجاح!'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': f'حدث خطأ: {str(e)}'}), 500
