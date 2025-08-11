# الكود الصحيح
from flask import Blueprint

main_bp = Blueprint('main', __name__)

# هذا السطر يستدعي ملف routes.py الموجود بجانبه
# والذي يحتوي على كل المسارات مثل @main_bp.route('/')
from . import routes 
