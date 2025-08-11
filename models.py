# المسار: src/models.py

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Risk(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(100), nullable=False)
    
    probability = db.Column(db.Integer, nullable=False, default=1)
    impact = db.Column(db.Integer, nullable=False, default=1)
    
    risk_level = db.Column(db.String(50), nullable=True)
    owner = db.Column(db.String(100), nullable=True)
    risk_location = db.Column(db.String(150), nullable=True)
    immediate_actions = db.Column(db.Text, nullable=True)
    action_effectiveness = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(50), nullable=False, default='جديد')
    attachment_filename = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def calculate_risk_level(self):
        """
        يحسب مستوى الخطورة بناءً على مصفوفة التقييم الصحيحة.
        النتيجة = الاحتمالية * التأثير.
        """
        score = int(self.probability) * int(self.impact)
        
        if score >= 20:
            return 'مرتفع جدا / كارثي'
        elif score >= 15:
            return 'مرتفع'
        elif score >= 10:
            return 'متوسط'
        elif score >= 5:
            ret
