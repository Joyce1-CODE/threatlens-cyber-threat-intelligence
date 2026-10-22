import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, DateTime, JSON, Text
from app.database import Base

def utc_now():
    return datetime.now(timezone.utc)

class Investigation(Base):
    __tablename__ = "investigations"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    indicator = Column(String(512), nullable=False, index=True)
    normalized_indicator = Column(String(512), nullable=False, index=True)
    indicator_type = Column(String(32), nullable=False, index=True)
    
    risk_score = Column(Integer, nullable=False, default=0)
    severity = Column(String(16), nullable=False, default="Low", index=True)
    confidence = Column(String(32), nullable=False, default="Low")
    data_coverage = Column(String(64), nullable=False, default="None")
    
    verdict_summary = Column(Text, nullable=False)
    
    vt_status = Column(String(32), nullable=False, default="unconfigured")
    otx_status = Column(String(32), nullable=False, default="unconfigured")
    
    vt_detections = Column(Integer, default=0)
    vt_total_engines = Column(Integer, default=0)
    otx_pulse_count = Column(Integer, default=0)
    
    evidence = Column(JSON, nullable=False, default=list)
    factor_breakdown = Column(JSON, nullable=False, default=dict)
    provider_results = Column(JSON, nullable=False, default=dict)
    recommendations = Column(JSON, nullable=False, default=list)
    
    created_at = Column(DateTime(timezone=True), default=utc_now, index=True)
