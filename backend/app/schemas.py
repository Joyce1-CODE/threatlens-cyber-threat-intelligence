from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field, ConfigDict

class IOCInvestigationRequest(BaseModel):
    indicator: str = Field(..., min_length=1, max_length=2048, description="Indicator of Compromise (IP, Domain, URL, or Hash)")
    indicator_type: Optional[str] = Field(default="auto", description="Optional explicit indicator type or 'auto'")

class ProviderStatus(BaseModel):
    name: str
    configured: bool
    status: str # ready, missing_key, error
    rate_limit_info: str
    description: str

class SystemStatusResponse(BaseModel):
    app_name: str
    version: str
    status: str
    timestamp: datetime
    providers: Dict[str, ProviderStatus]

class ProviderResultDetail(BaseModel):
    provider_name: str
    status: str # success, clean, not_found, missing_key, rate_limited, unauthorized, error, unsupported
    is_malicious: bool = False
    detections: int = 0
    total_engines: int = 0
    reputation_score: Optional[float] = None
    summary: str = ""
    error_message: Optional[str] = None
    queried_at: Optional[datetime] = None
    attributes: Dict[str, Any] = Field(default_factory=dict)

class RiskFactorBreakdown(BaseModel):
    virustotal_weight: float = 0.0
    virustotal_score: float = 0.0
    alienvault_weight: float = 0.0
    alienvault_score: float = 0.0
    synergy_boost: float = 0.0
    final_score: int = 0

class EvidenceItem(BaseModel):
    source: str
    severity: str # info, low, medium, high, critical
    title: str
    description: str
    timestamp: Optional[datetime] = None

class InvestigationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    indicator: str
    normalized_indicator: str
    indicator_type: str
    risk_score: int
    severity: str
    confidence: str
    data_coverage: str
    verdict_summary: str
    vt_status: str
    otx_status: str
    vt_detections: int
    vt_total_engines: int
    otx_pulse_count: int
    evidence: List[Dict[str, Any]]
    factor_breakdown: Dict[str, Any]
    provider_results: Dict[str, Any]
    recommendations: List[str]
    created_at: datetime

class InvestigationListItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    indicator: str
    normalized_indicator: str
    indicator_type: str
    risk_score: int
    severity: str
    confidence: str
    vt_status: str
    otx_status: str
    vt_detections: int
    otx_pulse_count: int
    created_at: datetime

class PaginatedInvestigationResponse(BaseModel):
    total: int
    page: int
    page_size: int
    total_pages: int
    items: List[InvestigationListItem]

class DashboardStatsResponse(BaseModel):
    total_investigations: int
    unique_indicators: int
    high_critical_count: int
    severity_breakdown: Dict[str, int]
    indicator_type_breakdown: Dict[str, int]
    provider_health: Dict[str, ProviderStatus]
    recent_investigations: List[InvestigationListItem]


# ==========================================
# Authentication & User Management Schemas
# ==========================================

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=128, description="Username or email")
    password: str = Field(..., min_length=1, max_length=256, description="User password")

class RefreshTokenRequest(BaseModel):
    refresh_token: Optional[str] = Field(default=None, description="Optional refresh token string if not supplied via cookie")

class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    email: str
    full_name: Optional[str] = ""
    role: str
    is_active: bool
    created_at: datetime

class AuthTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse
    refresh_token: Optional[str] = None

class UserCreateRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    email: str = Field(..., min_length=5, max_length=255)
    password: str = Field(..., min_length=8, max_length=128)
    full_name: Optional[str] = ""
    role: str = Field(default="Read-Only Analyst", description="Admin, Senior Analyst, or Read-Only Analyst")

class UserUpdateRequest(BaseModel):
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    password: Optional[str] = Field(default=None, min_length=8, max_length=128)

class UserListResponse(BaseModel):
    total: int
    users: List[UserResponse]
