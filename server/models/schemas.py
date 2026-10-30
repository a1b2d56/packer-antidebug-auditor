from typing import Optional, Literal, Any, List, Dict, Union
from pydantic import BaseModel, Field

JobStatus = Literal["PENDING", "RUNNING", "COMPLETED", "FAILED", "CANCELLED"]


class PEMetadata(BaseModel):
    arch: str
    entry_point: int
    image_base: int
    section_count: int


class SectionInfo(BaseModel):
    name: str
    entropy: float
    raw_size: int
    virtual_size: int
    characteristics: int
    likely_packed: bool
    entropy_reliable: Optional[bool] = None
    normalized_entropy: Optional[float] = None


class HeuristicsResult(BaseModel):
    size_deltas: List[Dict[str, Any]] = []
    packer_section_names: List[Dict[str, Any]] = []
    rwx_sections: List[Dict[str, Any]] = []
    entry_point_anomalies: List[Dict[str, Any]] = []
    overlay: Optional[Dict[str, Any]] = None
    iat_density: List[Dict[str, Any]] = []
    header_anomalies: List[Dict[str, Any]] = []
    section_count_flag: Optional[Dict[str, Any]] = None


class AntiAnalysisResult(BaseModel):
    imports: List[Dict[str, Any]] = []
    strings: List[Dict[str, Any]] = []
    tls_callbacks: List[Dict[str, Any]] = []
    opcodes: List[Dict[str, Any]] = []
    direct_syscalls: List[Dict[str, Any]] = []


class TechniqueRef(BaseModel):
    mitre_id: str
    mitre_name: str


class MitreTechnique(BaseModel):
    reason: str
    mitre_id: Optional[str] = None
    mitre_name: Optional[str] = None
    signal_key: Optional[str] = None
    secondary: List[TechniqueRef] = []


class VerdictResult(BaseModel):
    # int under the balanced profile; profiles with weight multipliers can yield fractions
    score: Union[int, float]
    verdict: Literal["LOW", "MEDIUM", "HIGH"]
    reasons: List[str]
    signal_keys: List[str] = []
    mitre_techniques: List[MitreTechnique] = []
    profile: Optional[str] = None
    thresholds: Optional[Dict[str, int]] = None
    confidence: Optional[float] = None
    score_interval: Optional[List[Union[int, float]]] = None
    verdict_stable: Optional[bool] = None


class MLPrediction(BaseModel):
    probability: float
    label: str
    confidence: float


class YaraMatch(BaseModel):
    rule: str
    namespace: Optional[str] = None
    description: str = ""
    mitre_id: Optional[str] = None
    confidence: Optional[str] = None
    tags: List[str] = []


class APKMetadata(BaseModel):
    package_name: str
    version_code: str
    version_name: str
    min_sdk: str
    target_sdk: str


class APKComponentInfo(BaseModel):
    activities: List[str] = []
    services: List[str] = []
    receivers: List[str] = []
    providers: List[str] = []


class AuditResult(BaseModel):
    job_id: str
    file_name: str
    file_type: Literal["PE", "APK"]
    sha256: str
    file_size: int
    status: JobStatus
    progress: Optional[int] = Field(default=None, ge=0, le=100)

    # Shared / PE specific
    pe_info: Optional[PEMetadata] = None
    sections: Optional[List[SectionInfo]] = None
    heuristics: Optional[HeuristicsResult] = None
    anti_analysis: Optional[AntiAnalysisResult] = None
    verdict: Optional[VerdictResult] = None
    ml_prediction: Optional[MLPrediction] = None

    # YARA matches
    yara_matches: Optional[List[YaraMatch]] = None

    # APK specific
    apk_info: Optional[APKMetadata] = None
    apk_components: Optional[APKComponentInfo] = None
    apk_permissions: Optional[List[str]] = None
    apk_endpoints: Optional[List[str]] = None
    apk_suspicious_apis: Optional[List[Dict[str, Any]]] = None

    # Non-fatal analysis notes (e.g. JADX partial output) and the error string if FAILED/CANCELLED
    warnings: List[str] = []
    error: Optional[str] = None


class HealthResponse(BaseModel):
    status: Literal["ok"]
    version: str
    model_loaded: bool
    yara_enabled: bool
    jadx_available: bool


class CancelResponse(BaseModel):
    job_id: str
    status: JobStatus
    cancelled: bool
