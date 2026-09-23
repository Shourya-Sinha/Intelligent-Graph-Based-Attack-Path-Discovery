from pydantic import BaseModel, Field, HttpUrl
from typing import List, Optional, Dict, Any, Literal
from enum import Enum
from datetime import datetime
import uuid

class ScanMode(str, Enum):
    QUICK = "quick"
    DEEP = "deep"
    ADVANCE = "advance"
    STEALTH = "stealth"
    COMPREHENSIVE = "comprehensive"

class ScanTargetType(str, Enum):
    WEB = "web"
    NETWORK = "network"
    API = "api"
    CLOUD = "cloud"
    INTERNAL = "internal"

class ScanRequest(BaseModel):
    target: str = Field(..., description="Target URL, IP, CIDR or domain")
    mode: ScanMode = ScanMode.ADVANCE
    target_type: ScanTargetType = ScanTargetType.WEB
    depth: int = Field(2, ge=1, le=5)
    enable_subdomain_enum: bool = True
    enable_port_scan: bool = True
    enable_dir_bruteforce: bool = True
    enable_vuln_scan: bool = True
    enable_graph_build: bool = True
    enable_ai_analysis: bool = True
    custom_headers: Optional[Dict[str, str]] = None
    auth_cookies: Optional[str] = None
    wordlist_size: Literal["small","medium","large"] = "medium"
    # Powerhouse controls — user selects how much power to use
    engines: Optional[List[str]] = Field(default=None, description="Selected engine ids (44 total). Null → use global power config")
    power_preset: Optional[str] = Field(default=None, description="Preset: eco/balanced/maximum/turbo/overdrive")
    powerhouse: Optional[bool] = Field(default=None, description="If true, enable all engines @ max power")
    task_power: Optional[Dict[str, int]] = Field(default=None, description="Per-task power 0-100 for scanner/graph/risk/ai")

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Vulnerability(BaseModel):
    id: str = Field(default_factory=lambda: f"VULN-{uuid.uuid4().hex[:8].upper()}")
    title: str
    severity: Severity
    cvss: float = Field(..., ge=0, le=10)
    cwe: Optional[str] = None
    cve: Optional[str] = None
    owasp: Optional[str] = None
    mitre_technique: Optional[str] = None
    url: Optional[str] = None
    param: Optional[str] = None
    evidence: Optional[str] = None
    description: str
    impact: str
    remediation: str
    remediation_code: Optional[str] = None
    confidence: float = Field(0.85, ge=0, le=1)
    exploit_available: bool = False
    epss: float = Field(0.0, ge=0, le=1)
    tags: List[str] = []
    references: List[str] = []

class PortInfo(BaseModel):
    port: int
    state: Literal["open","closed","filtered"]
    service: str
    version: Optional[str] = None
    banner: Optional[str] = None
    cpe: Optional[str] = None

class Technology(BaseModel):
    name: str
    version: Optional[str] = None
    confidence: float = 0.9
    category: str = "framework"

class ScanFinding(BaseModel):
    category: str
    key: str
    value: Any
    severity: Severity = Severity.INFO

class ScanResult(BaseModel):
    job_id: str
    target: str
    mode: ScanMode
    status: Literal["queued","running","completed","failed","cancelled"] = "queued"
    progress: int = 0
    current_stage: str = "Initializing"
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    technologies: List[Technology] = []
    ports: List[PortInfo] = []
    subdomains: List[str] = []
    directories: List[str] = []
    vulnerabilities: List[Vulnerability] = []
    findings: List[ScanFinding] = []
    headers_analysis: Dict[str, Any] = {}
    tls_analysis: Dict[str, Any] = {}
    summary: Dict[str, Any] = {}
    logs: List[str] = []

class GraphNode(BaseModel):
    id: str
    label: str
    type: Literal["entry","host","service","vulnerability","privilege","data","user","external"]
    severity: Optional[Severity] = None
    cvss: Optional[float] = None
    properties: Dict[str, Any] = {}
    x: Optional[float] = None
    y: Optional[float] = None

class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: str
    type: Literal["exploits","accesses","escalates","lateral","exfiltrates"]
    weight: float = Field(1.0, ge=0, le=10)
    exploitability: float = Field(0.5, ge=0, le=1)
    description: Optional[str] = None

class AttackGraph(BaseModel):
    graph_id: str
    job_id: str
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    paths: List[List[str]] = []
    critical_paths: List[Dict[str, Any]] = []
    metrics: Dict[str, Any] = {}

class RiskAnalysisRequest(BaseModel):
    job_id: Optional[str] = None
    graph_id: Optional[str] = None
    business_context: Optional[Dict[str, Any]] = None

class RiskAnalysisResult(BaseModel):
    analysis_id: str
    job_id: Optional[str] = None
    graph_id: Optional[str] = None
    overall_risk_score: float
    risk_level: Literal["critical","high","medium","low","minimal"]
    exposure_score: float
    financial_impact_usd: Dict[str, float]
    compliance: Dict[str, Any]
    node_criticality: List[Dict[str, Any]]
    path_risks: List[Dict[str, Any]]
    monte_carlo: Dict[str, Any]
    recommendations: List[Dict[str, Any]]
    generated_at: datetime = Field(default_factory=datetime.utcnow)

class AIExplainRequest(BaseModel):
    vuln_id: Optional[str] = None
    graph_id: Optional[str] = None
    job_id: Optional[str] = None
    question: Optional[str] = None

class ExportRequest(BaseModel):
    format: Literal["json","csv","pdf","html","sarif"] = "json"
    include_graph: bool = True
    include_risk: bool = True
