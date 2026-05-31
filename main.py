from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional

from services.port_scanner import PortScannerService
from services.hash_cracker import HashCrackerService, PasswordStrengthService
from services.dns_lookup import DnsLookupService
from services.whois_lookup import WhoisLookupService
from services.header_analyzer import HeaderAnalyzerService

app = FastAPI(
    title="Cybersecurity Toolkit Hub API",
    description="Educational API endpoints for cybersecurity audits, decoding, encoding, and packet simulations.",
    version="1.0.0"
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- PORT SCANNER MODELS & ENDPOINTS ---
class PortScanRequest(BaseModel):
    host: str = Field(..., examples=["127.0.0.1"])
    ports: List[int] = Field(default=[21, 22, 80, 443, 3306], examples=[[80, 443]])

@app.post("/api/port-scanner/scan")
def run_port_scan(payload: PortScanRequest):
    return {
        "host": payload.host,
        "results": PortScannerService.scan_local_ports(payload.host, payload.ports)
    }

@app.get("/api/port-scanner/simulate")
def get_scan_simulation(
    host: str = Query(..., examples=["google.com"]),
    scan_type: str = Query("SYN", pattern="^(SYN|CONNECT|FIN)$"),
    port: int = Query(80, ge=1, le=65535)
):
    return PortScannerService.get_educational_simulation(host, scan_type, port)


# --- HASH GENERATOR & CRACKER MODELS & ENDPOINTS ---
class HashGenRequest(BaseModel):
    text: str
    algorithm: str = Field("sha256", pattern="^(md5|sha1|sha256|sha512)$")

@app.post("/api/hash/generate")
def generate_hash(payload: HashGenRequest):
    try:
        h = HashCrackerService.generate_hash(payload.text, payload.algorithm)
        return {"hash": h, "algorithm": payload.algorithm}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

class HashCrackRequest(BaseModel):
    hash: str
    algorithm: str = Field("sha256", pattern="^(md5|sha1|sha256|sha512)$")
    custom_words: Optional[List[str]] = None

@app.post("/api/hash/crack")
def crack_hash(payload: HashCrackRequest):
    return HashCrackerService.crack_hash_demo(payload.hash, payload.algorithm, payload.custom_words)


# --- PASSWORD STRENGTH ENDPOINTS ---
class PasswordCheckRequest(BaseModel):
    password: str

@app.post("/api/password/check")
def check_password(payload: PasswordCheckRequest):
    return PasswordStrengthService.analyze_password(payload.password)


# --- SUBDOMAIN & DNS LOOKUP ENDPOINTS ---
@app.get("/api/dns/lookup")
def dns_lookup(domain: str = Query(..., examples=["example.com"])):
    if not DnsLookupService.is_valid_domain(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")
    return DnsLookupService.query_dns_records(domain)

@app.get("/api/dns/subdomains")
def dns_subdomains(domain: str = Query(..., examples=["example.com"])):
    if not DnsLookupService.is_valid_domain(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")
    return {
        "domain": domain,
        "subdomains": DnsLookupService.discover_subdomains_demo(domain)
    }


# --- WHOIS LOOKUP ENDPOINTS ---
@app.get("/api/whois")
def whois_lookup(domain: str = Query(..., examples=["example.com"])):
    if not WhoisLookupService.is_valid_domain(domain):
        raise HTTPException(status_code=400, detail="Invalid domain format")
    return WhoisLookupService.lookup(domain)


# --- HEADER ANALYZER ENDPOINTS ---
@app.get("/api/headers/analyze")
def analyze_headers(url: str = Query(..., examples=["example.com"])):
    result = HeaderAnalyzerService.analyze_headers(url)
    if not result.get("success", True):
        raise HTTPException(status_code=400, detail=result.get("error"))
    return result


# --- API BASE CHECK ---
@app.get("/")
def read_root():
    return {"message": "Welcome to Cybersecurity Toolkit Hub API", "status": "online"}
