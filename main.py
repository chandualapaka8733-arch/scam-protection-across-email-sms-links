import os
import uvicorn
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Optional

from backend.detector import PhishDetector
import backend.database as db

app = FastAPI(title="Phish Hunter AI API")
detector = PhishDetector()

# Initialize DB on start
@app.on_event("startup")
async def startup_event():
    db.init_db()

# Models
class EmailScanRequest(BaseModel):
    sender: str
    subject: str
    body: str

class SMSScanRequest(BaseModel):
    message: str

class URLScanRequest(BaseModel):
    url: str

# Endpoints
@app.post("/analyze-email")
async def analyze_email(req: EmailScanRequest):
    # Combine sender, subject, body for a deep search
    full_text = f"From: {req.sender}\nSubject: {req.subject}\n\n{req.body}"
    result = detector.analyze_text(full_text, mode="email")
    
    # Persistence
    input_summary = f"{req.sender} | {req.subject[:30]}..."
    db.save_scan("Email", input_summary, result["risk"], result["score"], result["flags"])
    
    return result

@app.post("/analyze-sms")
async def analyze_sms(req: SMSScanRequest):
    result = detector.analyze_text(req.message, mode="sms")
    
    # Persistence
    input_summary = req.message[:50] + "..."
    db.save_scan("SMS", input_summary, result["risk"], result["score"], result["flags"])
    
    return result

@app.post("/check-url")
async def check_url(req: URLScanRequest):
    result = detector.analyze_url(req.url)
    
    # Check blocklist
    if db.is_blocked(result.get("domain", "")):
        result["risk"] = "High"
        result["score"] = 100
        result["flags"].insert(0, "🛡️ Admin Blocklist: This domain is explicitly blocked by the administrator.")
    
    # Persistence
    db.save_scan("URL", req.url, result["risk"], result["score"], result["flags"])
    
    return result

@app.get("/dashboard-stats")
async def get_dashboard_stats():
    stats = db.get_stats()
    top_domains = db.get_top_domains()
    return {
        "stats": stats,
        "top_domains": top_domains
    }

@app.post("/admin/blocklist")
async def add_blocked_domain(domain: str):
    db.add_to_blocklist(domain)
    return {"status": "success", "message": f"Domain {domain} added to blocklist"}

# Serve Frontend
@app.get("/", response_class=HTMLResponse)
async def read_index():
    index_path = os.path.join("frontend", "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "Frontend not found. Please build frontend/index.html"

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
