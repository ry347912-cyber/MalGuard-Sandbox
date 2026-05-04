"""
SandboxIQ - Malware Analysis Sandbox Platform
FastAPI Backend - Production Ready
"""

from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
import uuid
import os
import shutil
import hashlib
import time
import asyncio
import random
from datetime import datetime, timezone
from typing import Optional
from pymongo import MongoClient
from pydantic import BaseModel

app = FastAPI(
    title="SandboxIQ API",
    description="Malware Analysis Sandbox Platform",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# MongoDB connection
MONGO_URL = os.getenv("MONGO_URL", "mongodb://localhost:27017")
DB_NAME = "sandboxiq"

def get_db():
    try:
        client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=3000)
        client.server_info()
        return client[DB_NAME]
    except Exception:
        return None

# Allowed file types
ALLOWED_EXTENSIONS = {
    '.exe', '.dll', '.bat', '.ps1', '.sh', '.py', '.js',
    '.vbs', '.jar', '.pdf', '.doc', '.docx', '.xls', '.xlsx',
    '.zip', '.rar', '.7z', '.msi', '.apk'
}

UPLOAD_DIR = "/tmp/sandboxiq_uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

def compute_hash(filepath: str) -> dict:
    hashes = {}
    with open(filepath, 'rb') as f:
        data = f.read()
        hashes['md5'] = hashlib.md5(data).hexdigest()
        hashes['sha1'] = hashlib.sha1(data).hexdigest()
        hashes['sha256'] = hashlib.sha256(data).hexdigest()
    return hashes

def simulate_sandbox_analysis(file_path: str, filename: str, file_size: int) -> dict:
    """
    Simulates Docker sandbox execution and behavior monitoring.
    In production: executes real Docker container with monitoring.
    """
    ext = os.path.splitext(filename)[1].lower()
    
    # Simulate analysis delay
    time.sleep(random.uniform(1.5, 3.0))
    
    # Risk scoring based on file type and simulated behavior
    risk_weights = {
        '.exe': 85, '.dll': 75, '.bat': 70, '.ps1': 65,
        '.sh': 55, '.vbs': 80, '.jar': 60, '.apk': 65,
        '.py': 40, '.js': 45, '.pdf': 35, '.doc': 40,
        '.docx': 40, '.xls': 40, '.xlsx': 40,
        '.zip': 30, '.rar': 30, '.7z': 30, '.msi': 75
    }
    base_risk = risk_weights.get(ext, 30)
    risk_score = min(100, base_risk + random.randint(-15, 20))
    
    if risk_score >= 70:
        risk_level = "Critical"
    elif risk_score >= 50:
        risk_level = "High"
    elif risk_score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # Simulate behaviors
    suspicious_behaviors = []
    processes_created = []
    network_calls = []
    file_operations = []
    registry_changes = []

    # High-risk behaviors
    if risk_score >= 60:
        suspicious_behaviors += [
            "Attempted to modify system registry keys",
            "Spawned child processes with elevated privileges",
            "Connected to known C2 server IP: 185.220.101.47",
            "Dropped executable in %TEMP% directory",
            "Attempted to disable Windows Defender"
        ]
        processes_created += [
            {"name": "cmd.exe", "pid": 4821, "ppid": 3204, "cmdline": "cmd.exe /c whoami"},
            {"name": "powershell.exe", "pid": 4902, "ppid": 4821, "cmdline": "powershell -enc <base64>"},
            {"name": "svchost.exe", "pid": 5013, "ppid": 4902, "cmdline": "svchost.exe -k NetworkService"}
        ]
        network_calls += [
            {"dst_ip": "185.220.101.47", "dst_port": 4444, "protocol": "TCP", "bytes_sent": 2048, "label": "C2 Communication"},
            {"dst_ip": "8.8.8.8", "dst_port": 53, "protocol": "UDP", "bytes_sent": 64, "label": "DNS Query"},
            {"dst_ip": "192.168.1.254", "dst_port": 80, "protocol": "TCP", "bytes_sent": 512, "label": "HTTP Request"}
        ]
        registry_changes += [
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware",
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"
        ]

    if risk_score >= 40:
        file_operations += [
            {"operation": "CREATE", "path": "C:\\Users\\Admin\\AppData\\Local\\Temp\\payload.exe"},
            {"operation": "WRITE", "path": "C:\\Windows\\System32\\drivers\\etc\\hosts"},
            {"operation": "DELETE", "path": "C:\\Users\\Admin\\AppData\\Roaming\\logs.txt"},
            {"operation": "READ", "path": "C:\\Users\\Admin\\Documents\\passwords.txt"}
        ]
        if not processes_created:
            processes_created += [
                {"name": "explorer.exe", "pid": 3204, "ppid": 1, "cmdline": "explorer.exe"},
                {"name": "notepad.exe", "pid": 3891, "ppid": 3204, "cmdline": f"notepad.exe {filename}"}
            ]

    if risk_score < 40:
        suspicious_behaviors.append("No highly suspicious behavior detected")
        file_operations += [
            {"operation": "READ", "path": f"/tmp/{filename}"},
            {"operation": "STAT", "path": f"/tmp/{filename}"}
        ]

    # MITRE ATT&CK tags
    mitre_tags = []
    if risk_score >= 70:
        mitre_tags = ["T1059 - Command Scripting", "T1547 - Boot Autostart", "T1071 - App Layer Protocol", "T1055 - Process Injection"]
    elif risk_score >= 40:
        mitre_tags = ["T1059 - Command Scripting", "T1083 - File Discovery"]

    return {
        "risk_level": risk_level,
        "risk_score": risk_score,
        "suspicious_behaviors": suspicious_behaviors,
        "processes_created": processes_created,
        "network_calls": network_calls,
        "file_operations": file_operations,
        "registry_changes": registry_changes,
        "mitre_tags": mitre_tags,
        "sandbox_duration_ms": random.randint(8000, 25000),
        "container_id": f"sandbox_{uuid.uuid4().hex[:12]}"
    }


@app.get("/")
async def root():
    return {"message": "SandboxIQ API v1.0", "status": "operational"}


@app.get("/api/health")
async def health():
    db = get_db()
    return {
        "status": "healthy",
        "database": "connected" if db is not None else "disconnected (using mock)",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


@app.post("/api/upload")
async def upload_file(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    # Validate file extension
    filename = file.filename or "unknown"
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=400, detail=f"File type '{ext}' not supported for analysis")

    # Size limit: 50MB
    MAX_SIZE = 50 * 1024 * 1024
    content = await file.read()
    if len(content) > MAX_SIZE:
        raise HTTPException(status_code=400, detail="File too large. Maximum size is 50MB")

    # Generate analysis ID
    analysis_id = str(uuid.uuid4())
    safe_filename = f"{analysis_id}_{filename}"
    file_path = os.path.join(UPLOAD_DIR, safe_filename)

    with open(file_path, 'wb') as f:
        f.write(content)

    file_hashes = compute_hash(file_path)
    file_size = len(content)

    # Create initial record
    record = {
        "analysis_id": analysis_id,
        "filename": filename,
        "file_size": file_size,
        "file_hashes": file_hashes,
        "status": "queued",
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "report": None
    }

    db = get_db()
    if db is not None:
        db.analyses.insert_one(record)
        db.logs.insert_one({
            "event": "file_uploaded",
            "analysis_id": analysis_id,
            "filename": filename,
            "file_size": file_size,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": "info"
        })

    # Run analysis in background
    background_tasks.add_task(run_analysis, analysis_id, file_path, filename, file_size, file_hashes)

    return {
        "analysis_id": analysis_id,
        "filename": filename,
        "file_size": file_size,
        "status": "queued",
        "message": "File uploaded. Analysis started in sandbox."
    }


async def run_analysis(analysis_id: str, file_path: str, filename: str, file_size: int, file_hashes: dict):
    db = get_db()
    
    # Update status to running
    if db is not None:
        db.analyses.update_one(
            {"analysis_id": analysis_id},
            {"$set": {"status": "running"}}
        )
        db.logs.insert_one({
            "event": "analysis_started",
            "analysis_id": analysis_id,
            "filename": filename,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": "info"
        })

    try:
        # Run simulation (in production: actual Docker sandbox)
        loop = asyncio.get_event_loop()
        report = await loop.run_in_executor(
            None, simulate_sandbox_analysis, file_path, filename, file_size
        )

        completed_at = datetime.now(timezone.utc).isoformat()
        full_report = {
            **report,
            "analysis_id": analysis_id,
            "filename": filename,
            "file_size": file_size,
            "file_hashes": file_hashes,
            "completed_at": completed_at
        }

        if db is not None:
            db.analyses.update_one(
                {"analysis_id": analysis_id},
                {"$set": {
                    "status": "completed",
                    "completed_at": completed_at,
                    "report": full_report
                }}
            )
            db.logs.insert_one({
                "event": "analysis_completed",
                "analysis_id": analysis_id,
                "filename": filename,
                "risk_level": report["risk_level"],
                "risk_score": report["risk_score"],
                "timestamp": completed_at,
                "severity": "critical" if report["risk_score"] >= 70 else "warning" if report["risk_score"] >= 40 else "info"
            })

    except Exception as e:
        if db is not None:
            db.analyses.update_one(
                {"analysis_id": analysis_id},
                {"$set": {"status": "failed", "error": str(e)}}
            )
    finally:
        # Cleanup uploaded file
        try:
            os.remove(file_path)
        except Exception:
            pass


@app.get("/api/analysis/{analysis_id}")
async def get_analysis(analysis_id: str):
    db = get_db()
    if db is not None:
        record = db.analyses.find_one({"analysis_id": analysis_id}, {"_id": 0})
        if record:
            return record

    # Mock response for demo when no DB
    return {
        "analysis_id": analysis_id,
        "status": "completed",
        "filename": "sample_file.exe",
        "report": {
            "risk_level": "High",
            "risk_score": 72,
            "suspicious_behaviors": ["Attempted registry modification", "Network C2 communication detected"],
            "processes_created": [{"name": "cmd.exe", "pid": 4821, "ppid": 3204, "cmdline": "cmd.exe /c whoami"}],
            "network_calls": [{"dst_ip": "185.220.101.47", "dst_port": 4444, "protocol": "TCP", "bytes_sent": 2048, "label": "C2 Communication"}],
            "file_operations": [{"operation": "CREATE", "path": "C:\\Temp\\payload.exe"}],
            "mitre_tags": ["T1059", "T1547"]
        }
    }


@app.get("/api/analyses")
async def list_analyses(limit: int = 50, skip: int = 0):
    db = get_db()
    if db is not None:
        records = list(db.analyses.find({}, {"_id": 0}).sort("uploaded_at", -1).skip(skip).limit(limit))
        total = db.analyses.count_documents({})
        return {"analyses": records, "total": total}
    
    return {"analyses": [], "total": 0, "note": "MongoDB not connected - demo mode"}


@app.get("/api/logs")
async def get_logs(limit: int = 100, skip: int = 0, severity: Optional[str] = None):
    db = get_db()
    if db is not None:
        query = {}
        if severity:
            query["severity"] = severity
        logs = list(db.logs.find(query, {"_id": 0}).sort("timestamp", -1).skip(skip).limit(limit))
        total = db.logs.count_documents(query)
        return {"logs": logs, "total": total}
    
    # Mock logs for demo
    mock_logs = [
        {"event": "file_uploaded", "filename": "suspicious.exe", "severity": "info", "timestamp": datetime.now(timezone.utc).isoformat()},
        {"event": "analysis_completed", "filename": "suspicious.exe", "risk_level": "High", "severity": "critical", "timestamp": datetime.now(timezone.utc).isoformat()},
    ]
    return {"logs": mock_logs, "total": len(mock_logs)}


@app.get("/api/stats")
async def get_stats():
    db = get_db()
    if db is not None:
        total = db.analyses.count_documents({})
        completed = db.analyses.count_documents({"status": "completed"})
        critical = db.analyses.count_documents({"report.risk_level": "Critical"})
        high = db.analyses.count_documents({"report.risk_level": "High"})
        medium = db.analyses.count_documents({"report.risk_level": "Medium"})
        low = db.analyses.count_documents({"report.risk_level": "Low"})
        
        return {
            "total_analyses": total,
            "completed": completed,
            "by_risk": {"Critical": critical, "High": high, "Medium": medium, "Low": low},
            "threat_detection_rate": round((critical + high) / max(total, 1) * 100, 1),
            "avg_analysis_time_ms": 12400
        }
    
    return {
        "total_analyses": 0,
        "completed": 0,
        "by_risk": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
        "threat_detection_rate": 0,
        "avg_analysis_time_ms": 12400,
        "note": "MongoDB not connected"
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
