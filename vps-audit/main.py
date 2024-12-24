from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
import logging
import uvicorn
from typing import Optional
from pydantic import BaseModel

from database import SessionLocal, engine
from models import Base, VPSServer, AuditResult
from audit_runner import AuditRunner, AuditError  # Import AuditError
from app_logger import setup_logger

# Setup logging
logger = setup_logger(__name__)

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ServerCreate(BaseModel):
    name: str
    ip_address: str
    ssh_username: str
    sshPassword: Optional[str] = None
    ssh_key_path: Optional[str] = None

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.post("/servers")
async def create_server(request: Request):
    body = await request.json()
    logger.info(f"Received request body: {body}")
    
    # Debug log for password fields
    logger.info(f"Password field values:")
    logger.info(f"  sshPassword: {body.get('sshPassword')}")
    logger.info(f"  ssh_password: {body.get('ssh_password')}")

    server_id = body.get("id")
    db = SessionLocal()
    try:
        if server_id:
            db_server = db.query(VPSServer).filter(VPSServer.id == server_id).first()
            if db_server:
                db_server.name = body.get("name")
                db_server.ip_address = body.get("ip_address")
                db_server.ssh_username = body.get("ssh_username")
                db_server.sshPassword = body.get("sshPassword")  # Match frontend field name
                db_server.ssh_key_path = body.get("ssh_key_path")
                db.commit()
                db.refresh(db_server)
                return {
                    "id": db_server.id,
                    "name": db_server.name,
                    "ip_address": db_server.ip_address,
                    "ssh_username": db_server.ssh_username,
                    "ssh_key_path": db_server.ssh_key_path
                }
            else:
                raise HTTPException(status_code=404, detail=f"Server with ID {server_id} not found")
        else:
            db_server = VPSServer(
                name=body.get("name"),
                ip_address=body.get("ip_address"),
                ssh_username=body.get("ssh_username"),
                sshPassword=body.get("sshPassword"),  # Match frontend field name
                ssh_key_path=body.get("ssh_key_path")
            )
            db.add(db_server)
            db.commit()
            db.refresh(db_server)
            return {
                "id": db_server.id,
                "name": db_server.name,
                "ip_address": db_server.ip_address,
                "ssh_username": db_server.ssh_username,
                "ssh_key_path": db_server.ssh_key_path
            }
    finally:
        db.close()
    
    

@app.get("/servers")
def get_servers():
    db = SessionLocal()
    try:
        servers = db.query(VPSServer).all()
        return [{
            "id": server.id,
            "name": server.name,
            "ip_address": server.ip_address,
            "ssh_username": server.ssh_username,
            "ssh_key_path": server.ssh_key_path
        } for server in servers]
    finally:
        db.close()

@app.get("/servers/{server_id}")
def get_server(server_id: int):
    db = SessionLocal()
    try:
        server = db.query(VPSServer).filter(VPSServer.id == server_id).first()
        if server is None:
            raise HTTPException(status_code=404, detail="Server not found")
        return {
            "id": server.id,
            "name": server.name,
            "ip_address": server.ip_address,
            "ssh_username": server.ssh_username,
            "ssh_key_path": server.ssh_key_path
        }
    finally:
        db.close()

@app.post("/servers/{server_id}/audit")
async def start_audit(server_id: int):
    try:
        audit_runner = AuditRunner()
        result_data = await audit_runner.run_audit(server_id)
        return result_data
        
    except AuditError as e:
        logger.error(f"Audit error for server {server_id}: {str(e)}")
        error_message = str(e)
        
        # Map different error types to appropriate HTTP status codes
        if "Authentication failed" in error_message:
            status_code = 401  # Unauthorized
        elif "SSH key error" in error_message:
            status_code = 400  # Bad Request
        elif "Connection failed" in error_message:
            status_code = 503  # Service Unavailable
        elif "Host key verification failed" in error_message:
            status_code = 400  # Bad Request
        elif "Server not found" in error_message:
            status_code = 404  # Not Found
        else:
            status_code = 500  # Internal Server Error
            
        raise HTTPException(
            status_code=status_code,
            detail={
                "error": error_message,
                "error_type": e.__class__.__name__
            }
        )
        
    except Exception as e:
        logger.error(f"Unexpected error during audit: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail={
                "error": "An unexpected error occurred during the audit",
                "error_type": "UnexpectedError"
            }
        )

@app.get("/servers/{server_id}/audits")
def get_server_audits(server_id: int):
    db = SessionLocal()
    try:
        # First check if server exists
        server = db.query(VPSServer).filter(VPSServer.id == server_id).first()
        if server is None:
            raise HTTPException(status_code=404, detail="Server not found")
            
        # Get audit history for the server
        audits = db.query(AuditResult).filter(
            AuditResult.server_id == server_id
        ).order_by(AuditResult.timestamp.desc()).all()
        
        return [{
            "id": audit.id,
            "timestamp": audit.timestamp,
            "results": audit.results
        } for audit in audits]
    finally:
        db.close()

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)