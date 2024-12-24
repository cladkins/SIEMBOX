import logging
import re
from datetime import datetime
from typing import Dict, Optional, List, Tuple

from database import SessionLocal
from models import VPSServer, AuditResult
from ssh_manager import (
    SSHManager,
    SSHError,
    SSHAuthenticationError,
    SSHKeyError,
    SSHConnectionError,
    SSHHostKeyError
)

logger = logging.getLogger(__name__)

class AuditError(Exception):
    """Base class for audit-related errors"""
    pass

class AuditRunner:
    def __init__(self):
        self.ssh_manager = SSHManager()

    def parse_audit_results(self, raw_results: Dict[str, str]) -> Dict[str, Dict]:
        """
        Parse raw audit results in the container
        """
        parsed_results = {}
        
        try:
            # Parse OS Information
            if 'os_info' in raw_results:
                os_lines = raw_results['os_info'].split('\n')
                parsed_results['os_info'] = {
                    'kernel': os_lines[0] if os_lines else 'Unknown',
                    'distribution': '\n'.join(os_lines[1:]) if len(os_lines) > 1 else 'Unknown'
                }

            # Parse Users Information
            if 'users' in raw_results:
                users_lines = raw_results['users'].split('\n')
                parsed_results['users'] = {
                    'system_users': [line.split(':')[0] for line in users_lines if ':' in line],
                    'sudo_users': users_lines[-1] if users_lines else 'No sudo users found'
                }

            # Parse Network Information
            if 'network' in raw_results:
                network_lines = raw_results['network'].split('\n')
                open_ports = []
                for line in network_lines:
                    if 'LISTEN' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            port = parts[3].split(':')[-1]
                            protocol = 'tcp' if 'tcp' in line.lower() else 'udp'
                            open_ports.append({'port': port, 'protocol': protocol})
                parsed_results['network'] = {'open_ports': open_ports}

            # Parse Services Information
            if 'services' in raw_results:
                services_lines = raw_results['services'].split('\n')
                running_services = []
                for line in services_lines:
                    if 'running' in line.lower():
                        service = line.split()[0]
                        running_services.append(service)
                parsed_results['services'] = {'running_services': running_services}

            # Parse File Permissions
            if 'file_permissions' in raw_results:
                perms_lines = raw_results['file_permissions'].split('\n')
                permissions = {}
                for line in perms_lines:
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 9:
                            file_name = parts[-1]
                            perms = parts[0]
                            permissions[file_name] = perms
                parsed_results['file_permissions'] = {'permissions': permissions}

            # Parse Last Logins
            if 'last_logins' in raw_results:
                parsed_results['last_logins'] = {
                    'entries': [line for line in raw_results['last_logins'].split('\n') if line.strip()]
                }

            # Parse System Logs
            if 'system_logs' in raw_results:
                parsed_results['system_logs'] = {
                    'entries': [line for line in raw_results['system_logs'].split('\n') if line.strip()]
                }

        except Exception as e:
            logger.error(f"Error parsing audit results: {str(e)}")
            raise Exception(f"Failed to parse audit results: {str(e)}")

        return parsed_results

    async def run_audit(self, server_id: int) -> AuditResult:
        db = SessionLocal()
        try:
            server = db.query(VPSServer).filter(VPSServer.id == server_id).first()
            if not server:
                raise AuditError(f"Server with ID {server_id} not found")

            # Detailed debug logging for server object
            logger.info("Server object details from database:")
            logger.info(f"  ID: {server.id}")
            logger.info(f"  Name: {server.name}")
            logger.info(f"  IP: {server.ip_address}")
            logger.info(f"  Username: {server.ssh_username}")
            logger.info(f"  SSH Key Path: {server.ssh_key_path!r}")
            logger.info(f"  Password attribute exists: {'sshPassword' in dir(server)}")
            logger.info(f"  Password value type: {type(server.sshPassword).__name__}")
            logger.info(f"  Password is None: {server.sshPassword is None}")
            logger.info(f"  Password bool value: {bool(server.sshPassword)}")
            if server.sshPassword:
                logger.info(f"  Password Length: {len(server.sshPassword)}")

            logger.info(f"Starting audit for server {server.name} ({server.ip_address})")

            # Validate server configuration
            if not server.ssh_username:
                raise AuditError("SSH username not configured")
            if not server.ssh_key_path and not server.sshPassword:
                logger.error(f"Authentication validation failed:")
                logger.error(f"  ssh_key_path: {bool(server.ssh_key_path)}")
                logger.error(f"  sshPassword: {bool(server.sshPassword)}")
                raise AuditError("No authentication method configured - need either SSH key or password")

            try:
                # Connect to the server
                if server.ssh_key_path:
                    logger.info(f"Attempting key-based authentication for {server.name}")
                    self.ssh_manager.connect(
                        hostname=server.ip_address,
                        username=server.ssh_username,
                        key_path=server.ssh_key_path,
                        timeout=10
                    )
                else:
                    logger.info(f"Attempting password authentication for {server.name}")
                    self.ssh_manager.connect(
                        hostname=server.ip_address,
                        username=server.ssh_username,
                        password=server.sshPassword,
                        timeout=10
                    )
            except SSHAuthenticationError as e:
                raise AuditError(f"Authentication failed: {str(e)}")
            except SSHKeyError as e:
                raise AuditError(f"SSH key error: {str(e)}")
            except SSHConnectionError as e:
                raise AuditError(f"Connection failed: {str(e)}")
            except SSHHostKeyError as e:
                raise AuditError(f"Host key verification failed: {str(e)}")
            except SSHError as e:
                raise AuditError(f"SSH error: {str(e)}")
            # Download and validate the audit script locally
            import requests
            script_url = "https://raw.githubusercontent.com/vernu/vps-audit/main/vps-audit.sh"
            
            try:
                logger.info(f"Downloading audit script from {script_url}")
                response = requests.get(script_url)
                response.raise_for_status()  # Raises HTTPError for bad responses
                
                script_content = response.text
                if not script_content.strip() or "404: Not Found" in script_content:
                    raise AuditError("Downloaded script is empty or not found")
                
                if "#!/bin/bash" not in script_content:
                    raise AuditError("Invalid script format - missing shebang")
                
                # Create script on remote host
                create_script_cmd = f"cat > /tmp/vps_audit.sh << 'EOL'\n{script_content}\nEOL"
                success, output = self.ssh_manager.execute_command(create_script_cmd)
                if not success:
                    raise AuditError(f"Failed to create script on remote host: {output}")
                
                # Make executable
                chmod_command = "chmod +x /tmp/vps_audit.sh"
                success, chmod_output = self.ssh_manager.execute_command(chmod_command)
                if not success:
                    raise AuditError(f"Failed to make audit script executable: {chmod_output}")
                
                # Execute script
                success, script_output = self.ssh_manager.execute_command("/tmp/vps_audit.sh")
                if not success:
                    raise AuditError(f"Failed to execute audit script: {script_output}")
                
            except requests.exceptions.RequestException as e:
                raise AuditError(f"Failed to download audit script: {str(e)}")

            # Parse the script output into sections
            sections = {}
            current_section = None
            lines = script_output.split('\n')
            
            for line in lines:
                line = line.strip()
                # Remove ANSI color codes
                line = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', line)
                
                if line.startswith('==='):
                    # New section header
                    current_section = line.strip('= ').lower().replace(' ', '_')
                    sections[current_section] = []
                elif current_section and line:
                    # Add line to current section
                    sections[current_section].append(line)
            
            # Process sections into structured data
            parsed_results = {
                'system_info': {},
                'security_issues': [],
                'warnings': [],
                'summary': {}
            }
            
            # Parse system information
            if 'system_information' in sections:
                for line in sections['system_information']:
                    if 'Hostname:' in line:
                        parsed_results['system_info']['hostname'] = line.split('Hostname:')[-1].strip()
                    elif 'Operating System:' in line:
                        parsed_results['system_info']['os'] = line.split('Operating System:')[-1].strip()
                    elif 'Kernel Version:' in line:
                        parsed_results['system_info']['kernel'] = line.split('Kernel Version:')[-1].strip()
            
            # Extract security issues and warnings
            for line in script_output.split('\n'):
                line = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', line)
                if '[FAIL]' in line:
                    parsed_results['security_issues'].append(line.split('[FAIL]')[-1].strip())
                elif '[WARN]' in line:
                    parsed_results['warnings'].append(line.split('[WARN]')[-1].strip())
            
            # Store parsed results
            audit_result = AuditResult(
                server_id=server_id,
                timestamp=datetime.utcnow(),
                results={
                    'system_info': parsed_results['system_info'],
                    'security_issues': parsed_results['security_issues'],
                    'warnings': parsed_results['warnings'],
                    'raw_output': script_output  # Keep raw output for reference
                }
            )
            db.add(audit_result)
            db.commit()

            # Create result data before closing session
            result_data = {
                "id": audit_result.id,
                "timestamp": audit_result.timestamp,
                "results": audit_result.results
            }
            return result_data

        except Exception as e:
            logger.error(f"Audit failed for server {server_id}: {str(e)}")
            raise

        finally:
            self.ssh_manager.close()
            db.close()