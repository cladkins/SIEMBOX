import paramiko
import logging
import os
import socket
from typing import Tuple, Optional

logger = logging.getLogger(__name__)

class SSHError(Exception):
    """Base class for SSH-related errors"""
    pass

class SSHAuthenticationError(SSHError):
    """Raised when authentication fails"""
    pass

class SSHKeyError(SSHError):
    """Raised when there are issues with SSH keys"""
    pass

class SSHConnectionError(SSHError):
    """Raised when connection fails"""
    pass

class SSHHostKeyError(SSHError):
    """Raised when there are host key verification issues"""
    pass

class SSHManager:
    def __init__(self):
        self.client = None

    def validate_key_file(self, key_path: str) -> Tuple[bool, Optional[str]]:
        """Validate SSH key file exists and has correct permissions"""
        if not key_path or not key_path.strip():
            return False, "SSH key path is empty"
            
        if not os.path.exists(key_path):
            return False, f"SSH key file not found: {key_path}"
            
        try:
            # Try to load the key to validate format
            paramiko.RSAKey.from_private_key_file(key_path)
            return True, None
        except paramiko.ssh_exception.PasswordRequiredException:
            # Key is valid but encrypted
            return True, None
        except Exception as e:
            return False, f"Invalid SSH key file: {str(e)}"

    def connect(self, hostname: str, username: str, password: Optional[str] = None,
                key_path: Optional[str] = None, timeout: int = 10) -> bool:
        """
        Connect to remote host via SSH with detailed error handling
        """
        try:
            self.client = paramiko.SSHClient()
            
            # TODO: In production, implement proper host key verification
            # For now, automatically accept new host keys
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            logger.info(f"Initiating SSH connection to {hostname} as {username}")
            
            if key_path and key_path.strip():
                # Validate key file before attempting connection
                valid, error = self.validate_key_file(key_path)
                if not valid:
                    raise SSHKeyError(error)
                
                logger.info(f"Attempting key-based authentication: Host={hostname}, User={username}, KeyPath={key_path}")
                try:
                    self.client.connect(hostname, username=username, key_filename=key_path, timeout=timeout)
                except paramiko.ssh_exception.PasswordRequiredException:
                    raise SSHKeyError("SSH key is encrypted and requires a passphrase")
                    
            else:
                if not password:
                    raise SSHAuthenticationError("No password provided for password authentication")
                
                logger.info(f"Attempting password authentication: Host={hostname}, User={username}, Timeout={timeout}")
                try:
                    self.client.connect(hostname, username=username, password=password, timeout=timeout)
                    # Test connection with a simple command
                    stdin, stdout, stderr = self.client.exec_command('echo "test"')
                    if stdout.channel.recv_exit_status() != 0:
                        raise Exception("Connection test failed")
                    logger.info(f"Successfully connected to {hostname}")
                    return True
                except Exception as e:
                    logger.error(f"Detailed connection error: {str(e)}, Error type: {type(e).__name__}")
                    self.close()  # Clean up failed connection
                    raise
            
        except paramiko.ssh_exception.AuthenticationException as e:
            error_msg = "Authentication failed - Invalid credentials"
            logger.error(f"Authentication error for {hostname}: {str(e)}")
            raise SSHAuthenticationError(error_msg)
            
        except paramiko.ssh_exception.BadHostKeyException as e:
            error_msg = f"Host key verification failed for {hostname}"
            logger.error(f"Host key error: {str(e)}")
            raise SSHHostKeyError(error_msg)
            
        except (paramiko.ssh_exception.NoValidConnectionsError,
                socket.timeout,
                ConnectionError) as e:
            error_msg = f"Failed to connect to {hostname} - Host unreachable or connection timeout"
            logger.error(f"Connection error: {str(e)}")
            raise SSHConnectionError(error_msg)
            
        except SSHError:
            # Re-raise our custom errors
            raise
            
        except Exception as e:
            error_msg = f"Unexpected SSH error: {str(e)}"
            logger.error(error_msg)
            raise SSHError(error_msg)

    def execute_command(self, command):
        """Execute a command over SSH with proper error handling"""
        if not self.client:
            logger.error("Attempted to execute command without connection")
            return False, "Not connected to server"
        
        try:
            # Test connection before executing command
            try:
                transport = self.client.get_transport()
                if not transport or not transport.is_active():
                    logger.error("SSH connection is not active")
                    self.close()
                    return False, "SSH connection lost"
            except Exception as e:
                logger.error(f"Failed to check connection state: {str(e)}")
                self.close()
                return False, "SSH connection error"

            # Execute command
            logger.info(f"Executing command: {command}")
            stdin, stdout, stderr = self.client.exec_command(command)
            
            # Get both stdout and stderr
            out = stdout.read().decode()
            err = stderr.read().decode()
            
            exit_status = stdout.channel.recv_exit_status()
            if exit_status != 0:
                logger.error(f"Command failed with exit status {exit_status}: {err}")
                return False, f"Command failed: {err}"
                
            return True, out
            
        except Exception as e:
            logger.error(f"Command execution failed: {str(e)}")
            self.close()  # Clean up on error
            return False, str(e)

    def close(self):
        """Properly close the SSH connection and clean up"""
        try:
            if self.client:
                transport = self.client.get_transport()
                if transport and transport.is_active():
                    logger.info("Closing active SSH connection")
                    transport.close()
                self.client.close()
                logger.info("SSH connection closed")
        except Exception as e:
            logger.error(f"Error closing SSH connection: {str(e)}")
        finally:
            self.client = None