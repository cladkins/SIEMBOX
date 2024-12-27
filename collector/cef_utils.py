import re
from datetime import datetime
from typing import Dict, Any, Optional, Tuple

class CEFParser:
    """Parser for Common Event Format (CEF) logs"""
    
    # CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    CEF_REGEX = r'^CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$'
    
    @staticmethod
    def parse_extensions(extension_str: str) -> Dict[str, str]:
        """Parse CEF extension fields."""
        extensions = {}
        current_key = ''
        current_value = ''
        in_value = False
        
        for char in extension_str:
            if char == '=' and not in_value:
                current_key = current_key.strip()
                in_value = True
            elif char == ' ' and in_value:
                if current_key and current_value:
                    extensions[current_key] = current_value
                current_key = ''
                current_value = ''
                in_value = False
            elif in_value:
                current_value += char
            else:
                current_key += char
        
        # Add the last key-value pair if exists
        if current_key and current_value:
            extensions[current_key] = current_value
            
        return extensions

    @staticmethod
    def parse(log_str: str) -> Optional[Dict[str, Any]]:
        """Parse a CEF formatted log string into a dictionary."""
        try:
            match = re.match(CEFParser.CEF_REGEX, log_str)
            if not match:
                return None
                
            version, vendor, product, dev_version, sig_id, name, severity, extension_str = match.groups()
            
            # Parse extensions
            extensions = CEFParser.parse_extensions(extension_str)
            
            # Create standardized log structure
            return {
                'cef_version': version,
                'device_vendor': vendor,
                'device_product': product,
                'device_version': dev_version,
                'signature_id': sig_id,
                'name': name,
                'severity': severity,
                'extensions': extensions,
                # Add standard fields used by the system
                'source': f"{vendor}:{product}",
                'timestamp': extensions.get('rt', datetime.now().isoformat()),
                'level': CEFParser.map_severity_to_level(severity),
                'message': name
            }
        except Exception as e:
            print(f"Error parsing CEF log: {str(e)}")
            return None

    @staticmethod
    def map_severity_to_level(severity: str) -> str:
        """Map CEF severity (0-10) to log level."""
        try:
            severity_int = int(severity)
            if severity_int <= 3:
                return "INFO"
            elif severity_int <= 6:
                return "WARNING"
            elif severity_int <= 8:
                return "ERROR"
            else:
                return "CRITICAL"
        except ValueError:
            return "INFO"

class CEFFormatter:
    """Formatter for Common Event Format (CEF) logs"""
    
    @staticmethod
    def format(log_data: Dict[str, Any]) -> str:
        """Format a log dictionary into CEF format."""
        # Extract or default required CEF fields
        cef_version = "0"
        device_vendor = log_data.get('device_vendor', 'SIEMBox')
        device_product = log_data.get('device_product', 'Collector')
        device_version = log_data.get('device_version', '1.0')
        signature_id = log_data.get('signature_id', '0')
        name = log_data.get('name', log_data.get('message', 'Unknown Event'))
        severity = log_data.get('severity', '0')
        
        # Build extension string
        extensions = log_data.get('extensions', {})
        if 'timestamp' in log_data and 'rt' not in extensions:
            extensions['rt'] = log_data['timestamp']
        if 'source' in log_data and 'shost' not in extensions:
            extensions['shost'] = log_data['source']
            
        extension_str = ' '.join(f"{k}={v}" for k, v in extensions.items())
        
        # Construct CEF string
        cef_parts = [
            f"CEF:{cef_version}",
            device_vendor,
            device_product,
            device_version,
            signature_id,
            name,
            severity,
            extension_str
        ]
        
        return '|'.join(cef_parts)

    @staticmethod
    def to_cef_severity(level: str) -> str:
        """Convert log level to CEF severity (0-10)."""
        level_map = {
            'DEBUG': '0',
            'INFO': '3',
            'WARNING': '6',
            'ERROR': '8',
            'CRITICAL': '10'
        }
        return level_map.get(level.upper(), '0')

def is_cef_log(log_str: str) -> bool:
    """Check if a log string is in CEF format."""
    return log_str.startswith('CEF:')

def normalize_log(log_data: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize log data to include both CEF and standard fields."""
    if 'cef_version' in log_data:  # Already CEF format
        return log_data
        
    # Convert standard log to CEF format
    normalized = {
        'cef_version': '0',
        'device_vendor': 'SIEMBox',
        'device_product': log_data.get('source', 'Collector'),
        'device_version': '1.0',
        'signature_id': '0',
        'name': log_data.get('message', 'Unknown Event'),
        'severity': CEFFormatter.to_cef_severity(log_data.get('level', 'INFO')),
        'extensions': {
            'rt': log_data.get('timestamp', datetime.now().isoformat()),
            'shost': log_data.get('source', 'unknown'),
            'msg': log_data.get('message', '')
        }
    }
    
    # Add any additional metadata as extensions
    if 'metadata' in log_data:
        for k, v in log_data['metadata'].items():
            if isinstance(v, (str, int, float, bool)):
                normalized['extensions'][k] = str(v)
                
    return normalized