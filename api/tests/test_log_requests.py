import pytest
from pydantic import BaseModel
from typing import Dict, Any

# Copy the relevant classes from main.py to avoid importing the whole FastAPI app
class CreateLogRequest(BaseModel):
    source: str
    message: str
    level: str = "INFO"
    log_metadata: Dict[str, Any] = {}

class FlexibleLogRequest(BaseModel):
    __root__: Dict[str, Any]
    
    def to_standard_format(self) -> CreateLogRequest:
        """Convert to standard CreateLogRequest format"""
        data = self.__root__
        
        # Extract source, defaulting to a value if not present
        source = data.get("source", "unknown")
        
        # Extract message, looking in various possible locations
        message = data.get("message", None)
        if message is None:
            # Try to find message in other common fields
            for field in ["msg", "log", "MESSAGE", "message_text"]:
                if field in data:
                    message = data[field]
                    break
            
            # If still not found, use a default
            if message is None:
                message = "No message content"
        
        # Extract level, defaulting to INFO
        level = data.get("level", "INFO")
        
        # Everything else goes into log_metadata
        log_metadata = {}
        for k, v in data.items():
            if k not in ["source", "message", "level"]:
                log_metadata[k] = v
        
        return CreateLogRequest(
            source=source,
            message=message,
            level=level,
            log_metadata=log_metadata
        )

def test_flexible_log_request_standard_format():
    """Test FlexibleLogRequest with standard format input"""
    input_data = {
        "source": "test_source",
        "message": "test message",
        "level": "INFO"
    }
    
    flexible_log = FlexibleLogRequest(__root__=input_data)
    result = flexible_log.to_standard_format()
    
    assert isinstance(result, CreateLogRequest)
    assert result.source == "test_source"
    assert result.message == "test message"
    assert result.level == "INFO"
    assert result.log_metadata == {}

def test_flexible_log_request_alternative_message_field():
    """Test FlexibleLogRequest with alternative message field names"""
    input_data = {
        "source": "test_source",
        "msg": "test message via msg field",
        "level": "WARN"
    }
    
    flexible_log = FlexibleLogRequest(__root__=input_data)
    result = flexible_log.to_standard_format()
    
    assert result.source == "test_source"
    assert result.message == "test message via msg field"
    assert result.level == "WARN"

def test_flexible_log_request_with_metadata():
    """Test FlexibleLogRequest with additional metadata fields"""
    input_data = {
        "source": "test_source",
        "message": "test message",
        "level": "ERROR",
        "timestamp": "2024-03-20T10:00:00Z",
        "user_id": 123,
        "custom_field": "custom value"
    }
    
    flexible_log = FlexibleLogRequest(__root__=input_data)
    result = flexible_log.to_standard_format()
    
    assert result.source == "test_source"
    assert result.message == "test message"
    assert result.level == "ERROR"
    assert result.log_metadata == {
        "timestamp": "2024-03-20T10:00:00Z",
        "user_id": 123,
        "custom_field": "custom value"
    }

def test_flexible_log_request_missing_fields():
    """Test FlexibleLogRequest with missing fields"""
    input_data = {
        "some_field": "some value"
    }
    
    flexible_log = FlexibleLogRequest(__root__=input_data)
    result = flexible_log.to_standard_format()
    
    assert result.source == "unknown"
    assert result.message == "No message content"
    assert result.level == "INFO"
    assert result.log_metadata == {"some_field": "some value"}

def test_flexible_log_request_empty_input():
    """Test FlexibleLogRequest with empty input"""
    input_data = {}
    
    flexible_log = FlexibleLogRequest(__root__=input_data)
    result = flexible_log.to_standard_format()
    
    assert result.source == "unknown"
    assert result.message == "No message content"
    assert result.level == "INFO"
    assert result.log_metadata == {}