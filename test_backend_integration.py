#!/usr/bin/env python3
"""
Test script for backend integration
Exercises ingestion, detection, notification, and database connectivity in the lightweight architecture.
"""

import sys
import os
import asyncio
import json
from datetime import datetime

# Add the backend directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'backend'))

from app.db.database import get_db
from app.models.logs import ProcessedLog, DetectionRule, Alert
from app.services.detection_service import detection_service
from app.services.notification_service import notification_service
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text

# Test configuration
DATABASE_URL = "postgresql+asyncpg://siembox:siembox@localhost:5432/siembox"

async def test_database_connection():
    """Test database connection"""
    print("🔧 Testing database connection...")
    try:
        engine = create_async_engine(DATABASE_URL, echo=False)
        async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        
        async with async_session() as session:
            result = await session.execute(text("SELECT 1"))
            print("✅ Database connection successful")
            return True
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return False

async def test_processed_log_creation():
    """Test creating processed logs"""
    print("🔧 Testing processed log creation...")
    try:
        engine = create_async_engine(DATABASE_URL, echo=False)
        async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        
        async with async_session() as session:
            # Create a test processed log
            test_log = ProcessedLog(
                cribl_log_id=None,
                timestamp=datetime.utcnow(),
                hostname="test-host",
                source_ip="192.168.1.100",
                app_name="test-app",
                raw_message="Test log message from backend integration test",
                processed_fields={
                    "test_field": "test_value",
                    "severity": "info",
                    "category": "test"
                },
                log_type="test",
                severity="info",
                category="test",
                source="test_backend",
                cribl_pipeline=None
            )
            
            session.add(test_log)
            await session.commit()
            await session.refresh(test_log)
            
            print(f"✅ Created processed log: {test_log.id}")
            return str(test_log.id)
    except Exception as e:
        print(f"❌ Processed log creation failed: {e}")
        return None

async def test_detection_service():
    """Test detection service"""
    print("🔧 Testing detection service...")
    try:
        engine = create_async_engine(DATABASE_URL, echo=False)
        async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        
        async with async_session() as session:
            # Initialize default rules
            created_rules = await detection_service.initialize_default_rules(session)
            print(f"✅ Initialized {created_rules} detection rules")
            
            # Get detection stats
            stats = await detection_service.get_detection_stats(session)
            print(f"✅ Detection stats: {stats['rules']['total']} rules, {stats['alerts']['total']} alerts")
            
            return True
    except Exception as e:
        print(f"❌ Detection service test failed: {e}")
        return False

async def test_notification_service():
    """Test notification service"""
    print("🔧 Testing notification service...")
    try:
        engine = create_async_engine(DATABASE_URL, echo=False)
        async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        
        async with async_session() as session:
            # Get notification stats
            stats = await notification_service.get_notification_stats(session)
            print(f"✅ Notification stats: {stats['total_alerts']} alerts, {stats['notification_rate']:.1f}% notification rate")
            
            # Test configuration status
            config_status = stats['configuration_status']
            for notif_type, status in config_status.items():
                print(f"   {notif_type}: enabled={status['enabled']}, configured={status['configured']}")
            
            return True
    except Exception as e:
        print(f"❌ Notification service test failed: {e}")
        return False

async def test_complete_flow():
    """Test complete log processing flow"""
    print("🔧 Testing complete log processing flow...")
    try:
        engine = create_async_engine(DATABASE_URL, echo=False)
        async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
        
        async with async_session() as session:
            # Create a test log that should trigger a detection rule
            test_log = ProcessedLog(
                cribl_log_id=None,
                timestamp=datetime.utcnow(),
                hostname="suspicious-host",
                source_ip="192.168.1.99",
                app_name="auth",
                raw_message="Failed login attempt for user admin",
                processed_fields={
                    "action": "Failed",
                    "user": "admin",
                    "src_ip": "192.168.1.99",
                    "hostname": "suspicious-host"
                },
                log_type="authentication",
                severity="warning",
                category="security",
                source="test_backend",
                cribl_pipeline=None
            )
            
            session.add(test_log)
            await session.commit()
            await session.refresh(test_log)
            
            print(f"✅ Created test log: {test_log.id}")
            
            # Run detection on this log
            alerts_generated, rules_applied, errors = await detection_service.run_detection_on_processed_logs(
                session, [str(test_log.id)]
            )
            
            print(f"✅ Detection results: {alerts_generated} alerts, {rules_applied} rules applied")
            if errors:
                print(f"⚠️  Detection errors: {errors}")
            
            return True
    except Exception as e:
        print(f"❌ Complete flow test failed: {e}")
        return False

async def main():
    """Run all tests"""
    print("🧪 Backend Integration Test Suite")
    print("=" * 50)
    
    tests = [
        test_database_connection,
        test_processed_log_creation,
        test_detection_service,
        test_notification_service,
        test_complete_flow
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            result = await test()
            if result:
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} failed with exception: {e}")
            failed += 1
        print("-" * 50)
    
    print(f"\n📊 Test Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All tests passed! Backend integration is working correctly.")
    else:
        print("⚠️  Some tests failed. Please check the output above.")
    
    return failed == 0

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
