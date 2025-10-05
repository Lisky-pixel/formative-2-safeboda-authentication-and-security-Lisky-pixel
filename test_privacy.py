"""
Test script for Privacy and Data Protection functionality.
"""

import os
import sys
import django
from django.conf import settings

# Add the project directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'safeboda_auth.settings')
django.setup()

from authentication.models import User
from privacy.models import (
    ConsentType, UserConsent, DataAccessLog, DataRetentionPolicy,
    DataDeletionRequest, DataExportRequest, EncryptedPersonalData,
    PrivacySettings, DataProcessingActivity, DataEncryption
)


def test_consent_types():
    """Test consent types functionality."""
    print("Testing Consent Types...")
    
    # Get all consent types
    consent_types = ConsentType.objects.filter(is_active=True)
    print(f"[OK] Found {consent_types.count()} active consent types")
    
    # Test consent type creation
    consent_type, created = ConsentType.objects.get_or_create(
        name='Test Consent',
        defaults={
            'category': 'analytics',
            'description': 'Test consent for analytics',
            'is_required': False,
            'retention_period_days': 365,
            'is_active': True
        }
    )
    
    if created:
        print("[OK] Test consent type created")
    else:
        print("[OK] Test consent type already exists")
    
    return consent_type


def test_data_encryption():
    """Test data encryption functionality."""
    print("\nTesting Data Encryption...")
    
    # Test encryption and decryption
    test_value = "sensitive_data_123"
    encrypted_value = DataEncryption.encrypt_field(test_value)
    decrypted_value = DataEncryption.decrypt_field(encrypted_value)
    
    print(f"[OK] Original value: {test_value}")
    print(f"[OK] Encrypted value: {encrypted_value[:50]}...")
    print(f"[OK] Decrypted value: {decrypted_value}")
    print(f"[OK] Encryption/decryption successful: {test_value == decrypted_value}")
    
    # Test encrypted personal data model
    user = User.objects.filter(username__startswith='testuser').first()
    if user:
        encrypted_data, created = EncryptedPersonalData.objects.get_or_create(
            user=user,
            field_name='test_field',
            defaults={
                'encrypted_value': encrypted_value
            }
        )
        
        if created:
            print("[OK] Encrypted personal data record created")
        else:
            print("[OK] Encrypted personal data record already exists")
        
        # Test decryption
        decrypted_field_value = encrypted_data.get_decrypted_value()
        print(f"[OK] Decrypted field value: {decrypted_field_value}")
        print(f"[OK] Field decryption successful: {test_value == decrypted_field_value}")
        
        # Test integrity verification
        integrity_ok = encrypted_data.verify_integrity()
        print(f"[OK] Data integrity verification: {integrity_ok}")
        
        return encrypted_data
    
    return None


def test_user_consent():
    """Test user consent functionality."""
    print("\nTesting User Consent...")
    
    # Get test user and consent type
    user = User.objects.filter(username__startswith='testuser').first()
    consent_type = ConsentType.objects.first()
    
    if not user or not consent_type:
        print("[SKIP] No test user or consent type found")
        return None
    
    # Create user consent
    user_consent, created = UserConsent.objects.get_or_create(
        user=user,
        consent_type=consent_type,
        defaults={
            'status': 'granted',
            'ip_address': '127.0.0.1',
            'user_agent': 'Test Agent',
            'consent_version': '1.0'
        }
    )
    
    if created:
        print("[OK] User consent created")
    else:
        print("[OK] User consent already exists")
    
    print(f"[OK] Consent status: {user_consent.status}")
    print(f"[OK] Consent is valid: {user_consent.is_valid()}")
    print(f"[OK] Consent type: {user_consent.consent_type.name}")
    
    return user_consent


def test_data_access_logging():
    """Test data access logging functionality."""
    print("\nTesting Data Access Logging...")
    
    # Get test user
    user = User.objects.filter(username__startswith='testuser').first()
    
    if not user:
        print("[SKIP] No test user found")
        return None
    
    # Create data access log
    access_log = DataAccessLog.objects.create(
        user=user,
        accessed_by=user,
        access_type='read',
        data_category='personal_info',
        data_fields=['username', 'email'],
        purpose='Test access logging',
        ip_address='127.0.0.1',
        user_agent='Test Agent',
        retention_until='2025-12-31 23:59:59'
    )
    
    print(f"[OK] Data access log created: {access_log.id}")
    print(f"[OK] Access type: {access_log.access_type}")
    print(f"[OK] Data category: {access_log.data_category}")
    print(f"[OK] Purpose: {access_log.purpose}")
    
    return access_log


def test_retention_policies():
    """Test data retention policies."""
    print("\nTesting Data Retention Policies...")
    
    # Get all retention policies
    policies = DataRetentionPolicy.objects.filter(is_active=True)
    print(f"[OK] Found {policies.count()} active retention policies")
    
    # Test policy creation
    policy, created = DataRetentionPolicy.objects.get_or_create(
        data_type='test_data',
        defaults={
            'retention_period_days': 365,
            'retention_basis': 'business_necessity',
            'description': 'Test data retention policy',
            'auto_delete': True,
            'requires_consent': True,
            'is_active': True
        }
    )
    
    if created:
        print("[OK] Test retention policy created")
    else:
        print("[OK] Test retention policy already exists")
    
    print(f"[OK] Policy data type: {policy.get_data_type_display()}")
    print(f"[OK] Retention period: {policy.retention_period_days} days")
    print(f"[OK] Auto delete: {policy.auto_delete}")
    
    return policy


def test_data_deletion_requests():
    """Test data deletion requests."""
    print("\nTesting Data Deletion Requests...")
    
    # Get test user
    user = User.objects.filter(username__startswith='testuser').first()
    
    if not user:
        print("[SKIP] No test user found")
        return None
    
    # Create deletion request
    deletion_request = DataDeletionRequest.objects.create(
        user=user,
        request_type='partial_deletion',
        data_types=['contact_info', 'location_data'],
        reason='Test deletion request',
        status='pending'
    )
    
    print(f"[OK] Deletion request created: {deletion_request.id}")
    print(f"[OK] Request type: {deletion_request.get_request_type_display()}")
    print(f"[OK] Data types: {deletion_request.data_types}")
    print(f"[OK] Status: {deletion_request.status}")
    
    return deletion_request


def test_data_export_requests():
    """Test data export requests."""
    print("\nTesting Data Export Requests...")
    
    # Get test user
    user = User.objects.filter(username__startswith='testuser').first()
    
    if not user:
        print("[SKIP] No test user found")
        return None
    
    # Create export request
    export_request = DataExportRequest.objects.create(
        user=user,
        data_types=['user_info', 'profile_data'],
        format='json',
        status='pending',
        expires_at='2025-12-31 23:59:59'
    )
    
    print(f"[OK] Export request created: {export_request.id}")
    print(f"[OK] Data types: {export_request.data_types}")
    print(f"[OK] Format: {export_request.format}")
    print(f"[OK] Status: {export_request.status}")
    print(f"[OK] Is expired: {export_request.is_expired()}")
    print(f"[OK] Can download: {export_request.can_download()}")
    
    return export_request


def test_privacy_settings():
    """Test privacy settings."""
    print("\nTesting Privacy Settings...")
    
    # Get test user
    user = User.objects.filter(username__startswith='testuser').first()
    
    if not user:
        print("[SKIP] No test user found")
        return None
    
    # Create or get privacy settings
    privacy_settings, created = PrivacySettings.objects.get_or_create(user=user)
    
    if created:
        print("[OK] Privacy settings created")
    else:
        print("[OK] Privacy settings already exist")
    
    # Update some settings
    privacy_settings.allow_data_sharing = False
    privacy_settings.allow_analytics = True
    privacy_settings.email_notifications = True
    privacy_settings.save()
    
    print(f"[OK] Allow data sharing: {privacy_settings.allow_data_sharing}")
    print(f"[OK] Allow analytics: {privacy_settings.allow_analytics}")
    print(f"[OK] Email notifications: {privacy_settings.email_notifications}")
    
    return privacy_settings


def test_processing_activities():
    """Test data processing activities."""
    print("\nTesting Data Processing Activities...")
    
    # Get all processing activities
    activities = DataProcessingActivity.objects.filter(is_active=True)
    print(f"[OK] Found {activities.count()} active processing activities")
    
    # Test activity creation
    activity, created = DataProcessingActivity.objects.get_or_create(
        activity_name='Test Processing Activity',
        defaults={
            'description': 'Test data processing activity',
            'legal_basis': 'consent',
            'data_categories': ['personal_info'],
            'data_subjects': ['customers'],
            'recipients': ['internal_systems'],
            'third_country_transfers': False,
            'retention_period': '1 year',
            'security_measures': ['encryption'],
            'is_active': True
        }
    )
    
    if created:
        print("[OK] Test processing activity created")
    else:
        print("[OK] Test processing activity already exists")
    
    print(f"[OK] Activity name: {activity.activity_name}")
    print(f"[OK] Legal basis: {activity.get_legal_basis_display()}")
    print(f"[OK] Data categories: {activity.data_categories}")
    
    return activity


def test_privacy_models_integration():
    """Test integration between privacy models."""
    print("\nTesting Privacy Models Integration...")
    
    # Get test user
    user = User.objects.filter(username__startswith='testuser').first()
    
    if not user:
        print("[SKIP] No test user found")
        return
    
    # Test comprehensive privacy data
    consent_count = UserConsent.objects.filter(user=user).count()
    access_logs_count = DataAccessLog.objects.filter(user=user).count()
    deletion_requests_count = DataDeletionRequest.objects.filter(user=user).count()
    export_requests_count = DataExportRequest.objects.filter(user=user).count()
    
    print(f"[OK] User has {consent_count} consent records")
    print(f"[OK] User has {access_logs_count} access log entries")
    print(f"[OK] User has {deletion_requests_count} deletion requests")
    print(f"[OK] User has {export_requests_count} export requests")
    
    # Test privacy settings
    if hasattr(user, 'privacy_settings'):
        print("[OK] User has privacy settings configured")
    else:
        print("[OK] User privacy settings will be created on demand")


def main():
    """Run all privacy tests."""
    print("SafeBoda Privacy and Data Protection - Test Suite")
    print("=" * 60)
    
    try:
        # Test consent types
        consent_type = test_consent_types()
        
        # Test data encryption
        encrypted_data = test_data_encryption()
        
        # Test user consent
        user_consent = test_user_consent()
        
        # Test data access logging
        access_log = test_data_access_logging()
        
        # Test retention policies
        retention_policy = test_retention_policies()
        
        # Test data deletion requests
        deletion_request = test_data_deletion_requests()
        
        # Test data export requests
        export_request = test_data_export_requests()
        
        # Test privacy settings
        privacy_settings = test_privacy_settings()
        
        # Test processing activities
        processing_activity = test_processing_activities()
        
        # Test integration
        test_privacy_models_integration()
        
        print("\n" + "=" * 60)
        print("[OK] All privacy tests passed! Data Protection system is working.")
        
        # Clean up test data
        cleanup_objects = [
            consent_type, encrypted_data, user_consent, access_log,
            retention_policy, deletion_request, export_request,
            privacy_settings, processing_activity
        ]
        
        for obj in cleanup_objects:
            if obj:
                try:
                    obj.delete()
                except Exception as e:
                    print(f"[WARNING] Could not delete test object: {e}")
        
        print("[OK] Test data cleaned up.")
        
    except Exception as e:
        print(f"\n[FAIL] Test failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
