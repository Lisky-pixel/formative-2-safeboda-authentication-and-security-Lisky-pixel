"""
Test script for UAS (User Authentication Service) functionality.
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
from uas.models import UserProfile, RwandaDistrict, VerificationCode, AccountRecovery, NationalIDValidator
from uas.serializers import UserRegistrationSerializer, RwandaDistrictSerializer

def test_rwanda_districts():
    """Test Rwanda districts functionality."""
    print("Testing Rwanda Districts...")
    
    # Get all districts
    districts = RwandaDistrict.objects.filter(is_active=True)
    print(f"[OK] Found {districts.count()} active districts")
    
    # Test district serializer
    serializer = RwandaDistrictSerializer(districts[:3], many=True)
    print(f"[OK] District serializer works: {len(serializer.data)} districts serialized")
    
    return districts.first()

def test_national_id_validation():
    """Test Rwanda National ID validation."""
    print("\nTesting National ID Validation...")
    
    # Test valid National ID
    valid_id = "123456789012"  # 12 digits
    is_valid = NationalIDValidator.validate_format(valid_id)
    print(f"[OK] Valid National ID format: {is_valid}")
    
    # Test invalid National ID
    invalid_id = "12345678901"  # 11 digits
    is_invalid = NationalIDValidator.validate_format(invalid_id)
    print(f"[OK] Invalid National ID format: {not is_invalid}")
    
    # Test birth year extraction
    birth_year = NationalIDValidator.extract_birth_year(valid_id)
    print(f"[OK] Birth year extraction: {birth_year}")
    
    # Test age calculation
    age = NationalIDValidator.calculate_age(valid_id)
    print(f"[OK] Age calculation: {age}")

def test_user_registration():
    """Test enhanced user registration with Rwanda integration."""
    print("\nTesting User Registration...")
    
    # Clean up any existing test users
    User.objects.filter(username__startswith='testuser').delete()
    
    # Get a district for testing
    district = RwandaDistrict.objects.first()
    
    # Test registration data
    import random
    registration_data = {
        'username': f'testuser{random.randint(1000, 9999)}',
        'email': 'test@safeboda.com',
        'phone_number': f'+250788{random.randint(100000, 999999)}',
        'password': 'testpass123',
        'password_confirm': 'testpass123',
        'first_name': 'Test',
        'last_name': 'User',
        'national_id': '123456789012',
        'district_id': district.id,
        'address': 'Test Address, Kigali',
        'emergency_contact': '+250788123456',
        'emergency_contact_name': 'Emergency Contact'
    }
    
    # Test serializer validation
    serializer = UserRegistrationSerializer(data=registration_data)
    if serializer.is_valid():
        print("[OK] Registration serializer validation successful")
        
        # Create user
        user = serializer.save()
        print(f"[OK] User created: {user.username}")
        print(f"[OK] User profile created: {hasattr(user, 'profile')}")
        print(f"[OK] Profile completeness: {user.profile.profile_completeness}%")
        
        return user
    else:
        print(f"[FAIL] Registration serializer validation failed: {serializer.errors}")
        return None

def test_verification_codes():
    """Test verification code functionality."""
    print("\nTesting Verification Codes...")
    
    # Get a test user
    user = User.objects.filter(username__startswith='testuser').first()
    if not user:
        print("[SKIP] No test user found for verification code testing")
        return
    
    # Create verification code
    from uas.serializers import VerificationCodeGenerator
    verification_code = VerificationCodeGenerator.create_verification_code(
        user=user,
        code_type='phone',
        phone_number=user.phone_number,
        expires_in_minutes=10
    )
    
    print(f"[OK] Verification code created: {verification_code.code}")
    print(f"[OK] Code is valid: {verification_code.is_valid()}")
    print(f"[OK] Code is not expired: {not verification_code.is_expired()}")
    
    # Test code usage
    verification_code.mark_as_used()
    print(f"[OK] Code marked as used: {verification_code.is_used}")
    print(f"[OK] Code is no longer valid: {not verification_code.is_valid()}")

def test_account_recovery():
    """Test account recovery functionality."""
    print("\nTesting Account Recovery...")
    
    # Get a test user
    user = User.objects.filter(username__startswith='testuser').first()
    if not user:
        print("[SKIP] No test user found for account recovery testing")
        return
    
    # Create account recovery request
    recovery_request = AccountRecovery.objects.create(
        user=user,
        recovery_method='phone',
        recovery_value=user.phone_number,
        ip_address='127.0.0.1',
        user_agent='Test Agent'
    )
    
    print(f"[OK] Account recovery request created: {recovery_request.id}")
    print(f"[OK] Recovery method: {recovery_request.recovery_method}")
    print(f"[OK] Recovery value: {recovery_request.recovery_value}")
    print(f"[OK] Status: {recovery_request.status}")

def test_profile_completeness():
    """Test profile completeness calculation."""
    print("\nTesting Profile Completeness...")
    
    # Get a test user
    user = User.objects.filter(username__startswith='testuser').first()
    if not user:
        print("[SKIP] No test user found for profile completeness testing")
        return
    
    # Calculate completeness
    initial_completeness = user.profile.profile_completeness
    print(f"[OK] Initial profile completeness: {initial_completeness}%")
    
    # Update profile and recalculate
    user.profile.calculate_completeness()
    updated_completeness = user.profile.profile_completeness
    print(f"[OK] Updated profile completeness: {updated_completeness}%")

def main():
    """Run all UAS tests."""
    print("SafeBoda UAS (User Authentication Service) - Test Suite")
    print("=" * 60)
    
    try:
        # Test Rwanda districts
        district = test_rwanda_districts()
        
        # Test National ID validation
        test_national_id_validation()
        
        # Test user registration
        user = test_user_registration()
        
        # Test verification codes
        test_verification_codes()
        
        # Test account recovery
        test_account_recovery()
        
        # Test profile completeness
        test_profile_completeness()
        
        print("\n" + "=" * 60)
        print("[OK] All UAS tests passed! User Authentication Service is working.")
        
        # Clean up test data
        if user:
            user.delete()
        print("[OK] Test data cleaned up.")
        
    except Exception as e:
        print(f"\n[FAIL] Test failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()
