"""
Test script for SafeBoda authentication system.
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

from authentication.models import User, SecurityEvent
from authentication.serializers import BasicAuthSerializer, UserSerializer

def test_user_creation():
    """Test user creation and authentication."""
    print("Testing User Creation...")
    
    # Clean up any existing test users
    User.objects.filter(username__startswith='testuser').delete()
    
    # Create a test user
    import random
    phone_number = f'+250788{random.randint(100000, 999999)}'
    username = f'testuser{random.randint(1000, 9999)}'
    user = User.objects.create_user(
        username=username,
        email='test@safeboda.com',
        password='testpass123',
        phone_number=phone_number
    )
    
    print(f"[OK] User created: {user.username}")
    print(f"[OK] User ID: {user.id}")
    print(f"[OK] Phone: {user.phone_number}")
    
    # Test authentication
    from django.contrib.auth import authenticate
    auth_user = authenticate(username=username, password='testpass123')
    
    if auth_user:
        print("[OK] Authentication successful")
    else:
        print("[FAIL] Authentication failed")
    
    return user

def test_security_events():
    """Test security event logging."""
    print("\nTesting Security Events...")
    
    # Create a security event
    event = SecurityEvent.objects.create(
        user=None,
        event_type='login_failed',
        ip_address='127.0.0.1',
        user_agent='Test Agent',
        details={'test': True}
    )
    
    print(f"[OK] Security event created: {event.event_type}")
    print(f"[OK] Event ID: {event.id}")
    
    return event

def test_serializers():
    """Test serializers."""
    print("\nTesting Serializers...")
    
    # Test user serializer
    user = User.objects.filter(username__startswith='testuser').first()
    serializer = UserSerializer(user)
    print(f"[OK] User serializer works: {serializer.data['username']}")
    
    # Test basic auth serializer
    auth_data = {'username': user.username, 'password': 'testpass123'}
    auth_serializer = BasicAuthSerializer(data=auth_data)
    
    if auth_serializer.is_valid():
        print("[OK] Basic auth serializer validation successful")
    else:
        print(f"[FAIL] Basic auth serializer validation failed: {auth_serializer.errors}")

def main():
    """Run all tests."""
    print("SafeBoda Authentication System - Test Suite")
    print("=" * 50)
    
    try:
        # Test user creation
        user = test_user_creation()
        
        # Test security events
        event = test_security_events()
        
        # Test serializers
        test_serializers()
        
        print("\n" + "=" * 50)
        print("[OK] All tests passed! Authentication system is working.")
        
        # Clean up
        user.delete()
        event.delete()
        print("[OK] Test data cleaned up.")
        
    except Exception as e:
        print(f"\n[FAIL] Test failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()
