"""
Serializers for UAS (User Authentication Service) endpoints.
"""

from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .models import (
    UserProfile, RwandaDistrict, VerificationCode, AccountRecovery,
    NationalIDValidator
)
import random
import string
from datetime import timedelta
from django.utils import timezone

User = get_user_model()


class RwandaDistrictSerializer(serializers.ModelSerializer):
    """Serializer for Rwanda districts."""
    
    class Meta:
        model = RwandaDistrict
        fields = ['id', 'name', 'code', 'province', 'is_active']


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for user profile."""
    district_name = serializers.CharField(source='district.name', read_only=True)
    district_code = serializers.CharField(source='district.code', read_only=True)
    
    class Meta:
        model = UserProfile
        fields = [
            'national_id', 'district', 'district_name', 'district_code',
            'address', 'emergency_contact', 'emergency_contact_name',
            'profile_completeness', 'created_at', 'updated_at'
        ]
        read_only_fields = ['profile_completeness', 'created_at', 'updated_at']


class UserRegistrationSerializer(serializers.ModelSerializer):
    """Enhanced user registration serializer with Rwanda integration."""
    password = serializers.CharField(write_only=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True)
    national_id = serializers.CharField(max_length=16, required=False)
    district_id = serializers.IntegerField(required=False)
    address = serializers.CharField(required=False)
    emergency_contact = serializers.CharField(max_length=15, required=False)
    emergency_contact_name = serializers.CharField(max_length=100, required=False)
    
    class Meta:
        model = User
        fields = [
            'username', 'email', 'phone_number', 'password', 'password_confirm',
            'first_name', 'last_name', 'national_id', 'district_id',
            'address', 'emergency_contact', 'emergency_contact_name'
        ]
    
    def validate(self, attrs):
        """Validate registration data."""
        # Password confirmation
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match.")
        
        # National ID validation
        national_id = attrs.get('national_id')
        if national_id and not NationalIDValidator.validate_format(national_id):
            raise serializers.ValidationError("Invalid National ID format.")
        
        # Check if National ID already exists
        if national_id and UserProfile.objects.filter(national_id=national_id).exists():
            raise serializers.ValidationError("National ID already registered.")
        
        # District validation
        district_id = attrs.get('district_id')
        if district_id:
            try:
                district = RwandaDistrict.objects.get(id=district_id, is_active=True)
                attrs['district'] = district
            except RwandaDistrict.DoesNotExist:
                raise serializers.ValidationError("Invalid district selected.")
        
        return attrs
    
    def create(self, validated_data):
        """Create user and profile."""
        # Extract profile data
        profile_data = {
            'national_id': validated_data.pop('national_id', None),
            'district': validated_data.pop('district', None),
            'address': validated_data.pop('address', ''),
            'emergency_contact': validated_data.pop('emergency_contact', ''),
            'emergency_contact_name': validated_data.pop('emergency_contact_name', ''),
        }
        
        # Remove password_confirm and district_id (not part of User model)
        validated_data.pop('password_confirm', None)
        validated_data.pop('district_id', None)
        
        # Create user
        user = User.objects.create_user(**validated_data)
        
        # Create profile
        UserProfile.objects.create(user=user, **profile_data)
        
        # Calculate profile completeness
        user.profile.calculate_completeness()
        
        return user


class PhoneVerificationSerializer(serializers.Serializer):
    """Serializer for phone verification."""
    phone_number = serializers.CharField(max_length=15)
    
    def validate_phone_number(self, value):
        """Validate Rwanda phone number format."""
        # Remove any spaces or dashes
        clean_number = value.replace(' ', '').replace('-', '')
        
        # Check Rwanda phone number format (+250XXXXXXXXX)
        if not clean_number.startswith('+250'):
            raise serializers.ValidationError("Phone number must start with +250")
        
        if len(clean_number) != 13:
            raise serializers.ValidationError("Invalid phone number length")
        
        return clean_number


class EmailVerificationSerializer(serializers.Serializer):
    """Serializer for email verification."""
    email = serializers.EmailField()


class VerificationCodeSerializer(serializers.Serializer):
    """Serializer for verification code submission."""
    code = serializers.CharField(max_length=6, min_length=6)
    phone_number = serializers.CharField(max_length=15, required=False)
    email = serializers.EmailField(required=False)
    
    def validate_code(self, value):
        """Validate verification code format."""
        if not value.isdigit():
            raise serializers.ValidationError("Verification code must contain only digits.")
        return value


class PasswordResetSerializer(serializers.Serializer):
    """Serializer for password reset request."""
    email = serializers.EmailField(required=False)
    phone_number = serializers.CharField(max_length=15, required=False)
    national_id = serializers.CharField(max_length=16, required=False)
    
    def validate(self, attrs):
        """Validate that at least one recovery method is provided."""
        if not any(attrs.values()):
            raise serializers.ValidationError("At least one recovery method must be provided.")
        return attrs


class PasswordResetConfirmSerializer(serializers.Serializer):
    """Serializer for password reset confirmation."""
    code = serializers.CharField(max_length=6)
    new_password = serializers.CharField(validators=[validate_password])
    new_password_confirm = serializers.CharField()
    
    def validate(self, attrs):
        """Validate password confirmation."""
        if attrs['new_password'] != attrs['new_password_confirm']:
            raise serializers.ValidationError("Passwords don't match.")
        return attrs


class AccountRecoverySerializer(serializers.Serializer):
    """Serializer for account recovery request."""
    recovery_method = serializers.ChoiceField(choices=[
        ('phone', 'Phone Number'),
        ('email', 'Email Address'),
        ('national_id', 'National ID'),
    ])
    recovery_value = serializers.CharField(max_length=100)
    
    def validate(self, attrs):
        """Validate recovery method and value."""
        method = attrs['recovery_method']
        value = attrs['recovery_value']
        
        if method == 'phone':
            # Validate phone number format
            clean_number = value.replace(' ', '').replace('-', '')
            if not clean_number.startswith('+250') or len(clean_number) != 13:
                raise serializers.ValidationError("Invalid phone number format.")
            attrs['recovery_value'] = clean_number
        
        elif method == 'email':
            # Basic email validation is handled by EmailField
            pass
        
        elif method == 'national_id':
            if not NationalIDValidator.validate_format(value):
                raise serializers.ValidationError("Invalid National ID format.")
        
        return attrs


class AccountStatusSerializer(serializers.ModelSerializer):
    """Serializer for account status."""
    profile = UserProfileSerializer(read_only=True)
    district_name = serializers.CharField(source='profile.district.name', read_only=True)
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'phone_number', 'is_phone_verified',
            'is_email_verified', 'is_active', 'date_joined', 'last_login',
            'profile', 'district_name'
        ]
        read_only_fields = ['id', 'date_joined', 'last_login']


class VerificationCodeGenerator:
    """Utility class for generating verification codes."""
    
    @staticmethod
    def generate_code(length=6):
        """Generate random numeric code."""
        return ''.join(random.choices(string.digits, k=length))
    
    @staticmethod
    def create_verification_code(user, code_type, phone_number=None, email=None, expires_in_minutes=10):
        """Create a new verification code."""
        # Invalidate existing codes of the same type
        VerificationCode.objects.filter(
            user=user,
            code_type=code_type,
            is_used=False
        ).update(is_used=True)
        
        # Generate new code
        code = VerificationCodeGenerator.generate_code()
        expires_at = timezone.now() + timedelta(minutes=expires_in_minutes)
        
        verification_code = VerificationCode.objects.create(
            user=user,
            code_type=code_type,
            code=code,
            phone_number=phone_number,
            email=email,
            expires_at=expires_at
        )
        
        return verification_code
