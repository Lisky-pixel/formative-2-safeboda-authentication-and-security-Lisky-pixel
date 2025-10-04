"""
UAS (User Authentication Service) models for SafeBoda system.
Implements centralized user management with Rwanda-specific features.
"""

from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
import uuid
import re

User = get_user_model()


class RwandaDistrict(models.Model):
    """
    Model for Rwanda districts - required for user registration.
    """
    name = models.CharField(max_length=100, unique=True)
    code = models.CharField(max_length=10, unique=True)
    province = models.CharField(max_length=50)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'rwanda_districts'
        ordering = ['name']
    
    def __str__(self):
        return f"{self.name} ({self.province})"


class UserProfile(models.Model):
    """
    Extended user profile with Rwanda-specific information.
    """
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    national_id = models.CharField(max_length=16, unique=True, null=True, blank=True)
    district = models.ForeignKey(RwandaDistrict, on_delete=models.SET_NULL, null=True, blank=True)
    address = models.TextField(blank=True)
    emergency_contact = models.CharField(max_length=15, blank=True)
    emergency_contact_name = models.CharField(max_length=100, blank=True)
    profile_completeness = models.IntegerField(default=0)  # Percentage
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'user_profiles'
    
    def calculate_completeness(self):
        """Calculate profile completeness percentage."""
        fields = [
            self.user.first_name,
            self.user.last_name,
            self.user.email,
            self.user.phone_number,
            self.national_id,
            self.district,
            self.address,
            self.emergency_contact,
            self.emergency_contact_name
        ]
        completed = sum(1 for field in fields if field)
        self.profile_completeness = int((completed / len(fields)) * 100)
        self.save(update_fields=['profile_completeness'])
        return self.profile_completeness


class VerificationCode(models.Model):
    """
    Model for SMS and email verification codes.
    """
    CODE_TYPES = [
        ('phone', 'Phone Verification'),
        ('email', 'Email Verification'),
        ('password_reset', 'Password Reset'),
        ('account_recovery', 'Account Recovery'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code_type = models.CharField(max_length=20, choices=CODE_TYPES)
    code = models.CharField(max_length=6)
    phone_number = models.CharField(max_length=15, null=True, blank=True)
    email = models.EmailField(null=True, blank=True)
    is_used = models.BooleanField(default=False)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'verification_codes'
        ordering = ['-created_at']
    
    def is_expired(self):
        """Check if verification code is expired."""
        return timezone.now() > self.expires_at
    
    def is_valid(self):
        """Check if verification code is valid (not used and not expired)."""
        return not self.is_used and not self.is_expired()
    
    def mark_as_used(self):
        """Mark verification code as used."""
        self.is_used = True
        self.save(update_fields=['is_used'])


class AccountRecovery(models.Model):
    """
    Model for account recovery requests.
    """
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('verified', 'Verified'),
        ('completed', 'Completed'),
        ('expired', 'Expired'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    recovery_method = models.CharField(max_length=20, choices=[
        ('phone', 'Phone Number'),
        ('email', 'Email Address'),
        ('national_id', 'National ID'),
    ])
    recovery_value = models.CharField(max_length=100)  # Phone, email, or national ID
    verification_code = models.ForeignKey(VerificationCode, on_delete=models.CASCADE, null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'account_recoveries'
        ordering = ['-created_at']


class NationalIDValidator:
    """
    Rwanda National ID validation utility.
    """
    
    @staticmethod
    def validate_format(national_id):
        """
        Validate Rwanda National ID format.
        Format: 12 digits, first 2 digits represent birth year
        """
        if not national_id or not isinstance(national_id, str):
            return False
        
        # Remove any spaces or dashes
        clean_id = re.sub(r'[\s\-]', '', national_id)
        
        # Check if it's exactly 12 digits
        if not re.match(r'^\d{12}$', clean_id):
            return False
        
        # Extract birth year (first 2 digits)
        birth_year = int(clean_id[:2])
        current_year = timezone.now().year % 100
        
        # Birth year should be reasonable (between 00 and current year)
        if birth_year > current_year:
            birth_year += 1900
        else:
            birth_year += 2000
        
        # Check if birth year is reasonable (between 1900 and current year)
        if birth_year < 1900 or birth_year > timezone.now().year:
            return False
        
        return True
    
    @staticmethod
    def extract_birth_year(national_id):
        """Extract birth year from National ID."""
        if not NationalIDValidator.validate_format(national_id):
            return None
        
        clean_id = re.sub(r'[\s\-]', '', national_id)
        birth_year = int(clean_id[:2])
        current_year = timezone.now().year % 100
        
        if birth_year > current_year:
            return birth_year + 1900
        else:
            return birth_year + 2000
    
    @staticmethod
    def calculate_age(national_id):
        """Calculate age from National ID."""
        birth_year = NationalIDValidator.extract_birth_year(national_id)
        if not birth_year:
            return None
        
        current_year = timezone.now().year
        return current_year - birth_year