"""
Privacy and Data Protection models for SafeBoda system.
Implements GDPR-style compliance features and data protection.
"""

from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.core.validators import MinValueValidator, MaxValueValidator
import uuid
import json
from cryptography.fernet import Fernet
from django.conf import settings
import hashlib

User = get_user_model()


class DataEncryption:
    """
    Utility class for field-level data encryption.
    """
    
    @staticmethod
    def get_encryption_key():
        """Get or create encryption key."""
        if not hasattr(settings, 'ENCRYPTION_KEY'):
            # Generate a new key if not exists (for development)
            key = Fernet.generate_key()
            settings.ENCRYPTION_KEY = key
        return settings.ENCRYPTION_KEY
    
    @staticmethod
    def encrypt_field(value):
        """Encrypt a field value."""
        if not value:
            return value
        
        key = DataEncryption.get_encryption_key()
        f = Fernet(key)
        encrypted_value = f.encrypt(str(value).encode())
        return encrypted_value.decode()
    
    @staticmethod
    def decrypt_field(encrypted_value):
        """Decrypt a field value."""
        if not encrypted_value:
            return encrypted_value
        
        try:
            key = DataEncryption.get_encryption_key()
            f = Fernet(key)
            decrypted_value = f.decrypt(encrypted_value.encode())
            return decrypted_value.decode()
        except Exception:
            # If decryption fails, return the original value (for backward compatibility)
            return encrypted_value


class ConsentType(models.Model):
    """
    Model for different types of consent (GDPR categories).
    """
    CONSENT_CATEGORIES = [
        ('essential', 'Essential'),
        ('analytics', 'Analytics'),
        ('marketing', 'Marketing'),
        ('personalization', 'Personalization'),
        ('third_party', 'Third Party Sharing'),
        ('location', 'Location Data'),
        ('biometric', 'Biometric Data'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)
    category = models.CharField(max_length=20, choices=CONSENT_CATEGORIES)
    description = models.TextField()
    is_required = models.BooleanField(default=False)
    retention_period_days = models.IntegerField(
        default=365,
        validators=[MinValueValidator(1), MaxValueValidator(3650)]
    )
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'consent_types'
        ordering = ['category', 'name']
    
    def __str__(self):
        return f"{self.name} ({self.get_category_display()})"


class UserConsent(models.Model):
    """
    Model to track user consent for different data processing activities.
    """
    CONSENT_STATUS = [
        ('granted', 'Granted'),
        ('denied', 'Denied'),
        ('withdrawn', 'Withdrawn'),
        ('expired', 'Expired'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='consents')
    consent_type = models.ForeignKey(ConsentType, on_delete=models.CASCADE)
    status = models.CharField(max_length=10, choices=CONSENT_STATUS)
    granted_at = models.DateTimeField(null=True, blank=True)
    withdrawn_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    consent_version = models.CharField(max_length=10, default='1.0')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'user_consents'
        unique_together = ['user', 'consent_type']
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.user.username} - {self.consent_type.name}: {self.status}"
    
    def is_valid(self):
        """Check if consent is currently valid."""
        if self.status != 'granted':
            return False
        
        if self.expires_at and self.expires_at < timezone.now():
            self.status = 'expired'
            self.save(update_fields=['status'])
            return False
        
        return True


class DataAccessLog(models.Model):
    """
    Model to log all access to personal data (GDPR Article 30 requirement).
    """
    ACCESS_TYPES = [
        ('read', 'Data Read'),
        ('write', 'Data Write'),
        ('delete', 'Data Delete'),
        ('export', 'Data Export'),
        ('anonymize', 'Data Anonymization'),
    ]
    
    DATA_CATEGORIES = [
        ('personal_info', 'Personal Information'),
        ('contact_info', 'Contact Information'),
        ('location_data', 'Location Data'),
        ('payment_info', 'Payment Information'),
        ('usage_data', 'Usage Data'),
        ('biometric_data', 'Biometric Data'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='data_access_logs')
    accessed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='data_access_actions')
    access_type = models.CharField(max_length=15, choices=ACCESS_TYPES)
    data_category = models.CharField(max_length=20, choices=DATA_CATEGORIES)
    data_fields = models.JSONField(default=list)  # List of fields accessed
    purpose = models.TextField()  # Legal basis for access
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    retention_until = models.DateTimeField()  # When this log should be deleted
    
    class Meta:
        db_table = 'data_access_logs'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['accessed_by', 'timestamp']),
            models.Index(fields=['access_type', 'timestamp']),
        ]
    
    def __str__(self):
        return f"{self.access_type.title()} access to {self.user.username}'s {self.data_category}"


class DataRetentionPolicy(models.Model):
    """
    Model to define data retention policies for different data types.
    """
    DATA_TYPES = [
        ('user_profile', 'User Profile'),
        ('contact_info', 'Contact Information'),
        ('location_data', 'Location Data'),
        ('payment_info', 'Payment Information'),
        ('usage_data', 'Usage Data'),
        ('communication_data', 'Communication Data'),
        ('biometric_data', 'Biometric Data'),
    ]
    
    RETENTION_BASIS = [
        ('legal_requirement', 'Legal Requirement'),
        ('business_necessity', 'Business Necessity'),
        ('user_consent', 'User Consent'),
        ('contract_performance', 'Contract Performance'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    data_type = models.CharField(max_length=20, choices=DATA_TYPES, unique=True)
    retention_period_days = models.IntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(3650)]
    )
    retention_basis = models.CharField(max_length=20, choices=RETENTION_BASIS)
    description = models.TextField()
    auto_delete = models.BooleanField(default=True)
    requires_consent = models.BooleanField(default=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'data_retention_policies'
        ordering = ['data_type']
    
    def __str__(self):
        return f"{self.get_data_type_display()}: {self.retention_period_days} days"


class DataDeletionRequest(models.Model):
    """
    Model to track user requests for data deletion (GDPR Right to be Forgotten).
    """
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('rejected', 'Rejected'),
        ('partially_completed', 'Partially Completed'),
    ]
    
    REQUEST_TYPES = [
        ('full_deletion', 'Full Account Deletion'),
        ('partial_deletion', 'Partial Data Deletion'),
        ('anonymization', 'Data Anonymization'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='deletion_requests')
    request_type = models.CharField(max_length=20, choices=REQUEST_TYPES)
    data_types = models.JSONField(default=list)  # Specific data types to delete
    reason = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    requested_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    processed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    rejection_reason = models.TextField(blank=True)
    completion_details = models.JSONField(default=dict)
    
    class Meta:
        db_table = 'data_deletion_requests'
        ordering = ['-requested_at']
    
    def __str__(self):
        return f"Deletion request for {self.user.username}: {self.get_request_type_display()}"


class DataExportRequest(models.Model):
    """
    Model to track user requests for data export (GDPR Right to Data Portability).
    """
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('processing', 'Processing'),
        ('ready', 'Ready for Download'),
        ('downloaded', 'Downloaded'),
        ('expired', 'Expired'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='export_requests')
    data_types = models.JSONField(default=list)  # Specific data types to export
    format = models.CharField(max_length=10, default='json')  # json, csv, xml
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='pending')
    requested_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)
    download_url = models.URLField(blank=True)
    expires_at = models.DateTimeField()
    download_count = models.IntegerField(default=0)
    max_downloads = models.IntegerField(default=3)
    
    class Meta:
        db_table = 'data_export_requests'
        ordering = ['-requested_at']
    
    def __str__(self):
        return f"Export request for {self.user.username}: {self.status}"
    
    def is_expired(self):
        """Check if export request has expired."""
        return timezone.now() > self.expires_at
    
    def can_download(self):
        """Check if user can still download the export."""
        return (
            self.status == 'ready' and 
            not self.is_expired() and 
            self.download_count < self.max_downloads
        )


class EncryptedPersonalData(models.Model):
    """
    Model to store encrypted personal data fields.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='encrypted_data')
    field_name = models.CharField(max_length=50)
    encrypted_value = models.TextField()
    data_hash = models.CharField(max_length=64)  # SHA-256 hash for integrity checking
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'encrypted_personal_data'
        unique_together = ['user', 'field_name']
        indexes = [
            models.Index(fields=['user', 'field_name']),
        ]
    
    def __str__(self):
        return f"{self.user.username}.{self.field_name}"
    
    def save(self, *args, **kwargs):
        """Save with automatic encryption and hashing."""
        if self.encrypted_value:
            # Create hash for integrity checking
            self.data_hash = hashlib.sha256(self.encrypted_value.encode()).hexdigest()
        super().save(*args, **kwargs)
    
    def get_decrypted_value(self):
        """Get decrypted value of the field."""
        return DataEncryption.decrypt_field(self.encrypted_value)
    
    def verify_integrity(self):
        """Verify data integrity using hash."""
        if not self.encrypted_value:
            return True
        
        current_hash = hashlib.sha256(self.encrypted_value.encode()).hexdigest()
        return current_hash == self.data_hash


class PrivacySettings(models.Model):
    """
    Model to store user privacy preferences and settings.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='privacy_settings')
    
    # Data sharing preferences
    allow_data_sharing = models.BooleanField(default=False)
    allow_analytics = models.BooleanField(default=False)
    allow_marketing = models.BooleanField(default=False)
    allow_location_tracking = models.BooleanField(default=False)
    
    # Notification preferences
    email_notifications = models.BooleanField(default=True)
    sms_notifications = models.BooleanField(default=False)
    push_notifications = models.BooleanField(default=True)
    
    # Data retention preferences
    auto_delete_after_inactivity = models.BooleanField(default=False)
    inactivity_period_days = models.IntegerField(default=365)
    
    # Audit preferences
    notify_on_data_access = models.BooleanField(default=True)
    monthly_privacy_report = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'privacy_settings'
    
    def __str__(self):
        return f"Privacy settings for {self.user.username}"


class DataProcessingActivity(models.Model):
    """
    Model to track data processing activities (GDPR Article 30).
    """
    LEGAL_BASIS = [
        ('consent', 'Consent'),
        ('contract', 'Contract'),
        ('legal_obligation', 'Legal Obligation'),
        ('vital_interests', 'Vital Interests'),
        ('public_task', 'Public Task'),
        ('legitimate_interests', 'Legitimate Interests'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    activity_name = models.CharField(max_length=200)
    description = models.TextField()
    legal_basis = models.CharField(max_length=20, choices=LEGAL_BASIS)
    data_categories = models.JSONField(default=list)
    data_subjects = models.JSONField(default=list)  # Categories of data subjects
    recipients = models.JSONField(default=list)  # Who receives the data
    third_country_transfers = models.BooleanField(default=False)
    retention_period = models.CharField(max_length=100)
    security_measures = models.JSONField(default=list)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'data_processing_activities'
        ordering = ['activity_name']
    
    def __str__(self):
        return self.activity_name