"""
Serializers for privacy and data protection endpoints.
"""

from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.utils import timezone
from .models import (
    ConsentType, UserConsent, DataAccessLog, DataRetentionPolicy,
    DataDeletionRequest, DataExportRequest, EncryptedPersonalData,
    PrivacySettings, DataProcessingActivity, DataEncryption
)
import json

User = get_user_model()


class ConsentTypeSerializer(serializers.ModelSerializer):
    """Serializer for consent types."""
    
    class Meta:
        model = ConsentType
        fields = [
            'id', 'name', 'category', 'description', 'is_required',
            'retention_period_days', 'is_active', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class UserConsentSerializer(serializers.ModelSerializer):
    """Serializer for user consent."""
    consent_type_name = serializers.CharField(source='consent_type.name', read_only=True)
    consent_type_category = serializers.CharField(source='consent_type.category', read_only=True)
    
    class Meta:
        model = UserConsent
        fields = [
            'id', 'consent_type', 'consent_type_name', 'consent_type_category',
            'status', 'granted_at', 'withdrawn_at', 'expires_at',
            'consent_version', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'granted_at', 'withdrawn_at', 'created_at', 'updated_at']


class ConsentUpdateSerializer(serializers.Serializer):
    """Serializer for updating user consent."""
    consent_type_id = serializers.UUIDField()
    status = serializers.ChoiceField(choices=UserConsent.CONSENT_STATUS)
    
    def validate_status(self, value):
        """Validate consent status."""
        if value not in ['granted', 'denied', 'withdrawn']:
            raise serializers.ValidationError("Invalid consent status.")
        return value


class DataAccessLogSerializer(serializers.ModelSerializer):
    """Serializer for data access logs."""
    user_username = serializers.CharField(source='user.username', read_only=True)
    accessed_by_username = serializers.CharField(source='accessed_by.username', read_only=True)
    
    class Meta:
        model = DataAccessLog
        fields = [
            'id', 'user', 'user_username', 'accessed_by', 'accessed_by_username',
            'access_type', 'data_category', 'data_fields', 'purpose',
            'ip_address', 'user_agent', 'timestamp', 'retention_until'
        ]
        read_only_fields = ['id', 'timestamp']


class DataRetentionPolicySerializer(serializers.ModelSerializer):
    """Serializer for data retention policies."""
    
    class Meta:
        model = DataRetentionPolicy
        fields = [
            'id', 'data_type', 'retention_period_days', 'retention_basis',
            'description', 'auto_delete', 'requires_consent', 'is_active',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class DataDeletionRequestSerializer(serializers.ModelSerializer):
    """Serializer for data deletion requests."""
    user_username = serializers.CharField(source='user.username', read_only=True)
    processed_by_username = serializers.CharField(source='processed_by.username', read_only=True)
    
    class Meta:
        model = DataDeletionRequest
        fields = [
            'id', 'user', 'user_username', 'request_type', 'data_types',
            'reason', 'status', 'requested_at', 'processed_at',
            'processed_by', 'processed_by_username', 'rejection_reason',
            'completion_details'
        ]
        read_only_fields = [
            'id', 'user', 'status', 'requested_at', 'processed_at',
            'processed_by', 'created_at'
        ]


class DataDeletionCreateSerializer(serializers.Serializer):
    """Serializer for creating data deletion requests."""
    request_type = serializers.ChoiceField(choices=DataDeletionRequest.REQUEST_TYPES)
    data_types = serializers.ListField(
        child=serializers.ChoiceField(choices=DataRetentionPolicy.DATA_TYPES),
        required=False
    )
    reason = serializers.CharField(required=False, allow_blank=True)
    
    def validate_data_types(self, value):
        """Validate data types."""
        if not value:
            return value
        
        valid_types = [choice[0] for choice in DataRetentionPolicy.DATA_TYPES]
        for data_type in value:
            if data_type not in valid_types:
                raise serializers.ValidationError(f"Invalid data type: {data_type}")
        
        return value


class DataExportRequestSerializer(serializers.ModelSerializer):
    """Serializer for data export requests."""
    user_username = serializers.CharField(source='user.username', read_only=True)
    is_expired = serializers.BooleanField(read_only=True)
    can_download = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = DataExportRequest
        fields = [
            'id', 'user', 'user_username', 'data_types', 'format',
            'status', 'requested_at', 'processed_at', 'download_url',
            'expires_at', 'download_count', 'max_downloads',
            'is_expired', 'can_download'
        ]
        read_only_fields = [
            'id', 'user', 'status', 'requested_at', 'processed_at',
            'download_url', 'expires_at', 'download_count'
        ]


class DataExportCreateSerializer(serializers.Serializer):
    """Serializer for creating data export requests."""
    data_types = serializers.ListField(
        child=serializers.ChoiceField(choices=DataRetentionPolicy.DATA_TYPES),
        required=False
    )
    format = serializers.ChoiceField(choices=['json', 'csv', 'xml'], default='json')
    
    def validate_data_types(self, value):
        """Validate data types."""
        if not value:
            return value
        
        valid_types = [choice[0] for choice in DataRetentionPolicy.DATA_TYPES]
        for data_type in value:
            if data_type not in valid_types:
                raise serializers.ValidationError(f"Invalid data type: {data_type}")
        
        return value


class EncryptedPersonalDataSerializer(serializers.ModelSerializer):
    """Serializer for encrypted personal data."""
    decrypted_value = serializers.SerializerMethodField()
    
    class Meta:
        model = EncryptedPersonalData
        fields = [
            'id', 'user', 'field_name', 'encrypted_value',
            'data_hash', 'created_at', 'updated_at', 'decrypted_value'
        ]
        read_only_fields = ['id', 'user', 'encrypted_value', 'data_hash', 'created_at', 'updated_at']
    
    def get_decrypted_value(self, obj):
        """Get decrypted value (only for authenticated user)."""
        request = self.context.get('request')
        if request and request.user == obj.user:
            return obj.get_decrypted_value()
        return None


class PrivacySettingsSerializer(serializers.ModelSerializer):
    """Serializer for privacy settings."""
    user_username = serializers.CharField(source='user.username', read_only=True)
    
    class Meta:
        model = PrivacySettings
        fields = [
            'id', 'user', 'user_username', 'allow_data_sharing', 'allow_analytics',
            'allow_marketing', 'allow_location_tracking', 'email_notifications',
            'sms_notifications', 'push_notifications', 'auto_delete_after_inactivity',
            'inactivity_period_days', 'notify_on_data_access', 'monthly_privacy_report',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'user', 'created_at', 'updated_at']


class DataProcessingActivitySerializer(serializers.ModelSerializer):
    """Serializer for data processing activities."""
    
    class Meta:
        model = DataProcessingActivity
        fields = [
            'id', 'activity_name', 'description', 'legal_basis',
            'data_categories', 'data_subjects', 'recipients',
            'third_country_transfers', 'retention_period',
            'security_measures', 'is_active', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class DataExportSerializer(serializers.Serializer):
    """Serializer for user data export."""
    user_info = serializers.DictField(read_only=True)
    profile_data = serializers.DictField(read_only=True)
    consent_data = serializers.ListField(read_only=True)
    privacy_settings = serializers.DictField(read_only=True)
    access_logs = serializers.ListField(read_only=True)
    export_metadata = serializers.DictField(read_only=True)


class ConsentStatusSerializer(serializers.Serializer):
    """Serializer for current consent status."""
    consent_type_id = serializers.UUIDField(read_only=True)
    consent_type_name = serializers.CharField(read_only=True)
    consent_type_category = serializers.CharField(read_only=True)
    status = serializers.CharField(read_only=True)
    is_valid = serializers.BooleanField(read_only=True)
    granted_at = serializers.DateTimeField(read_only=True)
    expires_at = serializers.DateTimeField(read_only=True)


class AnonymizationRequestSerializer(serializers.Serializer):
    """Serializer for data anonymization requests."""
    data_types = serializers.ListField(
        child=serializers.ChoiceField(choices=DataRetentionPolicy.DATA_TYPES),
        required=False
    )
    anonymization_method = serializers.ChoiceField(
        choices=[
            ('pseudonymization', 'Pseudonymization'),
            ('generalization', 'Generalization'),
            ('suppression', 'Suppression'),
            ('randomization', 'Randomization'),
        ],
        default='pseudonymization'
    )
    reason = serializers.CharField(required=False, allow_blank=True)


class RetentionPolicyInfoSerializer(serializers.Serializer):
    """Serializer for retention policy information."""
    data_type = serializers.CharField(read_only=True)
    retention_period_days = serializers.IntegerField(read_only=True)
    retention_basis = serializers.CharField(read_only=True)
    description = serializers.CharField(read_only=True)
    auto_delete = serializers.BooleanField(read_only=True)
    requires_consent = serializers.BooleanField(read_only=True)
