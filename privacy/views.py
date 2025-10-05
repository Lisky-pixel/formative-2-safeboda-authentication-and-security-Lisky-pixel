"""
Privacy and Data Protection views for SafeBoda system.
Implements GDPR-style compliance features and data protection.
"""

from rest_framework import status, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.http import HttpResponse, JsonResponse
from django.core.exceptions import ValidationError
from django.db import transaction
import json
import logging
import zipfile
import io
from datetime import timedelta

from .models import (
    ConsentType, UserConsent, DataAccessLog, DataRetentionPolicy,
    DataDeletionRequest, DataExportRequest, EncryptedPersonalData,
    PrivacySettings, DataProcessingActivity, DataEncryption
)
from .serializers import (
    ConsentTypeSerializer, UserConsentSerializer, ConsentUpdateSerializer,
    DataAccessLogSerializer, DataRetentionPolicySerializer,
    DataDeletionRequestSerializer, DataDeletionCreateSerializer,
    DataExportRequestSerializer, DataExportCreateSerializer,
    EncryptedPersonalDataSerializer, PrivacySettingsSerializer,
    DataProcessingActivitySerializer, DataExportSerializer,
    ConsentStatusSerializer, AnonymizationRequestSerializer,
    RetentionPolicyInfoSerializer
)

User = get_user_model()
logger = logging.getLogger('security')


class DataExportView(APIView):
    """
    GET /api/privacy/data-export/ - Export user data (GDPR Right to Data Portability)
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Export user's personal data."""
        user = request.user
        
        # Log data access
        self.log_data_access(user, 'export', ['user_info', 'profile_data', 'consent_data'], 
                           'Data portability request', request)
        
        try:
            # Get user data
            user_data = self.get_user_data(user)
            
            # Create export request
            export_request = DataExportRequest.objects.create(
                user=user,
                data_types=['user_info', 'profile_data', 'consent_data'],
                format='json',
                expires_at=timezone.now() + timedelta(days=30)
            )
            
            # Generate export data
            export_data = DataExportSerializer({
                'user_info': user_data['user_info'],
                'profile_data': user_data['profile_data'],
                'consent_data': user_data['consent_data'],
                'privacy_settings': user_data['privacy_settings'],
                'access_logs': user_data['access_logs'],
                'export_metadata': {
                    'export_date': timezone.now().isoformat(),
                    'request_id': str(export_request.id),
                    'format': 'json',
                    'expires_at': export_request.expires_at.isoformat()
                }
            }).data
            
            # Mark as processed
            export_request.status = 'ready'
            export_request.processed_at = timezone.now()
            export_request.save()
            
            return Response(export_data, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Data export failed for user {user.id}: {e}")
            return Response({
                'error': 'Failed to export data'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def get_user_data(self, user):
        """Get comprehensive user data for export."""
        # Basic user information
        user_info = {
            'id': str(user.id),
            'username': user.username,
            'email': user.email,
            'phone_number': user.phone_number,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'date_joined': user.date_joined.isoformat(),
            'last_login': user.last_login.isoformat() if user.last_login else None,
            'is_active': user.is_active,
            'is_phone_verified': user.is_phone_verified,
            'is_email_verified': user.is_email_verified
        }
        
        # Profile data
        profile_data = {}
        if hasattr(user, 'profile'):
            profile = user.profile
            profile_data = {
                'national_id': profile.national_id,
                'district': profile.district.name if profile.district else None,
                'address': profile.address,
                'emergency_contact': profile.emergency_contact,
                'emergency_contact_name': profile.emergency_contact_name,
                'profile_completeness': profile.profile_completeness,
                'created_at': profile.created_at.isoformat(),
                'updated_at': profile.updated_at.isoformat()
            }
        
        # Consent data
        consent_data = []
        consents = UserConsent.objects.filter(user=user)
        for consent in consents:
            consent_data.append({
                'consent_type': consent.consent_type.name,
                'category': consent.consent_type.category,
                'status': consent.status,
                'granted_at': consent.granted_at.isoformat() if consent.granted_at else None,
                'expires_at': consent.expires_at.isoformat() if consent.expires_at else None,
                'version': consent.consent_version
            })
        
        # Privacy settings
        privacy_settings = {}
        if hasattr(user, 'privacy_settings'):
            settings = user.privacy_settings
            privacy_settings = {
                'allow_data_sharing': settings.allow_data_sharing,
                'allow_analytics': settings.allow_analytics,
                'allow_marketing': settings.allow_marketing,
                'allow_location_tracking': settings.allow_location_tracking,
                'email_notifications': settings.email_notifications,
                'sms_notifications': settings.sms_notifications,
                'push_notifications': settings.push_notifications,
                'notify_on_data_access': settings.notify_on_data_access,
                'monthly_privacy_report': settings.monthly_privacy_report
            }
        
        # Access logs (last 30 days)
        access_logs = []
        logs = DataAccessLog.objects.filter(
            user=user,
            timestamp__gte=timezone.now() - timedelta(days=30)
        )[:100]  # Limit to 100 recent logs
        
        for log in logs:
            access_logs.append({
                'access_type': log.access_type,
                'data_category': log.data_category,
                'purpose': log.purpose,
                'timestamp': log.timestamp.isoformat(),
                'accessed_by': log.accessed_by.username if log.accessed_by else 'System'
            })
        
        return {
            'user_info': user_info,
            'profile_data': profile_data,
            'consent_data': consent_data,
            'privacy_settings': privacy_settings,
            'access_logs': access_logs
        }
    
    def log_data_access(self, user, access_type, data_fields, purpose, request):
        """Log data access for audit purposes."""
        DataAccessLog.objects.create(
            user=user,
            accessed_by=request.user if request.user != user else None,
            access_type=access_type,
            data_category='personal_info',
            data_fields=data_fields,
            purpose=purpose,
            ip_address=self.get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            retention_until=timezone.now() + timedelta(days=2555)  # 7 years
        )
    
    def get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class DataDeletionView(APIView):
    """
    DELETE /api/privacy/data-deletion/ - Request data deletion (GDPR Right to be Forgotten)
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def delete(self, request):
        """Request deletion of user data."""
        serializer = DataDeletionCreateSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            
            # Log data access
            self.log_data_access(user, 'delete', ['user_data'], 
                               'Right to be forgotten request', request)
            
            # Create deletion request
            deletion_request = DataDeletionRequest.objects.create(
                user=user,
                request_type=serializer.validated_data['request_type'],
                data_types=serializer.validated_data.get('data_types', []),
                reason=serializer.validated_data.get('reason', ''),
                status='pending'
            )
            
            # For demo purposes, we'll process immediately
            # In production, this would go through approval workflow
            self.process_deletion_request(deletion_request)
            
            return Response({
                'message': 'Data deletion request submitted successfully',
                'request_id': str(deletion_request.id),
                'status': deletion_request.status
            }, status=status.HTTP_202_ACCEPTED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def process_deletion_request(self, deletion_request):
        """Process data deletion request."""
        user = deletion_request.user
        
        try:
            with transaction.atomic():
                deletion_details = {}
                
                if deletion_request.request_type == 'full_deletion':
                    # Anonymize user data instead of deleting (for audit purposes)
                    user.username = f"deleted_user_{user.id}"
                    user.email = f"deleted_{user.id}@safeboda.com"
                    user.first_name = "Deleted"
                    user.last_name = "User"
                    user.phone_number = None
                    user.is_active = False
                    user.save()
                    
                    deletion_details['user_anonymized'] = True
                    
                    # Anonymize profile if exists
                    if hasattr(user, 'profile'):
                        profile = user.profile
                        profile.national_id = None
                        profile.address = None
                        profile.emergency_contact = None
                        profile.emergency_contact_name = None
                        profile.save()
                        deletion_details['profile_anonymized'] = True
                
                elif deletion_request.request_type == 'partial_deletion':
                    # Delete specific data types
                    for data_type in deletion_request.data_types:
                        if data_type == 'contact_info':
                            user.phone_number = None
                            user.email = f"deleted_{user.id}@safeboda.com"
                            user.save()
                            deletion_details['contact_info_deleted'] = True
                        
                        elif data_type == 'location_data':
                            # In a real implementation, delete location data
                            deletion_details['location_data_deleted'] = True
                
                # Update deletion request
                deletion_request.status = 'completed'
                deletion_request.processed_at = timezone.now()
                deletion_request.completion_details = deletion_details
                deletion_request.save()
                
                logger.info(f"Data deletion completed for user {user.id}")
                
        except Exception as e:
            logger.error(f"Data deletion failed for user {user.id}: {e}")
            deletion_request.status = 'rejected'
            deletion_request.rejection_reason = str(e)
            deletion_request.save()
    
    def log_data_access(self, user, access_type, data_fields, purpose, request):
        """Log data access for audit purposes."""
        DataAccessLog.objects.create(
            user=user,
            accessed_by=request.user,
            access_type=access_type,
            data_category='personal_info',
            data_fields=data_fields,
            purpose=purpose,
            ip_address=self.get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            retention_until=timezone.now() + timedelta(days=2555)  # 7 years
        )
    
    def get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class AuditLogView(APIView):
    """
    GET /api/privacy/audit-log/ - Personal data access log
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get user's data access audit log."""
        user = request.user
        
        # Get query parameters
        days = int(request.query_params.get('days', 30))
        access_type = request.query_params.get('access_type')
        
        # Build query
        logs_query = DataAccessLog.objects.filter(user=user)
        
        if access_type:
            logs_query = logs_query.filter(access_type=access_type)
        
        # Filter by date range
        start_date = timezone.now() - timedelta(days=days)
        logs_query = logs_query.filter(timestamp__gte=start_date)
        
        # Order and limit results
        logs = logs_query.order_by('-timestamp')[:100]
        
        # Log this access
        self.log_data_access(user, 'read', ['audit_log'], 
                           'User requested audit log', request)
        
        serializer = DataAccessLogSerializer(logs, many=True)
        
        return Response({
            'logs': serializer.data,
            'total': logs.count(),
            'period_days': days,
            'access_type_filter': access_type
        }, status=status.HTTP_200_OK)
    
    def log_data_access(self, user, access_type, data_fields, purpose, request):
        """Log data access for audit purposes."""
        DataAccessLog.objects.create(
            user=user,
            accessed_by=request.user,
            access_type=access_type,
            data_category='audit_data',
            data_fields=data_fields,
            purpose=purpose,
            ip_address=self.get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            retention_until=timezone.now() + timedelta(days=2555)  # 7 years
        )
    
    def get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class ConsentManagementView(APIView):
    """
    POST /api/privacy/consent/ - Update consent preferences
    GET /api/privacy/consent/ - Get current consent status
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get current consent status."""
        user = request.user
        
        # Get all consent types
        consent_types = ConsentType.objects.filter(is_active=True)
        
        # Get user's current consents
        user_consents = UserConsent.objects.filter(user=user)
        consent_dict = {consent.consent_type_id: consent for consent in user_consents}
        
        # Build consent status
        consent_status = []
        for consent_type in consent_types:
            user_consent = consent_dict.get(consent_type.id)
            
            status_data = {
                'consent_type_id': consent_type.id,
                'consent_type_name': consent_type.name,
                'consent_type_category': consent_type.category,
                'status': user_consent.status if user_consent else 'denied',
                'is_valid': user_consent.is_valid() if user_consent else False,
                'granted_at': user_consent.granted_at if user_consent else None,
                'expires_at': user_consent.expires_at if user_consent else None
            }
            consent_status.append(status_data)
        
        # Log this access
        self.log_data_access(user, 'read', ['consent_data'], 
                           'User requested consent status', request)
        
        serializer = ConsentStatusSerializer(consent_status, many=True)
        
        return Response({
            'consent_status': serializer.data,
            'total_consent_types': len(consent_status)
        }, status=status.HTTP_200_OK)
    
    def post(self, request):
        """Update consent preferences."""
        serializer = ConsentUpdateSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            consent_type_id = serializer.validated_data['consent_type_id']
            new_status = serializer.validated_data['status']
            
            try:
                consent_type = ConsentType.objects.get(id=consent_type_id, is_active=True)
                
                # Get or create user consent
                user_consent, created = UserConsent.objects.get_or_create(
                    user=user,
                    consent_type=consent_type,
                    defaults={
                        'status': new_status,
                        'ip_address': self.get_client_ip(request),
                        'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                        'consent_version': '1.0'
                    }
                )
                
                if not created:
                    # Update existing consent
                    user_consent.status = new_status
                    user_consent.ip_address = self.get_client_ip(request)
                    user_consent.user_agent = request.META.get('HTTP_USER_AGENT', '')
                    
                    if new_status == 'granted':
                        user_consent.granted_at = timezone.now()
                        user_consent.withdrawn_at = None
                        # Set expiration based on consent type
                        if consent_type.retention_period_days:
                            user_consent.expires_at = timezone.now() + timedelta(days=consent_type.retention_period_days)
                    elif new_status == 'withdrawn':
                        user_consent.withdrawn_at = timezone.now()
                        user_consent.expires_at = None
                    
                    user_consent.save()
                
                # Log this consent change
                self.log_data_access(user, 'write', ['consent_data'], 
                                   f'Consent {new_status} for {consent_type.name}', request)
                
                return Response({
                    'message': f'Consent {new_status} successfully',
                    'consent_type': consent_type.name,
                    'status': new_status
                }, status=status.HTTP_200_OK)
                
            except ConsentType.DoesNotExist:
                return Response({
                    'error': 'Invalid consent type'
                }, status=status.HTTP_404_NOT_FOUND)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def log_data_access(self, user, access_type, data_fields, purpose, request):
        """Log data access for audit purposes."""
        DataAccessLog.objects.create(
            user=user,
            accessed_by=request.user,
            access_type=access_type,
            data_category='consent_data',
            data_fields=data_fields,
            purpose=purpose,
            ip_address=self.get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            retention_until=timezone.now() + timedelta(days=2555)  # 7 years
        )
    
    def get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class DataAnonymizationView(APIView):
    """
    POST /api/privacy/anonymize/ - Anonymize user data
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """Anonymize user data."""
        serializer = AnonymizationRequestSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            
            # Log data access
            self.log_data_access(user, 'anonymize', ['user_data'], 
                               'Data anonymization request', request)
            
            anonymization_method = serializer.validated_data.get('anonymization_method', 'pseudonymization')
            data_types = serializer.validated_data.get('data_types', [])
            reason = serializer.validated_data.get('reason', '')
            
            try:
                with transaction.atomic():
                    anonymized_data = {}
                    
                    if not data_types or 'user_profile' in data_types:
                        # Anonymize basic user data
                        if anonymization_method == 'pseudonymization':
                            user.username = f"anon_{user.id}"
                            user.email = f"anon_{user.id}@safeboda.com"
                            user.first_name = "Anonymous"
                            user.last_name = "User"
                            anonymized_data['basic_info'] = True
                        
                        elif anonymization_method == 'generalization':
                            user.first_name = "User"
                            user.last_name = "User"
                            anonymized_data['basic_info'] = True
                        
                        user.save()
                    
                    if not data_types or 'contact_info' in data_types:
                        # Anonymize contact information
                        user.phone_number = None
                        user.email = f"anon_{user.id}@safeboda.com"
                        anonymized_data['contact_info'] = True
                        user.save()
                    
                    if not data_types or 'profile_data' in data_types:
                        # Anonymize profile data
                        if hasattr(user, 'profile'):
                            profile = user.profile
                            profile.national_id = None
                            profile.address = None
                            profile.emergency_contact = None
                            profile.emergency_contact_name = None
                            profile.save()
                            anonymized_data['profile_data'] = True
                    
                    # Create audit log entry
                    DataAccessLog.objects.create(
                        user=user,
                        accessed_by=request.user,
                        access_type='anonymize',
                        data_category='personal_info',
                        data_fields=data_types or ['all_data'],
                        purpose=f'Data anonymization: {reason}',
                        ip_address=self.get_client_ip(request),
                        user_agent=request.META.get('HTTP_USER_AGENT', ''),
                        retention_until=timezone.now() + timedelta(days=2555)  # 7 years
                    )
                    
                    return Response({
                        'message': 'Data anonymization completed successfully',
                        'anonymization_method': anonymization_method,
                        'anonymized_data': anonymized_data,
                        'reason': reason
                    }, status=status.HTTP_200_OK)
                    
            except Exception as e:
                logger.error(f"Data anonymization failed for user {user.id}: {e}")
                return Response({
                    'error': 'Failed to anonymize data'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def log_data_access(self, user, access_type, data_fields, purpose, request):
        """Log data access for audit purposes."""
        DataAccessLog.objects.create(
            user=user,
            accessed_by=request.user,
            access_type=access_type,
            data_category='personal_info',
            data_fields=data_fields,
            purpose=purpose,
            ip_address=self.get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            retention_until=timezone.now() + timedelta(days=2555)  # 7 years
        )
    
    def get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class RetentionPolicyView(APIView):
    """
    GET /api/privacy/retention-policy/ - Data retention information
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get data retention policy information."""
        # Get all active retention policies
        policies = DataRetentionPolicy.objects.filter(is_active=True)
        
        # Log this access
        self.log_data_access(request.user, 'read', ['retention_policies'], 
                           'User requested retention policy information', request)
        
        serializer = RetentionPolicyInfoSerializer(policies, many=True)
        
        return Response({
            'retention_policies': serializer.data,
            'total_policies': len(serializer.data),
            'note': 'These policies define how long your data is retained and under what legal basis.'
        }, status=status.HTTP_200_OK)
    
    def log_data_access(self, user, access_type, data_fields, purpose, request):
        """Log data access for audit purposes."""
        DataAccessLog.objects.create(
            user=user,
            accessed_by=request.user,
            access_type=access_type,
            data_category='policy_data',
            data_fields=data_fields,
            purpose=purpose,
            ip_address=self.get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            retention_until=timezone.now() + timedelta(days=2555)  # 7 years
        )
    
    def get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class PrivacySettingsView(APIView):
    """
    GET /api/privacy/settings/ - Get privacy settings
    PUT /api/privacy/settings/ - Update privacy settings
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get user's privacy settings."""
        user = request.user
        
        # Get or create privacy settings
        privacy_settings, created = PrivacySettings.objects.get_or_create(user=user)
        
        # Log this access
        self.log_data_access(user, 'read', ['privacy_settings'], 
                           'User requested privacy settings', request)
        
        serializer = PrivacySettingsSerializer(privacy_settings)
        
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    def put(self, request):
        """Update user's privacy settings."""
        user = request.user
        
        # Get or create privacy settings
        privacy_settings, created = PrivacySettings.objects.get_or_create(user=user)
        
        serializer = PrivacySettingsSerializer(privacy_settings, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            
            # Log this access
            self.log_data_access(user, 'write', ['privacy_settings'], 
                               'User updated privacy settings', request)
            
            return Response({
                'message': 'Privacy settings updated successfully',
                'settings': serializer.data
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def log_data_access(self, user, access_type, data_fields, purpose, request):
        """Log data access for audit purposes."""
        DataAccessLog.objects.create(
            user=user,
            accessed_by=request.user,
            access_type=access_type,
            data_category='privacy_settings',
            data_fields=data_fields,
            purpose=purpose,
            ip_address=self.get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            retention_until=timezone.now() + timedelta(days=2555)  # 7 years
        )
    
    def get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip