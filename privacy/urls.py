"""
URL configuration for privacy app.
"""

from django.urls import path
from . import views

urlpatterns = [
    # Data Export (GDPR Right to Data Portability)
    path('data-export/', views.DataExportView.as_view(), name='data_export'),
    
    # Data Deletion (GDPR Right to be Forgotten)
    path('data-deletion/', views.DataDeletionView.as_view(), name='data_deletion'),
    
    # Audit Log (GDPR Article 30 requirement)
    path('audit-log/', views.AuditLogView.as_view(), name='audit_log'),
    
    # Consent Management
    path('consent/', views.ConsentManagementView.as_view(), name='consent_management'),
    
    # Data Anonymization
    path('anonymize/', views.DataAnonymizationView.as_view(), name='data_anonymization'),
    
    # Data Retention Policy Information
    path('retention-policy/', views.RetentionPolicyView.as_view(), name='retention_policy'),
    
    # Privacy Settings
    path('settings/', views.PrivacySettingsView.as_view(), name='privacy_settings'),
]