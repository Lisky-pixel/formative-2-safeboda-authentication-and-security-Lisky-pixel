"""
URL configuration for UAS app.
"""

from django.urls import path
from . import views

urlpatterns = [
    # User Registration
    path('register/', views.UserRegistrationView.as_view(), name='uas_register'),
    
    # Phone Verification
    path('verify-phone/', views.PhoneVerificationView.as_view(), name='verify_phone'),
    path('verify-phone/confirm/', views.VerifyPhoneView.as_view(), name='verify_phone_confirm'),
    
    # Email Verification
    path('verify-email/', views.EmailVerificationView.as_view(), name='verify_email'),
    path('verify-email/confirm/', views.VerifyEmailView.as_view(), name='verify_email_confirm'),
    
    # Password Reset
    path('password-reset/', views.PasswordResetView.as_view(), name='password_reset'),
    path('password-reset/confirm/', views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    
    # Account Management
    path('account/status/', views.AccountStatusView.as_view(), name='account_status'),
    path('account/recover/', views.AccountRecoveryView.as_view(), name='account_recovery'),
    
    # Rwanda Districts
    path('districts/', views.RwandaDistrictsView.as_view(), name='rwanda_districts'),
]
