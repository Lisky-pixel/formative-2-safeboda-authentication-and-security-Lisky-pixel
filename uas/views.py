"""
UAS (User Authentication Service) views for SafeBoda system.
Implements centralized user management with Rwanda integration.
"""

from rest_framework import status, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
import logging

from .models import (
    UserProfile, RwandaDistrict, VerificationCode, AccountRecovery,
    NationalIDValidator
)
from .serializers import (
    UserRegistrationSerializer, PhoneVerificationSerializer,
    EmailVerificationSerializer, VerificationCodeSerializer,
    PasswordResetSerializer, PasswordResetConfirmSerializer,
    AccountRecoverySerializer, AccountStatusSerializer,
    RwandaDistrictSerializer, UserProfileSerializer,
    VerificationCodeGenerator
)

User = get_user_model()
logger = logging.getLogger('security')


class UserRegistrationView(APIView):
    """
    Enhanced user registration with Rwanda integration.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        """Register new user with Rwanda-specific data."""
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            
            # Log registration event
            self.log_security_event(user, 'user_registration', request)
            
            return Response({
                'message': 'User registered successfully',
                'user': AccountStatusSerializer(user).data
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def log_security_event(self, user, event_type, request):
        """Log security event."""
        from authentication.models import SecurityEvent
        SecurityEvent.objects.create(
            user=user,
            event_type=event_type,
            ip_address=self.get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details={'endpoint': 'uas_registration'}
        )


class PhoneVerificationView(APIView):
    """
    SMS verification endpoint (design only - no actual SMS).
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """Send SMS verification code."""
        serializer = PhoneVerificationSerializer(data=request.data)
        if serializer.is_valid():
            phone_number = serializer.validated_data['phone_number']
            
            # Create verification code
            verification_code = VerificationCodeGenerator.create_verification_code(
                user=request.user,
                code_type='phone',
                phone_number=phone_number,
                expires_in_minutes=10
            )
            
            # In a real implementation, send SMS here
            # For now, we'll just log it
            logger.info(f"SMS verification code for {phone_number}: {verification_code.code}")
            
            return Response({
                'message': 'Verification code sent to phone number',
                'phone_number': phone_number,
                'expires_in': 10  # minutes
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmailVerificationView(APIView):
    """
    Email verification endpoint.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """Send email verification code."""
        serializer = EmailVerificationSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            
            # Create verification code
            verification_code = VerificationCodeGenerator.create_verification_code(
                user=request.user,
                code_type='email',
                email=email,
                expires_in_minutes=30
            )
            
            # Send verification email
            try:
                send_mail(
                    'SafeBoda Email Verification',
                    f'Your verification code is: {verification_code.code}\n\nThis code expires in 30 minutes.',
                    settings.DEFAULT_FROM_EMAIL,
                    [email],
                    fail_silently=False,
                )
                
                return Response({
                    'message': 'Verification code sent to email',
                    'email': email,
                    'expires_in': 30  # minutes
                }, status=status.HTTP_200_OK)
                
            except Exception as e:
                logger.error(f"Failed to send verification email: {e}")
                return Response({
                    'error': 'Failed to send verification email'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyPhoneView(APIView):
    """
    Verify phone number with SMS code.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """Verify phone number with code."""
        serializer = VerificationCodeSerializer(data=request.data)
        if serializer.is_valid():
            code = serializer.validated_data['code']
            phone_number = serializer.validated_data.get('phone_number')
            
            # Find valid verification code
            try:
                verification_code = VerificationCode.objects.get(
                    user=request.user,
                    code=code,
                    code_type='phone',
                    phone_number=phone_number,
                    is_used=False
                )
                
                if verification_code.is_expired():
                    return Response({
                        'error': 'Verification code has expired'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                # Mark code as used
                verification_code.mark_as_used()
                
                # Update user phone verification status
                request.user.is_phone_verified = True
                request.user.save(update_fields=['is_phone_verified'])
                
                # Update profile completeness
                request.user.profile.calculate_completeness()
                
                return Response({
                    'message': 'Phone number verified successfully',
                    'is_phone_verified': True
                }, status=status.HTTP_200_OK)
                
            except VerificationCode.DoesNotExist:
                return Response({
                    'error': 'Invalid verification code'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmailView(APIView):
    """
    Verify email address with email code.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """Verify email address with code."""
        serializer = VerificationCodeSerializer(data=request.data)
        if serializer.is_valid():
            code = serializer.validated_data['code']
            email = serializer.validated_data.get('email')
            
            # Find valid verification code
            try:
                verification_code = VerificationCode.objects.get(
                    user=request.user,
                    code=code,
                    code_type='email',
                    email=email,
                    is_used=False
                )
                
                if verification_code.is_expired():
                    return Response({
                        'error': 'Verification code has expired'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                # Mark code as used
                verification_code.mark_as_used()
                
                # Update user email verification status
                request.user.is_email_verified = True
                request.user.save(update_fields=['is_email_verified'])
                
                # Update profile completeness
                request.user.profile.calculate_completeness()
                
                return Response({
                    'message': 'Email address verified successfully',
                    'is_email_verified': True
                }, status=status.HTTP_200_OK)
                
            except VerificationCode.DoesNotExist:
                return Response({
                    'error': 'Invalid verification code'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetView(APIView):
    """
    Password reset request endpoint.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        """Request password reset."""
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data.get('email')
            phone_number = serializer.validated_data.get('phone_number')
            national_id = serializer.validated_data.get('national_id')
            
            # Find user by provided information
            user = None
            if email:
                try:
                    user = User.objects.get(email=email)
                except User.DoesNotExist:
                    pass
            
            if not user and phone_number:
                try:
                    user = User.objects.get(phone_number=phone_number)
                except User.DoesNotExist:
                    pass
            
            if not user and national_id:
                try:
                    profile = UserProfile.objects.get(national_id=national_id)
                    user = profile.user
                except UserProfile.DoesNotExist:
                    pass
            
            if not user:
                return Response({
                    'error': 'No account found with the provided information'
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Create password reset code
            verification_code = VerificationCodeGenerator.create_verification_code(
                user=user,
                code_type='password_reset',
                email=user.email,
                expires_in_minutes=30
            )
            
            # Send password reset email
            try:
                send_mail(
                    'SafeBoda Password Reset',
                    f'Your password reset code is: {verification_code.code}\n\nThis code expires in 30 minutes.',
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=False,
                )
                
                return Response({
                    'message': 'Password reset code sent to your email',
                    'expires_in': 30
                }, status=status.HTTP_200_OK)
                
            except Exception as e:
                logger.error(f"Failed to send password reset email: {e}")
                return Response({
                    'error': 'Failed to send password reset email'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PasswordResetConfirmView(APIView):
    """
    Password reset confirmation endpoint.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        """Confirm password reset with code."""
        serializer = PasswordResetConfirmSerializer(data=request.data)
        if serializer.is_valid():
            code = serializer.validated_data['code']
            new_password = serializer.validated_data['new_password']
            
            # Find valid verification code
            try:
                verification_code = VerificationCode.objects.get(
                    code=code,
                    code_type='password_reset',
                    is_used=False
                )
                
                if verification_code.is_expired():
                    return Response({
                        'error': 'Verification code has expired'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                # Mark code as used
                verification_code.mark_as_used()
                
                # Update user password
                user = verification_code.user
                user.set_password(new_password)
                user.save()
                
                # Log password change event
                self.log_security_event(user, 'password_change', request)
                
                return Response({
                    'message': 'Password reset successfully'
                }, status=status.HTTP_200_OK)
                
            except VerificationCode.DoesNotExist:
                return Response({
                    'error': 'Invalid verification code'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def log_security_event(self, user, event_type, request):
        """Log security event."""
        from authentication.models import SecurityEvent
        SecurityEvent.objects.create(
            user=user,
            event_type=event_type,
            ip_address=self.get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details={'endpoint': 'password_reset_confirm'}
        )


class AccountStatusView(APIView):
    """
    Get account verification status.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get user account status."""
        serializer = AccountStatusSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class AccountRecoveryView(APIView):
    """
    Account recovery endpoint.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        """Request account recovery."""
        serializer = AccountRecoverySerializer(data=request.data)
        if serializer.is_valid():
            recovery_method = serializer.validated_data['recovery_method']
            recovery_value = serializer.validated_data['recovery_value']
            
            # Find user by recovery method
            user = None
            if recovery_method == 'phone':
                try:
                    user = User.objects.get(phone_number=recovery_value)
                except User.DoesNotExist:
                    pass
            elif recovery_method == 'email':
                try:
                    user = User.objects.get(email=recovery_value)
                except User.DoesNotExist:
                    pass
            elif recovery_method == 'national_id':
                try:
                    profile = UserProfile.objects.get(national_id=recovery_value)
                    user = profile.user
                except UserProfile.DoesNotExist:
                    pass
            
            if not user:
                return Response({
                    'error': 'No account found with the provided information'
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Create account recovery request
            recovery_request = AccountRecovery.objects.create(
                user=user,
                recovery_method=recovery_method,
                recovery_value=recovery_value,
                ip_address=self.get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')
            )
            
            # Create verification code
            verification_code = VerificationCodeGenerator.create_verification_code(
                user=user,
                code_type='account_recovery',
                phone_number=user.phone_number if recovery_method == 'phone' else None,
                email=user.email if recovery_method == 'email' else None,
                expires_in_minutes=30
            )
            
            recovery_request.verification_code = verification_code
            recovery_request.save()
            
            # Send recovery code
            if recovery_method == 'phone':
                # In a real implementation, send SMS here
                logger.info(f"Account recovery code for {recovery_value}: {verification_code.code}")
                message = 'Account recovery code sent to your phone number'
            else:
                # Send email
                try:
                    send_mail(
                        'SafeBoda Account Recovery',
                        f'Your account recovery code is: {verification_code.code}\n\nThis code expires in 30 minutes.',
                        settings.DEFAULT_FROM_EMAIL,
                        [user.email],
                        fail_silently=False,
                    )
                    message = 'Account recovery code sent to your email'
                except Exception as e:
                    logger.error(f"Failed to send recovery email: {e}")
                    return Response({
                        'error': 'Failed to send recovery email'
                    }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            return Response({
                'message': message,
                'recovery_id': str(recovery_request.id),
                'expires_in': 30
            }, status=status.HTTP_200_OK)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get_client_ip(self, request):
        """Get client IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class RwandaDistrictsView(APIView):
    """
    Get Rwanda districts for registration.
    """
    permission_classes = [permissions.AllowAny]
    
    def get(self, request):
        """Get list of Rwanda districts."""
        districts = RwandaDistrict.objects.filter(is_active=True)
        serializer = RwandaDistrictSerializer(districts, many=True)
        
        return Response({
            'districts': serializer.data,
            'total': districts.count()
        }, status=status.HTTP_200_OK)