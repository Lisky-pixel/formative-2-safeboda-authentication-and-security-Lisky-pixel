"""
Authentication views for SafeBoda system.
Implements Basic, Session, and JWT authentication methods.
"""

from rest_framework import status, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
# from django_ratelimit.decorators import ratelimit
from django.utils import timezone
import logging

from .models import User, SecurityEvent
from .serializers import (
    BasicAuthSerializer, SessionLoginSerializer, JWTTokenSerializer,
    JWTRefreshSerializer, UserSerializer, UserRegistrationSerializer
)

logger = logging.getLogger('security')


class BasicAuthenticationView(APIView):
    """
    Basic authentication endpoint for API testing and development.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        """Authenticate using basic auth credentials."""
        serializer = BasicAuthSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            
            # Log successful authentication
            self.log_security_event(user, 'login_success', request)
            
            # Reset failed login attempts
            user.failed_login_attempts = 0
            user.last_login_ip = self.get_client_ip(request)
            user.save(update_fields=['failed_login_attempts', 'last_login_ip'])
            
            return Response({
                'message': 'Authentication successful',
                'user': UserSerializer(user).data
            }, status=status.HTTP_200_OK)
        
        # Log failed authentication
        self.log_security_event(None, 'login_failed', request)
        
        return Response(serializer.errors, status=status.HTTP_401_UNAUTHORIZED)
    
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
        SecurityEvent.objects.create(
            user=user,
            event_type=event_type,
            ip_address=self.get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details={'endpoint': 'basic_auth'}
        )


class SessionLoginView(APIView):
    """
    Session-based login for web dashboard users.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        """Login using session authentication."""
        serializer = SessionLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            remember_me = serializer.validated_data.get('remember_me', False)
            
            # Login user
            login(request, user)
            
            # Set session expiry
            if not remember_me:
                request.session.set_expiry(0)  # Browser close
            else:
                request.session.set_expiry(60 * 60 * 24 * 7)  # 7 days
            
            # Log successful authentication
            self.log_security_event(user, 'login_success', request)
            
            # Reset failed login attempts
            user.failed_login_attempts = 0
            user.last_login_ip = self.get_client_ip(request)
            user.save(update_fields=['failed_login_attempts', 'last_login_ip'])
            
            return Response({
                'message': 'Login successful',
                'user': UserSerializer(user).data
            }, status=status.HTTP_200_OK)
        
        # Log failed authentication
        self.log_security_event(None, 'login_failed', request)
        
        return Response(serializer.errors, status=status.HTTP_401_UNAUTHORIZED)
    
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
        SecurityEvent.objects.create(
            user=user,
            event_type=event_type,
            ip_address=self.get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details={'endpoint': 'session_login'}
        )


class SessionLogoutView(APIView):
    """
    Session-based logout for web dashboard users.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """Logout user from session."""
        user = request.user
        
        # Log logout event
        self.log_security_event(user, 'logout', request)
        
        # Logout user
        logout(request)
        
        return Response({
            'message': 'Logout successful'
        }, status=status.HTTP_200_OK)
    
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
        SecurityEvent.objects.create(
            user=user,
            event_type=event_type,
            ip_address=self.get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details={'endpoint': 'session_logout'}
        )


class JWTTokenView(APIView):
    """
    JWT token generation for mobile applications.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        """Generate JWT tokens."""
        serializer = JWTTokenSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            
            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)
            access_token = refresh.access_token
            
            # Log successful authentication
            self.log_security_event(user, 'login_success', request)
            
            # Reset failed login attempts
            user.failed_login_attempts = 0
            user.last_login_ip = self.get_client_ip(request)
            user.save(update_fields=['failed_login_attempts', 'last_login_ip'])
            
            return Response({
                'access': str(access_token),
                'refresh': str(refresh),
                'user': UserSerializer(user).data
            }, status=status.HTTP_200_OK)
        
        # Log failed authentication
        self.log_security_event(None, 'login_failed', request)
        
        return Response(serializer.errors, status=status.HTTP_401_UNAUTHORIZED)
    
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
        SecurityEvent.objects.create(
            user=user,
            event_type=event_type,
            ip_address=self.get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details={'endpoint': 'jwt_token'}
        )


class JWTRefreshView(APIView):
    """
    JWT token refresh for mobile applications.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        """Refresh JWT tokens."""
        serializer = JWTRefreshSerializer(data=request.data)
        if serializer.is_valid():
            refresh_token = serializer.validated_data['refresh']
            
            try:
                refresh = RefreshToken(refresh_token)
                access_token = refresh.access_token
                
                return Response({
                    'access': str(access_token),
                    'refresh': str(refresh)
                }, status=status.HTTP_200_OK)
            except Exception as e:
                return Response({
                    'error': 'Invalid refresh token'
                }, status=status.HTTP_401_UNAUTHORIZED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class JWTVerifyView(APIView):
    """
    JWT token verification endpoint.
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """Verify JWT token."""
        return Response({
            'message': 'Token is valid',
            'user': UserSerializer(request.user).data
        }, status=status.HTTP_200_OK)


class AuthMethodsView(APIView):
    """
    List available authentication methods.
    """
    permission_classes = [permissions.AllowAny]
    
    def get(self, request):
        """Get available authentication methods."""
        methods = [
            {
                'name': 'Basic Authentication',
                'endpoint': '/api/auth/basic/',
                'description': 'For API testing and development',
                'type': 'basic'
            },
            {
                'name': 'Session Authentication',
                'endpoint': '/api/auth/session/login/',
                'description': 'For web dashboard users',
                'type': 'session'
            },
            {
                'name': 'JWT Authentication',
                'endpoint': '/api/auth/jwt-token/',
                'description': 'For mobile applications',
                'type': 'jwt'
            }
        ]
        
        return Response({
            'methods': methods,
            'total': len(methods)
        }, status=status.HTTP_200_OK)


class UserRegistrationView(APIView):
    """
    User registration endpoint.
    """
    permission_classes = [permissions.AllowAny]
    
    def post(self, request):
        """Register new user."""
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            
            # Log registration event
            self.log_security_event(user, 'login_success', request)
            
            return Response({
                'message': 'User registered successfully',
                'user': UserSerializer(user).data
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
        SecurityEvent.objects.create(
            user=user,
            event_type=event_type,
            ip_address=self.get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            details={'endpoint': 'user_registration'}
        )