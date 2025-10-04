"""
Serializers for authentication endpoints.
"""

from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from .models import User, SecurityEvent


class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration."""
    password = serializers.CharField(write_only=True, validators=[validate_password])
    password_confirm = serializers.CharField(write_only=True)
    
    class Meta:
        model = User
        fields = ('username', 'email', 'phone_number', 'password', 'password_confirm', 'first_name', 'last_name')
    
    def validate(self, attrs):
        """Validate password confirmation."""
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords don't match.")
        return attrs
    
    def create(self, validated_data):
        """Create new user."""
        validated_data.pop('password_confirm')
        user = User.objects.create_user(**validated_data)
        return user


class BasicAuthSerializer(serializers.Serializer):
    """Serializer for basic authentication."""
    username = serializers.CharField()
    password = serializers.CharField()
    
    def validate(self, attrs):
        """Validate credentials."""
        username = attrs.get('username')
        password = attrs.get('password')
        
        if username and password:
            user = authenticate(username=username, password=password)
            if not user:
                raise serializers.ValidationError('Invalid credentials.')
            if not user.is_active:
                raise serializers.ValidationError('Account is disabled.')
            if user.is_account_locked():
                raise serializers.ValidationError('Account is locked.')
            attrs['user'] = user
        else:
            raise serializers.ValidationError('Must include username and password.')
        
        return attrs


class SessionLoginSerializer(serializers.Serializer):
    """Serializer for session-based login."""
    username = serializers.CharField()
    password = serializers.CharField()
    remember_me = serializers.BooleanField(default=False)
    
    def validate(self, attrs):
        """Validate credentials."""
        username = attrs.get('username')
        password = attrs.get('password')
        
        if username and password:
            user = authenticate(username=username, password=password)
            if not user:
                raise serializers.ValidationError('Invalid credentials.')
            if not user.is_active:
                raise serializers.ValidationError('Account is disabled.')
            if user.is_account_locked():
                raise serializers.ValidationError('Account is locked.')
            attrs['user'] = user
        else:
            raise serializers.ValidationError('Must include username and password.')
        
        return attrs


class JWTTokenSerializer(serializers.Serializer):
    """Serializer for JWT token generation."""
    username = serializers.CharField()
    password = serializers.CharField()
    
    def validate(self, attrs):
        """Validate credentials."""
        username = attrs.get('username')
        password = attrs.get('password')
        
        if username and password:
            user = authenticate(username=username, password=password)
            if not user:
                raise serializers.ValidationError('Invalid credentials.')
            if not user.is_active:
                raise serializers.ValidationError('Account is disabled.')
            if user.is_account_locked():
                raise serializers.ValidationError('Account is locked.')
            attrs['user'] = user
        else:
            raise serializers.ValidationError('Must include username and password.')
        
        return attrs


class JWTRefreshSerializer(serializers.Serializer):
    """Serializer for JWT token refresh."""
    refresh = serializers.CharField()


class UserSerializer(serializers.ModelSerializer):
    """Serializer for user data."""
    
    class Meta:
        model = User
        fields = ('id', 'username', 'email', 'first_name', 'last_name', 'phone_number', 
                 'is_phone_verified', 'is_email_verified', 'date_joined', 'last_login')
        read_only_fields = ('id', 'date_joined', 'last_login')


class SecurityEventSerializer(serializers.ModelSerializer):
    """Serializer for security events."""
    
    class Meta:
        model = SecurityEvent
        fields = ('id', 'event_type', 'ip_address', 'user_agent', 'details', 'timestamp')
        read_only_fields = ('id', 'timestamp')
