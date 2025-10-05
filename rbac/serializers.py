"""
Serializers for RBAC (Role-Based Access Control) endpoints.
"""

from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.utils import timezone
from .models import (
    Permission, Role, RolePermission, UserRole, GovernmentAccessRequest,
    PermissionAuditLog, AccessControlRule, RoleHierarchy, DriverEarningsProtection
)

User = get_user_model()


class PermissionSerializer(serializers.ModelSerializer):
    """Serializer for permissions."""
    
    class Meta:
        model = Permission
        fields = [
            'id', 'name', 'codename', 'category', 'description',
            'resource_type', 'action', 'is_system_permission',
            'is_active', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class RoleSerializer(serializers.ModelSerializer):
    """Serializer for roles."""
    permissions_count = serializers.SerializerMethodField()
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)
    
    class Meta:
        model = Role
        fields = [
            'id', 'name', 'codename', 'role_type', 'description',
            'hierarchy_level', 'is_system_role', 'is_active',
            'permissions_count', 'created_by_username',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
    
    def get_permissions_count(self, obj):
        """Get count of permissions for this role."""
        return obj.permissions.filter(is_active=True).count()


class RoleDetailSerializer(RoleSerializer):
    """Detailed serializer for roles with permissions."""
    permissions = PermissionSerializer(many=True, read_only=True)
    
    class Meta(RoleSerializer.Meta):
        fields = RoleSerializer.Meta.fields + ['permissions']


class RolePermissionSerializer(serializers.ModelSerializer):
    """Serializer for role-permission relationships."""
    permission_name = serializers.CharField(source='permission.name', read_only=True)
    permission_codename = serializers.CharField(source='permission.codename', read_only=True)
    granted_by_username = serializers.CharField(source='granted_by.username', read_only=True)
    
    class Meta:
        model = RolePermission
        fields = [
            'id', 'role', 'permission', 'permission_name', 'permission_codename',
            'granted_by', 'granted_by_username', 'granted_at', 'is_active'
        ]
        read_only_fields = ['id', 'granted_at']


class UserRoleSerializer(serializers.ModelSerializer):
    """Serializer for user-role assignments."""
    role_name = serializers.CharField(source='role.name', read_only=True)
    role_codename = serializers.CharField(source='role.codename', read_only=True)
    role_type = serializers.CharField(source='role.role_type', read_only=True)
    assigned_by_username = serializers.CharField(source='assigned_by.username', read_only=True)
    is_valid = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = UserRole
        fields = [
            'id', 'user', 'role', 'role_name', 'role_codename', 'role_type',
            'assigned_by', 'assigned_by_username', 'status', 'assigned_at',
            'expires_at', 'reason', 'is_active', 'is_valid'
        ]
        read_only_fields = ['id', 'assigned_at']


class AssignRoleSerializer(serializers.Serializer):
    """Serializer for assigning roles to users."""
    user_id = serializers.UUIDField()
    role_id = serializers.UUIDField()
    expires_at = serializers.DateTimeField(required=False, allow_null=True)
    reason = serializers.CharField(required=False, allow_blank=True)
    
    def validate_user_id(self, value):
        """Validate user exists."""
        try:
            User.objects.get(id=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("User does not exist.")
        return value
    
    def validate_role_id(self, value):
        """Validate role exists."""
        try:
            Role.objects.get(id=value)
        except Role.DoesNotExist:
            raise serializers.ValidationError("Role does not exist.")
        return value


class GovernmentAccessRequestSerializer(serializers.ModelSerializer):
    """Serializer for government access requests."""
    requesting_official_username = serializers.CharField(source='requesting_official.username', read_only=True)
    approved_by_username = serializers.CharField(source='approved_by.username', read_only=True)
    is_expired = serializers.BooleanField(read_only=True)
    
    class Meta:
        model = GovernmentAccessRequest
        fields = [
            'id', 'requesting_official', 'requesting_official_username',
            'government_agency', 'official_title', 'official_id',
            'request_type', 'purpose', 'legal_basis', 'data_categories',
            'specific_users', 'date_range_start', 'date_range_end',
            'status', 'approved_by', 'approved_by_username', 'approved_at',
            'rejection_reason', 'access_granted_until', 'is_expired',
            'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'requesting_official', 'status', 'approved_by',
            'approved_at', 'created_at', 'updated_at'
        ]


class GovernmentAccessRequestCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating government access requests."""
    
    class Meta:
        model = GovernmentAccessRequest
        fields = [
            'government_agency', 'official_title', 'official_id',
            'request_type', 'purpose', 'legal_basis', 'data_categories',
            'specific_users', 'date_range_start', 'date_range_end'
        ]
    
    def validate_date_range_start(self, value):
        """Validate date range start."""
        if value and value > timezone.now():
            raise serializers.ValidationError("Start date cannot be in the future.")
        return value
    
    def validate_date_range_end(self, value):
        """Validate date range end."""
        if value and value > timezone.now():
            raise serializers.ValidationError("End date cannot be in the future.")
        return value
    
    def validate(self, attrs):
        """Validate date range."""
        start_date = attrs.get('date_range_start')
        end_date = attrs.get('date_range_end')
        
        if start_date and end_date and start_date > end_date:
            raise serializers.ValidationError("Start date cannot be after end date.")
        
        return attrs


class PermissionAuditLogSerializer(serializers.ModelSerializer):
    """Serializer for permission audit logs."""
    user_username = serializers.CharField(source='user.username', read_only=True)
    target_user_username = serializers.CharField(source='target_user.username', read_only=True)
    role_name = serializers.CharField(source='role.name', read_only=True)
    permission_name = serializers.CharField(source='permission.name', read_only=True)
    
    class Meta:
        model = PermissionAuditLog
        fields = [
            'id', 'user', 'user_username', 'target_user', 'target_user_username',
            'action_type', 'resource_type', 'resource_id', 'role', 'role_name',
            'permission', 'permission_name', 'details', 'ip_address',
            'user_agent', 'timestamp'
        ]
        read_only_fields = ['id', 'timestamp']


class AccessControlRuleSerializer(serializers.ModelSerializer):
    """Serializer for access control rules."""
    permission_name = serializers.CharField(source='permission.name', read_only=True)
    
    class Meta:
        model = AccessControlRule
        fields = [
            'id', 'name', 'rule_type', 'permission', 'permission_name',
            'conditions', 'is_active', 'priority', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class RoleHierarchySerializer(serializers.ModelSerializer):
    """Serializer for role hierarchy."""
    parent_role_name = serializers.CharField(source='parent_role.name', read_only=True)
    child_role_name = serializers.CharField(source='child_role.name', read_only=True)
    
    class Meta:
        model = RoleHierarchy
        fields = [
            'id', 'parent_role', 'parent_role_name', 'child_role',
            'child_role_name', 'can_inherit_permissions', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class DriverEarningsProtectionSerializer(serializers.ModelSerializer):
    """Serializer for driver earnings protection."""
    driver_username = serializers.CharField(source='driver.username', read_only=True)
    last_accessed_by_username = serializers.CharField(source='last_accessed_by.username', read_only=True)
    
    class Meta:
        model = DriverEarningsProtection
        fields = [
            'id', 'driver', 'driver_username', 'access_level_required',
            'government_access_allowed', 'last_accessed_by',
            'last_accessed_by_username', 'last_accessed_at',
            'access_count', 'created_at', 'updated_at'
        ]
        read_only_fields = [
            'id', 'driver', 'last_accessed_by', 'last_accessed_at',
            'access_count', 'created_at', 'updated_at'
        ]


class UserPermissionSerializer(serializers.Serializer):
    """Serializer for user permissions summary."""
    user_id = serializers.UUIDField(read_only=True)
    username = serializers.CharField(read_only=True)
    roles = serializers.ListField(read_only=True)
    permissions = serializers.ListField(read_only=True)
    hierarchy_level = serializers.IntegerField(read_only=True)
    can_access_driver_earnings = serializers.BooleanField(read_only=True)
    can_manage_users = serializers.BooleanField(read_only=True)
    can_access_government_data = serializers.BooleanField(read_only=True)


class AdminUserManagementSerializer(serializers.ModelSerializer):
    """Serializer for administrative user management."""
    user_roles = UserRoleSerializer(many=True, read_only=True)
    profile_completeness = serializers.SerializerMethodField()
    last_login_display = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'phone_number', 'is_active', 'is_phone_verified',
            'is_email_verified', 'date_joined', 'last_login',
            'last_login_display', 'user_roles', 'profile_completeness'
        ]
        read_only_fields = ['id', 'date_joined', 'last_login']
    
    def get_profile_completeness(self, obj):
        """Get profile completeness percentage."""
        if hasattr(obj, 'profile'):
            return obj.profile.profile_completeness
        return 0
    
    def get_last_login_display(self, obj):
        """Get formatted last login."""
        if obj.last_login:
            return obj.last_login.strftime('%Y-%m-%d %H:%M:%S')
        return 'Never'


class CreateRoleSerializer(serializers.ModelSerializer):
    """Serializer for creating new roles (super admin only)."""
    permission_ids = serializers.ListField(
        child=serializers.UUIDField(),
        required=False,
        write_only=True
    )
    
    class Meta:
        model = Role
        fields = [
            'name', 'codename', 'role_type', 'description',
            'hierarchy_level', 'permission_ids'
        ]
    
    def validate_codename(self, value):
        """Validate role codename is unique."""
        if Role.objects.filter(codename=value).exists():
            raise serializers.ValidationError("Role with this codename already exists.")
        return value
    
    def create(self, validated_data):
        """Create role with permissions."""
        permission_ids = validated_data.pop('permission_ids', [])
        role = Role.objects.create(**validated_data)
        
        # Add permissions if provided
        if permission_ids:
            permissions = Permission.objects.filter(id__in=permission_ids)
            role.permissions.set(permissions)
        
        return role


class PermissionCheckSerializer(serializers.Serializer):
    """Serializer for permission checking."""
    user_id = serializers.UUIDField()
    permission_codename = serializers.CharField()
    resource_type = serializers.CharField(required=False, allow_blank=True)
    resource_id = serializers.CharField(required=False, allow_blank=True)
    
    def validate_user_id(self, value):
        """Validate user exists."""
        try:
            User.objects.get(id=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("User does not exist.")
        return value
    
    def validate_permission_codename(self, value):
        """Validate permission exists."""
        try:
            Permission.objects.get(codename=value)
        except Permission.DoesNotExist:
            raise serializers.ValidationError("Permission does not exist.")
        return value


class BulkRoleAssignmentSerializer(serializers.Serializer):
    """Serializer for bulk role assignments."""
    user_ids = serializers.ListField(
        child=serializers.UUIDField(),
        min_length=1
    )
    role_id = serializers.UUIDField()
    expires_at = serializers.DateTimeField(required=False, allow_null=True)
    reason = serializers.CharField(required=False, allow_blank=True)
    
    def validate_user_ids(self, value):
        """Validate all users exist."""
        existing_users = User.objects.filter(id__in=value)
        if len(existing_users) != len(value):
            raise serializers.ValidationError("One or more users do not exist.")
        return value
    
    def validate_role_id(self, value):
        """Validate role exists."""
        try:
            Role.objects.get(id=value)
        except Role.DoesNotExist:
            raise serializers.ValidationError("Role does not exist.")
        return value
