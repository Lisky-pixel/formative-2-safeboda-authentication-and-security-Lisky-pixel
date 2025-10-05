"""
Role-Based Access Control (RBAC) models for SafeBoda system.
Implements flexible permission system with government integration.
"""

from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.core.exceptions import ValidationError
import uuid

User = get_user_model()


class Permission(models.Model):
    """
    Model for individual permissions that can be assigned to roles.
    """
    PERMISSION_CATEGORIES = [
        ('user_management', 'User Management'),
        ('data_access', 'Data Access'),
        ('system_admin', 'System Administration'),
        ('government_access', 'Government Access'),
        ('driver_management', 'Driver Management'),
        ('passenger_management', 'Passenger Management'),
        ('financial_data', 'Financial Data'),
        ('analytics', 'Analytics'),
        ('privacy_management', 'Privacy Management'),
        ('audit_access', 'Audit Access'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)
    codename = models.CharField(max_length=100, unique=True)
    category = models.CharField(max_length=20, choices=PERMISSION_CATEGORIES)
    description = models.TextField()
    resource_type = models.CharField(max_length=50, help_text="Type of resource this permission applies to")
    action = models.CharField(max_length=50, help_text="Action this permission allows (read, write, delete, etc.)")
    is_system_permission = models.BooleanField(default=False, help_text="System permissions cannot be modified")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'rbac_permissions'
        ordering = ['category', 'name']
    
    def __str__(self):
        return f"{self.name} ({self.codename})"
    
    def clean(self):
        """Validate permission data."""
        if not self.codename:
            self.codename = self.name.lower().replace(' ', '_')
        
        # Ensure codename is unique and follows naming conventions
        if not self.codename.replace('_', '').isalnum():
            raise ValidationError("Permission codename must contain only letters, numbers, and underscores.")


class Role(models.Model):
    """
    Model for roles that can be assigned to users.
    Implements role hierarchy: passenger < driver < admin < super_admin
    """
    ROLE_TYPES = [
        ('passenger', 'Passenger'),
        ('driver', 'Driver'),
        ('admin', 'Administrator'),
        ('super_admin', 'Super Administrator'),
        ('government_official', 'Government Official'),
        ('support_agent', 'Support Agent'),
        ('analyst', 'Data Analyst'),
        ('auditor', 'Auditor'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)
    codename = models.CharField(max_length=50, unique=True)
    role_type = models.CharField(max_length=20, choices=ROLE_TYPES)
    description = models.TextField()
    hierarchy_level = models.IntegerField(default=0, help_text="Higher numbers have more privileges")
    is_system_role = models.BooleanField(default=False, help_text="System roles cannot be deleted")
    is_active = models.BooleanField(default=True)
    permissions = models.ManyToManyField(Permission, through='RolePermission', blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='created_roles')
    
    class Meta:
        db_table = 'rbac_roles'
        ordering = ['-hierarchy_level', 'name']
    
    def __str__(self):
        return f"{self.name} (Level {self.hierarchy_level})"
    
    def get_permissions(self):
        """Get all permissions for this role."""
        return self.permissions.filter(is_active=True)
    
    def has_permission(self, permission_codename):
        """Check if role has a specific permission."""
        return self.permissions.filter(codename=permission_codename, is_active=True).exists()
    
    def can_manage_role(self, other_role):
        """Check if this role can manage another role (hierarchy check)."""
        return self.hierarchy_level > other_role.hierarchy_level


class RolePermission(models.Model):
    """
    Through model for role-permission relationships with additional metadata.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)
    granted_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    granted_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'rbac_role_permissions'
        unique_together = ['role', 'permission']
    
    def __str__(self):
        return f"{self.role.name} - {self.permission.name}"


class UserRole(models.Model):
    """
    Model for user-role assignments.
    """
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('suspended', 'Suspended'),
        ('pending_approval', 'Pending Approval'),
        ('expired', 'Expired'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_roles')
    role = models.ForeignKey(Role, on_delete=models.CASCADE)
    assigned_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='assigned_roles')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    assigned_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    reason = models.TextField(blank=True, help_text="Reason for role assignment")
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'rbac_user_roles'
        unique_together = ['user', 'role']
        ordering = ['-assigned_at']
    
    def __str__(self):
        return f"{self.user.username} - {self.role.name}"
    
    def is_valid(self):
        """Check if user role is currently valid."""
        if not self.is_active or self.status != 'active':
            return False
        
        if self.expires_at and self.expires_at < timezone.now():
            self.status = 'expired'
            self.save(update_fields=['status'])
            return False
        
        return True
    
    def clean(self):
        """Validate user role assignment."""
        if self.expires_at and self.expires_at <= timezone.now():
            raise ValidationError("Expiration date must be in the future.")


class GovernmentAccessRequest(models.Model):
    """
    Model for government data access requests with approval workflow.
    """
    STATUS_CHOICES = [
        ('pending', 'Pending Approval'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('expired', 'Expired'),
        ('completed', 'Completed'),
    ]
    
    REQUEST_TYPES = [
        ('user_data', 'User Data Access'),
        ('driver_data', 'Driver Data Access'),
        ('financial_data', 'Financial Data Access'),
        ('safety_data', 'Safety Data Access'),
        ('analytics_data', 'Analytics Data Access'),
        ('audit_data', 'Audit Data Access'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    requesting_official = models.ForeignKey(User, on_delete=models.CASCADE, related_name='government_requests')
    government_agency = models.CharField(max_length=200)
    official_title = models.CharField(max_length=100)
    official_id = models.CharField(max_length=50, help_text="Government official ID number")
    request_type = models.CharField(max_length=20, choices=REQUEST_TYPES)
    purpose = models.TextField()
    legal_basis = models.TextField(help_text="Legal basis for the request")
    data_categories = models.JSONField(default=list, help_text="Categories of data requested")
    specific_users = models.JSONField(default=list, blank=True, help_text="Specific user IDs if targeting specific users")
    date_range_start = models.DateTimeField(null=True, blank=True)
    date_range_end = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    approved_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='approved_requests')
    approved_at = models.DateTimeField(null=True, blank=True)
    rejection_reason = models.TextField(blank=True)
    access_granted_until = models.DateTimeField(null=True, blank=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'rbac_government_access_requests'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Government Request: {self.government_agency} - {self.get_request_type_display()}"
    
    def is_expired(self):
        """Check if the access request has expired."""
        if self.access_granted_until and self.access_granted_until < timezone.now():
            self.status = 'expired'
            self.save(update_fields=['status'])
            return True
        return False
    
    def approve(self, approved_by_user):
        """Approve the government access request."""
        self.status = 'approved'
        self.approved_by = approved_by_user
        self.approved_at = timezone.now()
        # Set access expiration (default 30 days)
        self.access_granted_until = timezone.now() + timezone.timedelta(days=30)
        self.save()


class PermissionAuditLog(models.Model):
    """
    Model to audit all permission-related activities.
    """
    ACTION_TYPES = [
        ('role_assigned', 'Role Assigned'),
        ('role_removed', 'Role Removed'),
        ('permission_granted', 'Permission Granted'),
        ('permission_revoked', 'Permission Revoked'),
        ('role_created', 'Role Created'),
        ('role_modified', 'Role Modified'),
        ('role_deleted', 'Role Deleted'),
        ('government_access_granted', 'Government Access Granted'),
        ('government_access_denied', 'Government Access Denied'),
        ('permission_check', 'Permission Check'),
        ('access_denied', 'Access Denied'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='permission_audit_logs')
    target_user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True, related_name='target_permission_audit_logs')
    action_type = models.CharField(max_length=30, choices=ACTION_TYPES)
    resource_type = models.CharField(max_length=50, blank=True)
    resource_id = models.CharField(max_length=100, blank=True)
    role = models.ForeignKey(Role, on_delete=models.SET_NULL, null=True, blank=True)
    permission = models.ForeignKey(Permission, on_delete=models.SET_NULL, null=True, blank=True)
    details = models.JSONField(default=dict)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'rbac_permission_audit_logs'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['action_type', 'timestamp']),
            models.Index(fields=['resource_type', 'timestamp']),
        ]
    
    def __str__(self):
        return f"{self.get_action_type_display()} - {self.timestamp}"


class AccessControlRule(models.Model):
    """
    Model for fine-grained access control rules.
    """
    RULE_TYPES = [
        ('time_based', 'Time Based'),
        ('ip_based', 'IP Based'),
        ('resource_based', 'Resource Based'),
        ('context_based', 'Context Based'),
    ]
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)
    rule_type = models.CharField(max_length=20, choices=RULE_TYPES)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)
    conditions = models.JSONField(default=dict, help_text="Rule conditions (time, IP, etc.)")
    is_active = models.BooleanField(default=True)
    priority = models.IntegerField(default=0, help_text="Higher numbers have higher priority")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'rbac_access_control_rules'
        ordering = ['-priority', 'name']
    
    def __str__(self):
        return f"{self.name} ({self.get_rule_type_display()})"


class RoleHierarchy(models.Model):
    """
    Model to define role hierarchy relationships.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    parent_role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='child_roles')
    child_role = models.ForeignKey(Role, on_delete=models.CASCADE, related_name='parent_roles')
    can_inherit_permissions = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'rbac_role_hierarchy'
        unique_together = ['parent_role', 'child_role']
    
    def __str__(self):
        return f"{self.parent_role.name} -> {self.child_role.name}"
    
    def clean(self):
        """Validate hierarchy relationship."""
        if self.parent_role == self.child_role:
            raise ValidationError("A role cannot be a parent of itself.")
        
        # Check for circular references
        if self._would_create_circle():
            raise ValidationError("This would create a circular hierarchy.")
    
    def _would_create_circle(self):
        """Check if this relationship would create a circular hierarchy."""
        visited = set()
        to_visit = [self.child_role]
        
        while to_visit:
            current = to_visit.pop(0)
            if current == self.parent_role:
                return True
            if current in visited:
                continue
            visited.add(current)
            
            # Add all parents of current role
            for hierarchy in RoleHierarchy.objects.filter(child_role=current):
                to_visit.append(hierarchy.parent_role)
        
        return False


class DriverEarningsProtection(models.Model):
    """
    Model to protect driver earnings data with special access controls.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    driver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='earnings_protection')
    earnings_data_encrypted = models.TextField(blank=True)
    access_level_required = models.CharField(max_length=20, default='admin', help_text="Minimum role level to access")
    government_access_allowed = models.BooleanField(default=False)
    last_accessed_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    last_accessed_at = models.DateTimeField(null=True, blank=True)
    access_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'rbac_driver_earnings_protection'
    
    def __str__(self):
        return f"Earnings Protection: {self.driver.username}"
    
    def can_access(self, user):
        """Check if user can access driver earnings."""
        if not user.is_authenticated:
            return False
        
        # Check if user has required role level
        user_roles = UserRole.objects.filter(
            user=user,
            is_active=True,
            status='active'
        ).select_related('role')
        
        for user_role in user_roles:
            if user_role.is_valid():
                role = user_role.role
                if role.hierarchy_level >= self._get_required_level():
                    return True
        
        return False
    
    def _get_required_level(self):
        """Get required hierarchy level for access."""
        level_map = {
            'passenger': 0,
            'driver': 1,
            'admin': 2,
            'super_admin': 3,
        }
        return level_map.get(self.access_level_required, 2)
    
    def log_access(self, user):
        """Log access to driver earnings."""
        self.last_accessed_by = user
        self.last_accessed_at = timezone.now()
        self.access_count += 1
        self.save(update_fields=['last_accessed_by', 'last_accessed_at', 'access_count'])
        
        # Create audit log
        PermissionAuditLog.objects.create(
            user=user,
            target_user=self.driver,
            action_type='permission_check',
            resource_type='driver_earnings',
            resource_id=str(self.id),
            details={'earnings_accessed': True},
            ip_address='127.0.0.1',  # Would be set from request
            user_agent='System'
        )