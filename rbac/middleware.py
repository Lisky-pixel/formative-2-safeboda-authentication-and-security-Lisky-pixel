"""
RBAC middleware for SafeBoda system.
Implements access control and permission checking for API endpoints.
"""

import logging
from django.http import JsonResponse
from django.contrib.auth import get_user_model
from django.utils.deprecation import MiddlewareMixin
from django.urls import resolve
from .models import UserRole, PermissionAuditLog

User = get_user_model()
logger = logging.getLogger('security')


class RBACMiddleware(MiddlewareMixin):
    """
    Middleware to enforce Role-Based Access Control on API endpoints.
    """
    
    # Define endpoint permission mappings
    ENDPOINT_PERMISSIONS = {
        # Authentication endpoints (public)
        '/api/auth/basic/': [],
        '/api/auth/session/login/': [],
        '/api/auth/session/logout/': [],
        '/api/auth/jwt-token/': [],
        '/api/auth/jwt/refresh/': [],
        '/api/auth/jwt/verify/': [],
        '/api/auth/methods/': [],
        '/api/auth/register/': [],
        
        # UAS endpoints (require authentication)
        '/api/uas/register/': [],
        '/api/uas/verify-phone/': ['authenticated'],
        '/api/uas/verify-email/': ['authenticated'],
        '/api/uas/verify-phone/confirm/': ['authenticated'],
        '/api/uas/verify-email/confirm/': ['authenticated'],
        '/api/uas/password-reset/': [],
        '/api/uas/password-reset/confirm/': [],
        '/api/uas/account/status/': ['authenticated'],
        '/api/uas/account/recover/': [],
        '/api/uas/districts/': [],
        
        # Privacy endpoints (require authentication)
        '/api/privacy/data-export/': ['authenticated'],
        '/api/privacy/data-deletion/': ['authenticated'],
        '/api/privacy/audit-log/': ['authenticated'],
        '/api/privacy/consent/': ['authenticated'],
        '/api/privacy/anonymize/': ['authenticated'],
        '/api/privacy/retention-policy/': ['authenticated'],
        '/api/privacy/settings/': ['authenticated'],
        
        # RBAC endpoints (require specific permissions)
        '/api/rbac/roles/': ['view_roles'],
        '/api/rbac/assign-role/': ['assign_roles'],
        '/api/rbac/permissions/': ['view_user_permissions'],
        '/api/rbac/admin/users/': ['manage_users'],
        '/api/rbac/government/access-request/': ['create_government_access_request'],
        '/api/rbac/audit/permissions/': ['view_audit_logs'],
        '/api/rbac/create-role/': ['create_roles'],
        '/api/rbac/check-permission/': ['check_permissions'],
        '/api/rbac/bulk-assign-roles/': ['assign_roles'],
        '/api/rbac/driver-earnings/': ['access_driver_earnings'],
    }
    
    def process_request(self, request):
        """Process incoming requests for RBAC enforcement."""
        # Skip RBAC for non-API endpoints
        if not request.path.startswith('/api/'):
            return None
        
        # Skip RBAC for OPTIONS requests (CORS preflight)
        if request.method == 'OPTIONS':
            return None
        
        # Get required permissions for this endpoint
        required_permissions = self._get_required_permissions(request.path)
        
        # If no specific permissions required, just check authentication
        if required_permissions == ['authenticated']:
            if not request.user.is_authenticated:
                return JsonResponse({
                    'error': 'Authentication required'
                }, status=401)
            return None
        
        # If no permissions required, allow access
        if not required_permissions:
            return None
        
        # Check if user is authenticated
        if not request.user.is_authenticated:
            return JsonResponse({
                'error': 'Authentication required'
            }, status=401)
        
        # Check if user has required permissions
        if not self._user_has_permissions(request.user, required_permissions):
            # Log access denial
            self._log_access_denial(request.user, request.path, required_permissions, request)
            
            return JsonResponse({
                'error': 'Permission denied',
                'required_permissions': required_permissions
            }, status=403)
        
        # Log successful access
        self._log_access_granted(request.user, request.path, required_permissions, request)
        
        return None
    
    def _get_required_permissions(self, path):
        """Get required permissions for an endpoint."""
        # Direct path match
        if path in self.ENDPOINT_PERMISSIONS:
            return self.ENDPOINT_PERMISSIONS[path]
        
        # Check for path patterns (e.g., with IDs)
        for endpoint, permissions in self.ENDPOINT_PERMISSIONS.items():
            if endpoint.endswith('/') and path.startswith(endpoint):
                return permissions
        
        # Default: require authentication for all API endpoints
        return ['authenticated']
    
    def _user_has_permissions(self, user, required_permissions):
        """Check if user has all required permissions."""
        if not required_permissions:
            return True
        
        # Get user's active roles
        user_roles = UserRole.objects.filter(
            user=user,
            is_active=True,
            status='active'
        ).select_related('role')
        
        # Collect all user permissions
        user_permissions = set()
        for user_role in user_roles:
            if user_role.is_valid():
                role = user_role.role
                role_permissions = role.permissions.filter(is_active=True)
                for permission in role_permissions:
                    user_permissions.add(permission.codename)
        
        # Check if user has all required permissions
        return all(perm in user_permissions for perm in required_permissions)
    
    def _log_access_denial(self, user, path, required_permissions, request):
        """Log access denial for audit purposes."""
        PermissionAuditLog.objects.create(
            user=user,
            action_type='access_denied',
            resource_type='api_endpoint',
            resource_id=path,
            details={
                'method': request.method,
                'required_permissions': required_permissions,
                'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                'ip_address': self._get_client_ip(request)
            },
            ip_address=self._get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        logger.warning(f"Access denied for user {user.username} to {path}. Required permissions: {required_permissions}")
    
    def _log_access_granted(self, user, path, required_permissions, request):
        """Log successful access for audit purposes."""
        PermissionAuditLog.objects.create(
            user=user,
            action_type='permission_check',
            resource_type='api_endpoint',
            resource_id=path,
            details={
                'method': request.method,
                'required_permissions': required_permissions,
                'access_granted': True,
                'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                'ip_address': self._get_client_ip(request)
            },
            ip_address=self._get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
    
    def _get_client_ip(self, request):
        """Get client IP address from request."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class RoleHierarchyMiddleware(MiddlewareMixin):
    """
    Middleware to enforce role hierarchy in role assignments.
    """
    
    def process_request(self, request):
        """Process requests to enforce role hierarchy."""
        # Only apply to RBAC role assignment endpoints
        if not (request.path.startswith('/api/rbac/assign-role/') or 
                request.path.startswith('/api/rbac/bulk-assign-roles/')):
            return None
        
        # Skip for non-POST requests
        if request.method != 'POST':
            return None
        
        # Skip if user is not authenticated
        if not request.user.is_authenticated:
            return None
        
        # Check role hierarchy for role assignments
        try:
            data = request.json() if hasattr(request, 'json') else {}
            role_id = data.get('role_id')
            
            if role_id:
                from .models import Role
                try:
                    role = Role.objects.get(id=role_id)
                    if not self._can_assign_role(request.user, role):
                        return JsonResponse({
                            'error': 'Insufficient privileges to assign this role',
                            'required_level': role.hierarchy_level,
                            'user_level': self._get_user_max_level(request.user)
                        }, status=403)
                except Role.DoesNotExist:
                    return JsonResponse({
                        'error': 'Role not found'
                    }, status=404)
        except Exception:
            # If we can't parse the request, let it through to be handled by the view
            pass
        
        return None
    
    def _can_assign_role(self, user, role):
        """Check if user can assign the specified role."""
        user_max_level = self._get_user_max_level(user)
        return user_max_level > role.hierarchy_level
    
    def _get_user_max_level(self, user):
        """Get user's maximum role hierarchy level."""
        user_roles = UserRole.objects.filter(
            user=user,
            is_active=True,
            status='active'
        ).select_related('role')
        
        max_level = 0
        for user_role in user_roles:
            if user_role.is_valid():
                max_level = max(max_level, user_role.role.hierarchy_level)
        
        return max_level


class GovernmentAccessMiddleware(MiddlewareMixin):
    """
    Middleware to enforce government access controls.
    """
    
    def process_request(self, request):
        """Process requests for government access enforcement."""
        # Only apply to government access endpoints
        if not request.path.startswith('/api/rbac/government/'):
            return None
        
        # Skip if user is not authenticated
        if not request.user.is_authenticated:
            return None
        
        # Check if user has government official role
        if not self._is_government_official(request.user):
            return JsonResponse({
                'error': 'Government official role required for this endpoint'
            }, status=403)
        
        return None
    
    def _is_government_official(self, user):
        """Check if user has government official role."""
        user_roles = UserRole.objects.filter(
            user=user,
            is_active=True,
            status='active'
        ).select_related('role')
        
        for user_role in user_roles:
            if user_role.is_valid():
                if user_role.role.role_type == 'government_official':
                    return True
        
        return False


class DriverEarningsProtectionMiddleware(MiddlewareMixin):
    """
    Middleware to protect driver earnings data access.
    """
    
    def process_request(self, request):
        """Process requests for driver earnings protection."""
        # Only apply to driver earnings endpoints
        if not request.path.startswith('/api/rbac/driver-earnings/'):
            return None
        
        # Skip if user is not authenticated
        if not request.user.is_authenticated:
            return None
        
        # Check if user has permission to access driver earnings
        if not self._can_access_driver_earnings(request.user):
            return JsonResponse({
                'error': 'Insufficient privileges to access driver earnings data',
                'note': 'Admin level role or higher required'
            }, status=403)
        
        return None
    
    def _can_access_driver_earnings(self, user):
        """Check if user can access driver earnings."""
        user_roles = UserRole.objects.filter(
            user=user,
            is_active=True,
            status='active'
        ).select_related('role')
        
        for user_role in user_roles:
            if user_role.is_valid():
                role = user_role.role
                # Check if role has admin level or higher
                if role.hierarchy_level >= 2:  # Admin level
                    return True
                # Check if role has specific permission
                if role.has_permission('access_driver_earnings'):
                    return True
        
        return False
