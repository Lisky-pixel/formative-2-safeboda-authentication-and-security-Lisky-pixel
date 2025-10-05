"""
RBAC (Role-Based Access Control) views for SafeBoda system.
Implements comprehensive permission management with government integration.
"""

from rest_framework import status, permissions
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.db.models import Q, Count
from django.core.exceptions import PermissionDenied
import logging

from .models import (
    Permission, Role, RolePermission, UserRole, GovernmentAccessRequest,
    PermissionAuditLog, AccessControlRule, RoleHierarchy, DriverEarningsProtection
)
from .serializers import (
    PermissionSerializer, RoleSerializer, RoleDetailSerializer,
    RolePermissionSerializer, UserRoleSerializer, AssignRoleSerializer,
    GovernmentAccessRequestSerializer, GovernmentAccessRequestCreateSerializer,
    PermissionAuditLogSerializer, AccessControlRuleSerializer,
    RoleHierarchySerializer, DriverEarningsProtectionSerializer,
    UserPermissionSerializer, AdminUserManagementSerializer,
    CreateRoleSerializer, PermissionCheckSerializer, BulkRoleAssignmentSerializer
)

User = get_user_model()
logger = logging.getLogger('security')


class RBACPermissionMixin:
    """
    Mixin for RBAC permission checking.
    """
    
    def has_permission(self, user, permission_codename, resource_type=None, resource_id=None):
        """Check if user has a specific permission."""
        if not user.is_authenticated:
            return False
        
        # Get user's active roles
        user_roles = UserRole.objects.filter(
            user=user,
            is_active=True,
            status='active'
        ).select_related('role')
        
        for user_role in user_roles:
            if user_role.is_valid():
                role = user_role.role
                if role.has_permission(permission_codename):
                    # Log permission check
                    self.log_permission_check(user, permission_codename, resource_type, resource_id, True)
                    return True
        
        # Log failed permission check
        self.log_permission_check(user, permission_codename, resource_type, resource_id, False)
        return False
    
    def has_role_level(self, user, required_level):
        """Check if user has required role hierarchy level."""
        if not user.is_authenticated:
            return False
        
        user_roles = UserRole.objects.filter(
            user=user,
            is_active=True,
            status='active'
        ).select_related('role')
        
        for user_role in user_roles:
            if user_role.is_valid() and user_role.role.hierarchy_level >= required_level:
                return True
        
        return False
    
    def log_permission_check(self, user, permission_codename, resource_type, resource_id, granted):
        """Log permission check for audit purposes."""
        PermissionAuditLog.objects.create(
            user=user,
            action_type='permission_check',
            resource_type=resource_type or 'unknown',
            resource_id=resource_id or '',
            details={
                'permission': permission_codename,
                'granted': granted
            },
            ip_address=self.get_client_ip(),
            user_agent=self.get_user_agent()
        )
    
    def get_client_ip(self):
        """Get client IP address from request."""
        if hasattr(self, 'request'):
            x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
            if x_forwarded_for:
                ip = x_forwarded_for.split(',')[0]
            else:
                ip = self.request.META.get('REMOTE_ADDR')
            return ip
        return '127.0.0.1'
    
    def get_user_agent(self):
        """Get user agent from request."""
        if hasattr(self, 'request'):
            return self.request.META.get('HTTP_USER_AGENT', '')
        return 'System'


class RolesListView(APIView, RBACPermissionMixin):
    """
    GET /api/rbac/roles/ - List available roles
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get list of available roles."""
        if not self.has_permission(request.user, 'view_roles'):
            return Response({
                'error': 'Permission denied'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Get query parameters
        role_type = request.query_params.get('role_type')
        is_active = request.query_params.get('is_active')
        
        # Build query
        roles_query = Role.objects.all()
        
        if role_type:
            roles_query = roles_query.filter(role_type=role_type)
        
        if is_active is not None:
            roles_query = roles_query.filter(is_active=is_active.lower() == 'true')
        
        # Order by hierarchy level
        roles = roles_query.order_by('-hierarchy_level', 'name')
        
        serializer = RoleSerializer(roles, many=True)
        
        return Response({
            'roles': serializer.data,
            'total': roles.count()
        }, status=status.HTTP_200_OK)


class AssignRoleView(APIView, RBACPermissionMixin):
    """
    POST /api/rbac/assign-role/ - Assign role to user
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """Assign role to user."""
        if not self.has_permission(request.user, 'assign_roles'):
            return Response({
                'error': 'Permission denied'
            }, status=status.HTTP_403_FORBIDDEN)
        
        serializer = AssignRoleSerializer(data=request.data)
        if serializer.is_valid():
            user_id = serializer.validated_data['user_id']
            role_id = serializer.validated_data['role_id']
            expires_at = serializer.validated_data.get('expires_at')
            reason = serializer.validated_data.get('reason', '')
            
            try:
                user = User.objects.get(id=user_id)
                role = Role.objects.get(id=role_id)
                
                # Check if assigner can manage this role
                if not self._can_assign_role(request.user, role):
                    return Response({
                        'error': 'Insufficient privileges to assign this role'
                    }, status=status.HTTP_403_FORBIDDEN)
                
                # Create or update user role
                user_role, created = UserRole.objects.update_or_create(
                    user=user,
                    role=role,
                    defaults={
                        'assigned_by': request.user,
                        'status': 'active',
                        'expires_at': expires_at,
                        'reason': reason,
                        'is_active': True
                    }
                )
                
                # Log role assignment
                PermissionAuditLog.objects.create(
                    user=request.user,
                    target_user=user,
                    action_type='role_assigned' if created else 'role_modified',
                    resource_type='user_role',
                    resource_id=str(user_role.id),
                    role=role,
                    details={
                        'role_name': role.name,
                        'created': created,
                        'reason': reason
                    },
                    ip_address=self.get_client_ip(),
                    user_agent=self.get_user_agent()
                )
                
                action = 'assigned' if created else 'updated'
                return Response({
                    'message': f'Role {action} successfully',
                    'user_role': UserRoleSerializer(user_role).data
                }, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)
                
            except User.DoesNotExist:
                return Response({
                    'error': 'User not found'
                }, status=status.HTTP_404_NOT_FOUND)
            except Role.DoesNotExist:
                return Response({
                    'error': 'Role not found'
                }, status=status.HTTP_404_NOT_FOUND)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def _can_assign_role(self, user, role):
        """Check if user can assign the specified role."""
        # Get user's highest role level
        user_roles = UserRole.objects.filter(
            user=user,
            is_active=True,
            status='active'
        ).select_related('role')
        
        user_max_level = 0
        for user_role in user_roles:
            if user_role.is_valid():
                user_max_level = max(user_max_level, user_role.role.hierarchy_level)
        
        # Can only assign roles with lower hierarchy level
        return user_max_level > role.hierarchy_level


class UserPermissionsView(APIView, RBACPermissionMixin):
    """
    GET /api/rbac/permissions/ - List user permissions
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get user's permissions."""
        user_id = request.query_params.get('user_id')
        
        # If user_id provided, check if requester can view that user's permissions
        if user_id:
            if not self.has_permission(request.user, 'view_user_permissions'):
                return Response({
                    'error': 'Permission denied'
                }, status=status.HTTP_403_FORBIDDEN)
            
            try:
                target_user = User.objects.get(id=user_id)
            except User.DoesNotExist:
                return Response({
                    'error': 'User not found'
                }, status=status.HTTP_404_NOT_FOUND)
        else:
            target_user = request.user
        
        # Get user's roles and permissions
        user_roles = UserRole.objects.filter(
            user=target_user,
            is_active=True,
            status='active'
        ).select_related('role')
        
        roles_data = []
        all_permissions = set()
        max_hierarchy_level = 0
        
        for user_role in user_roles:
            if user_role.is_valid():
                role = user_role.role
                max_hierarchy_level = max(max_hierarchy_level, role.hierarchy_level)
                
                role_permissions = role.get_permissions()
                roles_data.append({
                    'role_id': str(role.id),
                    'role_name': role.name,
                    'role_type': role.role_type,
                    'hierarchy_level': role.hierarchy_level,
                    'permissions': PermissionSerializer(role_permissions, many=True).data
                })
                
                # Collect all permissions
                for permission in role_permissions:
                    all_permissions.add(permission.codename)
        
        # Check special permissions
        can_access_driver_earnings = self.has_permission(target_user, 'access_driver_earnings')
        can_manage_users = self.has_permission(target_user, 'manage_users')
        can_access_government_data = self.has_permission(target_user, 'access_government_data')
        
        serializer = UserPermissionSerializer({
            'user_id': target_user.id,
            'username': target_user.username,
            'roles': roles_data,
            'permissions': list(all_permissions),
            'hierarchy_level': max_hierarchy_level,
            'can_access_driver_earnings': can_access_driver_earnings,
            'can_manage_users': can_manage_users,
            'can_access_government_data': can_access_government_data
        })
        
        return Response(serializer.data, status=status.HTTP_200_OK)


class AdminUserManagementView(APIView, RBACPermissionMixin):
    """
    GET /api/rbac/admin/users/ - Administrative user management
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get users for administrative management."""
        if not self.has_permission(request.user, 'manage_users'):
            return Response({
                'error': 'Permission denied'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Get query parameters
        search = request.query_params.get('search')
        role_type = request.query_params.get('role_type')
        is_active = request.query_params.get('is_active')
        
        # Build query
        users_query = User.objects.all()
        
        if search:
            users_query = users_query.filter(
                Q(username__icontains=search) |
                Q(email__icontains=search) |
                Q(first_name__icontains=search) |
                Q(last_name__icontains=search)
            )
        
        if is_active is not None:
            users_query = users_query.filter(is_active=is_active.lower() == 'true')
        
        # Filter by role if specified
        if role_type:
            users_query = users_query.filter(
                user_roles__role__role_type=role_type,
                user_roles__is_active=True,
                user_roles__status='active'
            )
        
        # Paginate results
        paginator = PageNumberPagination()
        paginator.page_size = 20
        users = paginator.paginate_queryset(users_query.order_by('-date_joined'), request)
        
        serializer = AdminUserManagementSerializer(users, many=True)
        
        return paginator.get_paginated_response({
            'users': serializer.data
        })


class GovernmentAccessRequestView(APIView, RBACPermissionMixin):
    """
    POST /api/rbac/government/access-request/ - Government data access
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """Create government access request."""
        # Check if user has government official role
        if not self.has_permission(request.user, 'create_government_access_request'):
            return Response({
                'error': 'Permission denied. Government official role required.'
            }, status=status.HTTP_403_FORBIDDEN)
        
        serializer = GovernmentAccessRequestCreateSerializer(data=request.data)
        if serializer.is_valid():
            # Create government access request
            access_request = GovernmentAccessRequest.objects.create(
                requesting_official=request.user,
                ip_address=self.get_client_ip(),
                user_agent=self.get_user_agent(),
                **serializer.validated_data
            )
            
            # Log the request creation
            PermissionAuditLog.objects.create(
                user=request.user,
                action_type='government_access_granted' if access_request.status == 'approved' else 'government_access_denied',
                resource_type='government_access_request',
                resource_id=str(access_request.id),
                details={
                    'request_type': access_request.request_type,
                    'government_agency': access_request.government_agency,
                    'status': access_request.status
                },
                ip_address=self.get_client_ip(),
                user_agent=self.get_user_agent()
            )
            
            return Response({
                'message': 'Government access request submitted successfully',
                'request_id': str(access_request.id),
                'status': access_request.status
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def get(self, request):
        """Get government access requests."""
        if not self.has_permission(request.user, 'view_government_requests'):
            return Response({
                'error': 'Permission denied'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Get requests based on user's role
        if self.has_permission(request.user, 'approve_government_requests'):
            # Super admin can see all requests
            requests = GovernmentAccessRequest.objects.all()
        else:
            # Government officials can only see their own requests
            requests = GovernmentAccessRequest.objects.filter(requesting_official=request.user)
        
        requests = requests.order_by('-created_at')
        
        # Paginate results
        paginator = PageNumberPagination()
        paginator.page_size = 20
        requests = paginator.paginate_queryset(requests, request)
        
        serializer = GovernmentAccessRequestSerializer(requests, many=True)
        
        return paginator.get_paginated_response({
            'requests': serializer.data
        })


class GovernmentAccessApprovalView(APIView, RBACPermissionMixin):
    """
    POST /api/rbac/government/access-request/{id}/approve/ - Approve government access
    POST /api/rbac/government/access-request/{id}/reject/ - Reject government access
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request, request_id, action):
        """Approve or reject government access request."""
        if not self.has_permission(request.user, 'approve_government_requests'):
            return Response({
                'error': 'Permission denied. Super admin role required.'
            }, status=status.HTTP_403_FORBIDDEN)
        
        try:
            access_request = GovernmentAccessRequest.objects.get(id=request_id)
        except GovernmentAccessRequest.DoesNotExist:
            return Response({
                'error': 'Access request not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        if access_request.status != 'pending':
            return Response({
                'error': 'Request is not pending'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        if action == 'approve':
            # Approve the request
            access_request.approve(request.user)
            
            PermissionAuditLog.objects.create(
                user=request.user,
                target_user=access_request.requesting_official,
                action_type='government_access_granted',
                resource_type='government_access_request',
                resource_id=str(access_request.id),
                details={
                    'request_type': access_request.request_type,
                    'approved_by': request.user.username
                },
                ip_address=self.get_client_ip(),
                user_agent=self.get_user_agent()
            )
            
            return Response({
                'message': 'Government access request approved',
                'access_granted_until': access_request.access_granted_until.isoformat()
            }, status=status.HTTP_200_OK)
        
        elif action == 'reject':
            # Reject the request
            rejection_reason = request.data.get('reason', 'No reason provided')
            access_request.status = 'rejected'
            access_request.rejection_reason = rejection_reason
            access_request.save()
            
            PermissionAuditLog.objects.create(
                user=request.user,
                target_user=access_request.requesting_official,
                action_type='government_access_denied',
                resource_type='government_access_request',
                resource_id=str(access_request.id),
                details={
                    'request_type': access_request.request_type,
                    'rejection_reason': rejection_reason
                },
                ip_address=self.get_client_ip(),
                user_agent=self.get_user_agent()
            )
            
            return Response({
                'message': 'Government access request rejected',
                'reason': rejection_reason
            }, status=status.HTTP_200_OK)
        
        return Response({
            'error': 'Invalid action'
        }, status=status.HTTP_400_BAD_REQUEST)


class PermissionAuditLogView(APIView, RBACPermissionMixin):
    """
    GET /api/rbac/audit/permissions/ - Permission audit log
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request):
        """Get permission audit logs."""
        if not self.has_permission(request.user, 'view_audit_logs'):
            return Response({
                'error': 'Permission denied'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Get query parameters
        action_type = request.query_params.get('action_type')
        user_id = request.query_params.get('user_id')
        days = int(request.query_params.get('days', 30))
        
        # Build query
        logs_query = PermissionAuditLog.objects.all()
        
        if action_type:
            logs_query = logs_query.filter(action_type=action_type)
        
        if user_id:
            logs_query = logs_query.filter(user_id=user_id)
        
        # Filter by date range
        start_date = timezone.now() - timezone.timedelta(days=days)
        logs_query = logs_query.filter(timestamp__gte=start_date)
        
        # Order and limit results
        logs = logs_query.order_by('-timestamp')[:1000]  # Limit to 1000 recent logs
        
        serializer = PermissionAuditLogSerializer(logs, many=True)
        
        return Response({
            'logs': serializer.data,
            'total': logs.count(),
            'period_days': days,
            'filters': {
                'action_type': action_type,
                'user_id': user_id
            }
        }, status=status.HTTP_200_OK)


class CreateRoleView(APIView, RBACPermissionMixin):
    """
    POST /api/rbac/create-role/ - Create custom role (super admin only)
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """Create a new custom role."""
        if not self.has_permission(request.user, 'create_roles'):
            return Response({
                'error': 'Permission denied. Super admin role required.'
            }, status=status.HTTP_403_FORBIDDEN)
        
        serializer = CreateRoleSerializer(data=request.data)
        if serializer.is_valid():
            role = serializer.save(created_by=request.user)
            
            # Log role creation
            PermissionAuditLog.objects.create(
                user=request.user,
                action_type='role_created',
                resource_type='role',
                resource_id=str(role.id),
                role=role,
                details={
                    'role_name': role.name,
                    'role_type': role.role_type,
                    'hierarchy_level': role.hierarchy_level
                },
                ip_address=self.get_client_ip(),
                user_agent=self.get_user_agent()
            )
            
            return Response({
                'message': 'Role created successfully',
                'role': RoleSerializer(role).data
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PermissionCheckView(APIView, RBACPermissionMixin):
    """
    POST /api/rbac/check-permission/ - Check user permission
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """Check if user has specific permission."""
        if not self.has_permission(request.user, 'check_permissions'):
            return Response({
                'error': 'Permission denied'
            }, status=status.HTTP_403_FORBIDDEN)
        
        serializer = PermissionCheckSerializer(data=request.data)
        if serializer.is_valid():
            user_id = serializer.validated_data['user_id']
            permission_codename = serializer.validated_data['permission_codename']
            resource_type = serializer.validated_data.get('resource_type', '')
            resource_id = serializer.validated_data.get('resource_id', '')
            
            try:
                user = User.objects.get(id=user_id)
                has_permission = self.has_permission(user, permission_codename, resource_type, resource_id)
                
                return Response({
                    'user_id': user_id,
                    'permission': permission_codename,
                    'has_permission': has_permission,
                    'resource_type': resource_type,
                    'resource_id': resource_id
                }, status=status.HTTP_200_OK)
                
            except User.DoesNotExist:
                return Response({
                    'error': 'User not found'
                }, status=status.HTTP_404_NOT_FOUND)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class BulkRoleAssignmentView(APIView, RBACPermissionMixin):
    """
    POST /api/rbac/bulk-assign-roles/ - Bulk assign roles to multiple users
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def post(self, request):
        """Bulk assign role to multiple users."""
        if not self.has_permission(request.user, 'assign_roles'):
            return Response({
                'error': 'Permission denied'
            }, status=status.HTTP_403_FORBIDDEN)
        
        serializer = BulkRoleAssignmentSerializer(data=request.data)
        if serializer.is_valid():
            user_ids = serializer.validated_data['user_ids']
            role_id = serializer.validated_data['role_id']
            expires_at = serializer.validated_data.get('expires_at')
            reason = serializer.validated_data.get('reason', 'Bulk assignment')
            
            try:
                role = Role.objects.get(id=role_id)
                
                # Check if assigner can manage this role
                if not self._can_assign_role(request.user, role):
                    return Response({
                        'error': 'Insufficient privileges to assign this role'
                    }, status=status.HTTP_403_FORBIDDEN)
                
                assigned_users = []
                failed_users = []
                
                for user_id in user_ids:
                    try:
                        user = User.objects.get(id=user_id)
                        
                        user_role, created = UserRole.objects.update_or_create(
                            user=user,
                            role=role,
                            defaults={
                                'assigned_by': request.user,
                                'status': 'active',
                                'expires_at': expires_at,
                                'reason': reason,
                                'is_active': True
                            }
                        )
                        
                        assigned_users.append({
                            'user_id': str(user_id),
                            'username': user.username,
                            'created': created
                        })
                        
                        # Log role assignment
                        PermissionAuditLog.objects.create(
                            user=request.user,
                            target_user=user,
                            action_type='role_assigned' if created else 'role_modified',
                            resource_type='user_role',
                            resource_id=str(user_role.id),
                            role=role,
                            details={
                                'role_name': role.name,
                                'bulk_assignment': True,
                                'created': created,
                                'reason': reason
                            },
                            ip_address=self.get_client_ip(),
                            user_agent=self.get_user_agent()
                        )
                        
                    except User.DoesNotExist:
                        failed_users.append({
                            'user_id': str(user_id),
                            'error': 'User not found'
                        })
                
                return Response({
                    'message': f'Bulk role assignment completed',
                    'assigned_users': assigned_users,
                    'failed_users': failed_users,
                    'total_assigned': len(assigned_users),
                    'total_failed': len(failed_users)
                }, status=status.HTTP_200_OK)
                
            except Role.DoesNotExist:
                return Response({
                    'error': 'Role not found'
                }, status=status.HTTP_404_NOT_FOUND)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def _can_assign_role(self, user, role):
        """Check if user can assign the specified role."""
        user_roles = UserRole.objects.filter(
            user=user,
            is_active=True,
            status='active'
        ).select_related('role')
        
        user_max_level = 0
        for user_role in user_roles:
            if user_role.is_valid():
                user_max_level = max(user_max_level, user_role.role.hierarchy_level)
        
        return user_max_level > role.hierarchy_level


class DriverEarningsProtectionView(APIView, RBACPermissionMixin):
    """
    GET /api/rbac/driver-earnings/{driver_id}/ - Access driver earnings (protected)
    """
    permission_classes = [permissions.IsAuthenticated]
    
    def get(self, request, driver_id):
        """Get driver earnings with access protection."""
        try:
            driver = User.objects.get(id=driver_id)
        except User.DoesNotExist:
            return Response({
                'error': 'Driver not found'
            }, status=status.HTTP_404_NOT_FOUND)
        
        # Check if user can access driver earnings
        if not self.has_permission(request.user, 'access_driver_earnings'):
            return Response({
                'error': 'Permission denied. Insufficient privileges to access driver earnings.'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Get or create earnings protection record
        protection, created = DriverEarningsProtection.objects.get_or_create(
            driver=driver,
            defaults={
                'access_level_required': 'admin',
                'government_access_allowed': False
            }
        )
        
        # Check if access is allowed
        if not protection.can_access(request.user):
            return Response({
                'error': 'Access denied. Insufficient role level.'
            }, status=status.HTTP_403_FORBIDDEN)
        
        # Log access
        protection.log_access(request.user)
        
        # Return earnings data (mock data for demo)
        earnings_data = {
            'driver_id': str(driver_id),
            'driver_username': driver.username,
            'access_granted_by': request.user.username,
            'access_timestamp': timezone.now().isoformat(),
            'earnings_summary': {
                'total_earnings': 125000,  # Rwandan Francs
                'rides_completed': 45,
                'average_per_ride': 2778,
                'period': 'last_30_days'
            },
            'access_count': protection.access_count
        }
        
        return Response(earnings_data, status=status.HTTP_200_OK)