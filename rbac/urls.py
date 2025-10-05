"""
URL configuration for RBAC app.
"""

from django.urls import path
from . import views

urlpatterns = [
    # Role Management
    path('roles/', views.RolesListView.as_view(), name='rbac_roles'),
    path('assign-role/', views.AssignRoleView.as_view(), name='rbac_assign_role'),
    path('create-role/', views.CreateRoleView.as_view(), name='rbac_create_role'),
    path('bulk-assign-roles/', views.BulkRoleAssignmentView.as_view(), name='rbac_bulk_assign_roles'),
    
    # Permission Management
    path('permissions/', views.UserPermissionsView.as_view(), name='rbac_permissions'),
    path('check-permission/', views.PermissionCheckView.as_view(), name='rbac_check_permission'),
    
    # Administrative Interface
    path('admin/users/', views.AdminUserManagementView.as_view(), name='rbac_admin_users'),
    
    # Government Access
    path('government/access-request/', views.GovernmentAccessRequestView.as_view(), name='rbac_government_access_request'),
    path('government/access-request/<uuid:request_id>/approve/', 
         views.GovernmentAccessApprovalView.as_view(), name='rbac_government_access_approve'),
    path('government/access-request/<uuid:request_id>/reject/', 
         views.GovernmentAccessApprovalView.as_view(), name='rbac_government_access_reject'),
    
    # Audit and Monitoring
    path('audit/permissions/', views.PermissionAuditLogView.as_view(), name='rbac_audit_permissions'),
    
    # Driver Earnings Protection
    path('driver-earnings/<uuid:driver_id>/', views.DriverEarningsProtectionView.as_view(), name='rbac_driver_earnings'),
]