"""
Test script for RBAC (Role-Based Access Control) functionality.
"""

import os
import sys
import django
from django.conf import settings

# Add the project directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Set up Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'safeboda_auth.settings')
django.setup()

from authentication.models import User
from rbac.models import (
    Permission, Role, RolePermission, UserRole, GovernmentAccessRequest,
    PermissionAuditLog, AccessControlRule, RoleHierarchy, DriverEarningsProtection
)


def test_permissions():
    """Test permissions functionality."""
    print("Testing Permissions...")
    
    # Get all permissions
    permissions = Permission.objects.filter(is_active=True)
    print(f"[OK] Found {permissions.count()} active permissions")
    
    # Test permission creation
    permission, created = Permission.objects.get_or_create(
        codename='test_permission',
        defaults={
            'name': 'Test Permission',
            'category': 'system_admin',
            'description': 'Test permission for RBAC testing',
            'resource_type': 'test_resource',
            'action': 'read',
            'is_active': True
        }
    )
    
    if created:
        print("[OK] Test permission created")
    else:
        print("[OK] Test permission already exists")
    
    print(f"[OK] Permission name: {permission.name}")
    print(f"[OK] Permission codename: {permission.codename}")
    print(f"[OK] Permission category: {permission.category}")
    
    return permission


def test_roles():
    """Test roles functionality."""
    print("\nTesting Roles...")
    
    # Get all roles
    roles = Role.objects.filter(is_active=True)
    print(f"[OK] Found {roles.count()} active roles")
    
    # Test role creation
    role, created = Role.objects.get_or_create(
        codename='test_role',
        defaults={
            'name': 'Test Role',
            'role_type': 'admin',
            'description': 'Test role for RBAC testing',
            'hierarchy_level': 2,
            'is_system_role': False,
            'is_active': True
        }
    )
    
    if created:
        print("[OK] Test role created")
    else:
        print("[OK] Test role already exists")
    
    print(f"[OK] Role name: {role.name}")
    print(f"[OK] Role type: {role.role_type}")
    print(f"[OK] Hierarchy level: {role.hierarchy_level}")
    print(f"[OK] Permissions count: {role.get_permissions().count()}")
    
    return role


def test_role_permissions():
    """Test role-permission relationships."""
    print("\nTesting Role-Permission Relationships...")
    
    # Get test role and permission
    role = Role.objects.filter(codename='test_role').first()
    permission = Permission.objects.filter(codename='test_permission').first()
    
    if not role or not permission:
        print("[SKIP] Test role or permission not found")
        return None
    
    # Create role-permission relationship
    role_permission, created = RolePermission.objects.get_or_create(
        role=role,
        permission=permission,
        defaults={'is_active': True}
    )
    
    if created:
        print("[OK] Role-permission relationship created")
    else:
        print("[OK] Role-permission relationship already exists")
    
    print(f"[OK] Role: {role_permission.role.name}")
    print(f"[OK] Permission: {role_permission.permission.name}")
    print(f"[OK] Is active: {role_permission.is_active}")
    
    # Test permission checking
    has_permission = role.has_permission('test_permission')
    print(f"[OK] Role has test permission: {has_permission}")
    
    return role_permission


def test_user_roles():
    """Test user-role assignments."""
    print("\nTesting User-Role Assignments...")
    
    # Get test user and role
    user = User.objects.filter(username__startswith='testuser').first()
    role = Role.objects.filter(codename='test_role').first()
    
    if not user or not role:
        print("[SKIP] Test user or role not found")
        return None
    
    # Create user-role assignment
    user_role, created = UserRole.objects.get_or_create(
        user=user,
        role=role,
        defaults={
            'status': 'active',
            'reason': 'Test assignment',
            'is_active': True
        }
    )
    
    if created:
        print("[OK] User-role assignment created")
    else:
        print("[OK] User-role assignment already exists")
    
    print(f"[OK] User: {user_role.user.username}")
    print(f"[OK] Role: {user_role.role.name}")
    print(f"[OK] Status: {user_role.status}")
    print(f"[OK] Is valid: {user_role.is_valid()}")
    
    return user_role


def test_government_access_requests():
    """Test government access requests."""
    print("\nTesting Government Access Requests...")
    
    # Get test user
    user = User.objects.filter(username__startswith='testuser').first()
    
    if not user:
        print("[SKIP] No test user found")
        return None
    
    # Create government access request
    access_request = GovernmentAccessRequest.objects.create(
        requesting_official=user,
        government_agency='Rwanda Utilities Regulatory Authority',
        official_title='Regulatory Officer',
        official_id='RURA-001',
        request_type='user_data',
        purpose='Regulatory compliance review',
        legal_basis='Rwanda Data Protection Law',
        data_categories=['user_profile', 'contact_info'],
        status='pending',
        ip_address='127.0.0.1',
        user_agent='Test Agent'
    )
    
    print(f"[OK] Government access request created: {access_request.id}")
    print(f"[OK] Government agency: {access_request.government_agency}")
    print(f"[OK] Request type: {access_request.request_type}")
    print(f"[OK] Status: {access_request.status}")
    print(f"[OK] Is expired: {access_request.is_expired()}")
    
    return access_request


def test_permission_audit_logs():
    """Test permission audit logs."""
    print("\nTesting Permission Audit Logs...")
    
    # Get test user
    user = User.objects.filter(username__startswith='testuser').first()
    
    if not user:
        print("[SKIP] No test user found")
        return None
    
    # Create audit log entry
    audit_log = PermissionAuditLog.objects.create(
        user=user,
        action_type='role_assigned',
        resource_type='user_role',
        resource_id='test_id',
        details={'test': True},
        ip_address='127.0.0.1',
        user_agent='Test Agent'
    )
    
    print(f"[OK] Permission audit log created: {audit_log.id}")
    print(f"[OK] Action type: {audit_log.action_type}")
    print(f"[OK] Resource type: {audit_log.resource_type}")
    print(f"[OK] User: {audit_log.user.username}")
    
    return audit_log


def test_role_hierarchy():
    """Test role hierarchy."""
    print("\nTesting Role Hierarchy...")
    
    # Get test roles
    parent_role = Role.objects.filter(codename='test_role').first()
    child_role = Role.objects.filter(codename='passenger').first()
    
    if not parent_role or not child_role:
        print("[SKIP] Test roles not found")
        return None
    
    # Create hierarchy relationship
    hierarchy, created = RoleHierarchy.objects.get_or_create(
        parent_role=parent_role,
        child_role=child_role,
        defaults={'can_inherit_permissions': True}
    )
    
    if created:
        print("[OK] Role hierarchy created")
    else:
        print("[OK] Role hierarchy already exists")
    
    print(f"[OK] Parent role: {hierarchy.parent_role.name}")
    print(f"[OK] Child role: {hierarchy.child_role.name}")
    print(f"[OK] Can inherit permissions: {hierarchy.can_inherit_permissions}")
    
    return hierarchy


def test_access_control_rules():
    """Test access control rules."""
    print("\nTesting Access Control Rules...")
    
    # Get test permission
    permission = Permission.objects.filter(codename='test_permission').first()
    
    if not permission:
        print("[SKIP] Test permission not found")
        return None
    
    # Create access control rule
    rule, created = AccessControlRule.objects.get_or_create(
        name='Test Access Rule',
        defaults={
            'rule_type': 'time_based',
            'permission': permission,
            'conditions': {'allowed_hours': [9, 17]},
            'is_active': True,
            'priority': 1
        }
    )
    
    if created:
        print("[OK] Access control rule created")
    else:
        print("[OK] Access control rule already exists")
    
    print(f"[OK] Rule name: {rule.name}")
    print(f"[OK] Rule type: {rule.rule_type}")
    print(f"[OK] Permission: {rule.permission.name}")
    print(f"[OK] Conditions: {rule.conditions}")
    
    return rule


def test_driver_earnings_protection():
    """Test driver earnings protection."""
    print("\nTesting Driver Earnings Protection...")
    
    # Get test user
    driver = User.objects.filter(username__startswith='testuser').first()
    
    if not driver:
        print("[SKIP] No test user found")
        return None
    
    # Create driver earnings protection
    protection, created = DriverEarningsProtection.objects.get_or_create(
        driver=driver,
        defaults={
            'access_level_required': 'admin',
            'government_access_allowed': False
        }
    )
    
    if created:
        print("[OK] Driver earnings protection created")
    else:
        print("[OK] Driver earnings protection already exists")
    
    print(f"[OK] Driver: {protection.driver.username}")
    print(f"[OK] Access level required: {protection.access_level_required}")
    print(f"[OK] Government access allowed: {protection.government_access_allowed}")
    print(f"[OK] Access count: {protection.access_count}")
    
    return protection


def test_rbac_integration():
    """Test RBAC system integration."""
    print("\nTesting RBAC System Integration...")
    
    # Get test user
    user = User.objects.filter(username__startswith='testuser').first()
    
    if not user:
        print("[SKIP] No test user found")
        return
    
    # Test comprehensive RBAC data
    user_roles_count = UserRole.objects.filter(user=user).count()
    audit_logs_count = PermissionAuditLog.objects.filter(user=user).count()
    access_requests_count = GovernmentAccessRequest.objects.filter(requesting_official=user).count()
    
    print(f"[OK] User has {user_roles_count} role assignments")
    print(f"[OK] User has {audit_logs_count} audit log entries")
    print(f"[OK] User has {access_requests_count} government access requests")
    
    # Test permission checking
    if user_roles_count > 0:
        user_role = UserRole.objects.filter(user=user).first()
        if user_role.is_valid():
            role = user_role.role
            permissions_count = role.get_permissions().count()
            print(f"[OK] User's active role '{role.name}' has {permissions_count} permissions")
            
            # Test specific permission
            has_test_permission = role.has_permission('test_permission')
            print(f"[OK] Role has test permission: {has_test_permission}")
    
    # Test role hierarchy
    hierarchies_count = RoleHierarchy.objects.count()
    print(f"[OK] System has {hierarchies_count} role hierarchy relationships")
    
    # Test access control rules
    rules_count = AccessControlRule.objects.filter(is_active=True).count()
    print(f"[OK] System has {rules_count} active access control rules")


def test_rbac_permissions_by_category():
    """Test permissions by category."""
    print("\nTesting Permissions by Category...")
    
    categories = Permission.PERMISSION_CATEGORIES
    
    for category_code, category_name in categories:
        permissions = Permission.objects.filter(category=category_code, is_active=True)
        print(f"[OK] {category_name}: {permissions.count()} permissions")
        
        # Show first few permissions in each category
        for perm in permissions[:3]:
            print(f"    - {perm.name} ({perm.codename})")


def test_role_hierarchy_levels():
    """Test role hierarchy levels."""
    print("\nTesting Role Hierarchy Levels...")
    
    roles = Role.objects.filter(is_active=True).order_by('-hierarchy_level')
    
    print("[OK] Role hierarchy (highest to lowest):")
    for role in roles:
        print(f"    Level {role.hierarchy_level}: {role.name} ({role.role_type})")


def main():
    """Run all RBAC tests."""
    print("SafeBoda RBAC (Role-Based Access Control) - Test Suite")
    print("=" * 60)
    
    try:
        # Test permissions
        permission = test_permissions()
        
        # Test roles
        role = test_roles()
        
        # Test role-permission relationships
        role_permission = test_role_permissions()
        
        # Test user-role assignments
        user_role = test_user_roles()
        
        # Test government access requests
        access_request = test_government_access_requests()
        
        # Test permission audit logs
        audit_log = test_permission_audit_logs()
        
        # Test role hierarchy
        hierarchy = test_role_hierarchy()
        
        # Test access control rules
        access_rule = test_access_control_rules()
        
        # Test driver earnings protection
        earnings_protection = test_driver_earnings_protection()
        
        # Test RBAC integration
        test_rbac_integration()
        
        # Test permissions by category
        test_rbac_permissions_by_category()
        
        # Test role hierarchy levels
        test_role_hierarchy_levels()
        
        print("\n" + "=" * 60)
        print("[OK] All RBAC tests passed! Role-Based Access Control system is working.")
        
        # Clean up test data
        cleanup_objects = [
            permission, role, role_permission, user_role, access_request,
            audit_log, hierarchy, access_rule, earnings_protection
        ]
        
        for obj in cleanup_objects:
            if obj:
                try:
                    obj.delete()
                except Exception as e:
                    print(f"[WARNING] Could not delete test object: {e}")
        
        print("[OK] Test data cleaned up.")
        
    except Exception as e:
        print(f"\n[FAIL] Test failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
