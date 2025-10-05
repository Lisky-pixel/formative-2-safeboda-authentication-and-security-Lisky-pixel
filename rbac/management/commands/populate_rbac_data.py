"""
Management command to populate RBAC data.
"""

from django.core.management.base import BaseCommand
from rbac.models import Permission, Role, RolePermission, RoleHierarchy


class Command(BaseCommand):
    help = 'Populate RBAC data (permissions, roles, and role-permission relationships)'

    def handle(self, *args, **options):
        """Populate RBAC data."""
        
        # Populate permissions
        self.populate_permissions()
        
        # Populate roles
        self.populate_roles()
        
        # Populate role-permission relationships
        self.populate_role_permissions()
        
        # Populate role hierarchy
        self.populate_role_hierarchy()
        
        self.stdout.write(
            self.style.SUCCESS('Successfully populated RBAC data!')
        )

    def populate_permissions(self):
        """Populate permissions."""
        permissions_data = [
            # User Management Permissions
            {'name': 'View Users', 'codename': 'view_users', 'category': 'user_management', 
             'description': 'View user information and profiles', 'resource_type': 'user', 'action': 'read'},
            {'name': 'Manage Users', 'codename': 'manage_users', 'category': 'user_management',
             'description': 'Create, update, and delete user accounts', 'resource_type': 'user', 'action': 'write'},
            {'name': 'View User Permissions', 'codename': 'view_user_permissions', 'category': 'user_management',
             'description': 'View user roles and permissions', 'resource_type': 'user_permission', 'action': 'read'},
            
            # Data Access Permissions
            {'name': 'View Personal Data', 'codename': 'view_personal_data', 'category': 'data_access',
             'description': 'View personal user data', 'resource_type': 'personal_data', 'action': 'read'},
            {'name': 'Access Driver Earnings', 'codename': 'access_driver_earnings', 'category': 'financial_data',
             'description': 'Access driver earnings and financial data', 'resource_type': 'driver_earnings', 'action': 'read'},
            {'name': 'View Analytics Data', 'codename': 'view_analytics_data', 'category': 'analytics',
             'description': 'View analytics and reporting data', 'resource_type': 'analytics', 'action': 'read'},
            
            # System Administration Permissions
            {'name': 'Manage System', 'codename': 'manage_system', 'category': 'system_admin',
             'description': 'Manage system configuration and settings', 'resource_type': 'system', 'action': 'write'},
            {'name': 'View Audit Logs', 'codename': 'view_audit_logs', 'category': 'audit_access',
             'description': 'View system audit logs', 'resource_type': 'audit_log', 'action': 'read'},
            {'name': 'Manage Permissions', 'codename': 'manage_permissions', 'category': 'system_admin',
             'description': 'Manage roles and permissions', 'resource_type': 'permission', 'action': 'write'},
            
            # Role Management Permissions
            {'name': 'View Roles', 'codename': 'view_roles', 'category': 'system_admin',
             'description': 'View available roles', 'resource_type': 'role', 'action': 'read'},
            {'name': 'Assign Roles', 'codename': 'assign_roles', 'category': 'system_admin',
             'description': 'Assign roles to users', 'resource_type': 'user_role', 'action': 'write'},
            {'name': 'Create Roles', 'codename': 'create_roles', 'category': 'system_admin',
             'description': 'Create new custom roles', 'resource_type': 'role', 'action': 'write'},
            {'name': 'Check Permissions', 'codename': 'check_permissions', 'category': 'system_admin',
             'description': 'Check user permissions', 'resource_type': 'permission', 'action': 'read'},
            
            # Government Access Permissions
            {'name': 'Create Government Access Request', 'codename': 'create_government_access_request', 
             'category': 'government_access', 'description': 'Create government data access requests', 
             'resource_type': 'government_request', 'action': 'write'},
            {'name': 'View Government Requests', 'codename': 'view_government_requests', 
             'category': 'government_access', 'description': 'View government access requests', 
             'resource_type': 'government_request', 'action': 'read'},
            {'name': 'Approve Government Requests', 'codename': 'approve_government_requests', 
             'category': 'government_access', 'description': 'Approve or reject government access requests', 
             'resource_type': 'government_request', 'action': 'write'},
            {'name': 'Access Government Data', 'codename': 'access_government_data', 
             'category': 'government_access', 'description': 'Access government-specific data', 
             'resource_type': 'government_data', 'action': 'read'},
            
            # Driver Management Permissions
            {'name': 'Manage Drivers', 'codename': 'manage_drivers', 'category': 'driver_management',
             'description': 'Manage driver accounts and information', 'resource_type': 'driver', 'action': 'write'},
            {'name': 'View Driver Data', 'codename': 'view_driver_data', 'category': 'driver_management',
             'description': 'View driver information and statistics', 'resource_type': 'driver', 'action': 'read'},
            
            # Passenger Management Permissions
            {'name': 'Manage Passengers', 'codename': 'manage_passengers', 'category': 'passenger_management',
             'description': 'Manage passenger accounts and information', 'resource_type': 'passenger', 'action': 'write'},
            {'name': 'View Passenger Data', 'codename': 'view_passenger_data', 'category': 'passenger_management',
             'description': 'View passenger information and statistics', 'resource_type': 'passenger', 'action': 'read'},
            
            # Privacy Management Permissions
            {'name': 'Manage Privacy Settings', 'codename': 'manage_privacy_settings', 'category': 'privacy_management',
             'description': 'Manage user privacy settings and consent', 'resource_type': 'privacy_settings', 'action': 'write'},
            {'name': 'Process Data Requests', 'codename': 'process_data_requests', 'category': 'privacy_management',
             'description': 'Process data export and deletion requests', 'resource_type': 'data_request', 'action': 'write'},
        ]
        
        created_count = 0
        updated_count = 0
        
        for perm_data in permissions_data:
            permission, created = Permission.objects.get_or_create(
                codename=perm_data['codename'],
                defaults={
                    'name': perm_data['name'],
                    'category': perm_data['category'],
                    'description': perm_data['description'],
                    'resource_type': perm_data['resource_type'],
                    'action': perm_data['action'],
                    'is_active': True
                }
            )
            
            if created:
                created_count += 1
                self.stdout.write(
                    self.style.SUCCESS(f'Created permission: {permission.name}')
                )
            else:
                updated_count += 1
                self.stdout.write(
                    self.style.WARNING(f'Permission already exists: {permission.name}')
                )
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Processed {len(permissions_data)} permissions. '
                f'Created: {created_count}, Already existed: {updated_count}'
            )
        )

    def populate_roles(self):
        """Populate roles."""
        roles_data = [
            {
                'name': 'Passenger',
                'codename': 'passenger',
                'role_type': 'passenger',
                'description': 'Standard passenger role with basic permissions',
                'hierarchy_level': 0,
                'is_system_role': True
            },
            {
                'name': 'Driver',
                'codename': 'driver',
                'role_type': 'driver',
                'description': 'Driver role with ride management permissions',
                'hierarchy_level': 1,
                'is_system_role': True
            },
            {
                'name': 'Support Agent',
                'codename': 'support_agent',
                'role_type': 'support_agent',
                'description': 'Customer support agent with user assistance permissions',
                'hierarchy_level': 1,
                'is_system_role': True
            },
            {
                'name': 'Data Analyst',
                'codename': 'data_analyst',
                'role_type': 'analyst',
                'description': 'Data analyst with analytics and reporting permissions',
                'hierarchy_level': 2,
                'is_system_role': True
            },
            {
                'name': 'Administrator',
                'codename': 'admin',
                'role_type': 'admin',
                'description': 'System administrator with management permissions',
                'hierarchy_level': 2,
                'is_system_role': True
            },
            {
                'name': 'Government Official',
                'codename': 'government_official',
                'role_type': 'government_official',
                'description': 'Government official with regulatory access permissions',
                'hierarchy_level': 2,
                'is_system_role': True
            },
            {
                'name': 'Auditor',
                'codename': 'auditor',
                'role_type': 'auditor',
                'description': 'Auditor with audit and compliance permissions',
                'hierarchy_level': 2,
                'is_system_role': True
            },
            {
                'name': 'Super Administrator',
                'codename': 'super_admin',
                'role_type': 'super_admin',
                'description': 'Super administrator with full system access',
                'hierarchy_level': 3,
                'is_system_role': True
            }
        ]
        
        created_count = 0
        updated_count = 0
        
        for role_data in roles_data:
            role, created = Role.objects.get_or_create(
                codename=role_data['codename'],
                defaults={
                    'name': role_data['name'],
                    'role_type': role_data['role_type'],
                    'description': role_data['description'],
                    'hierarchy_level': role_data['hierarchy_level'],
                    'is_system_role': role_data['is_system_role'],
                    'is_active': True
                }
            )
            
            if created:
                created_count += 1
                self.stdout.write(
                    self.style.SUCCESS(f'Created role: {role.name}')
                )
            else:
                updated_count += 1
                self.stdout.write(
                    self.style.WARNING(f'Role already exists: {role.name}')
                )
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Processed {len(roles_data)} roles. '
                f'Created: {created_count}, Already existed: {updated_count}'
            )
        )

    def populate_role_permissions(self):
        """Populate role-permission relationships."""
        role_permissions = {
            'passenger': [
                'view_personal_data',
                'manage_privacy_settings',
            ],
            'driver': [
                'view_personal_data',
                'view_driver_data',
                'manage_privacy_settings',
            ],
            'support_agent': [
                'view_users',
                'view_personal_data',
                'view_passenger_data',
                'manage_privacy_settings',
            ],
            'data_analyst': [
                'view_users',
                'view_personal_data',
                'view_analytics_data',
                'view_driver_data',
                'view_passenger_data',
                'view_audit_logs',
                'manage_privacy_settings',
            ],
            'admin': [
                'view_users',
                'manage_users',
                'view_user_permissions',
                'view_personal_data',
                'view_analytics_data',
                'view_driver_data',
                'view_passenger_data',
                'manage_drivers',
                'manage_passengers',
                'view_roles',
                'assign_roles',
                'view_audit_logs',
                'manage_privacy_settings',
                'process_data_requests',
            ],
            'government_official': [
                'create_government_access_request',
                'view_government_requests',
                'access_government_data',
                'view_analytics_data',
                'view_audit_logs',
            ],
            'auditor': [
                'view_audit_logs',
                'view_analytics_data',
                'view_users',
                'view_personal_data',
                'check_permissions',
            ],
            'super_admin': [
                'view_users',
                'manage_users',
                'view_user_permissions',
                'view_personal_data',
                'access_driver_earnings',
                'view_analytics_data',
                'view_driver_data',
                'view_passenger_data',
                'manage_drivers',
                'manage_passengers',
                'view_roles',
                'assign_roles',
                'create_roles',
                'manage_permissions',
                'check_permissions',
                'view_audit_logs',
                'manage_privacy_settings',
                'process_data_requests',
                'create_government_access_request',
                'view_government_requests',
                'approve_government_requests',
                'access_government_data',
                'manage_system',
            ]
        }
        
        assigned_count = 0
        
        for role_codename, permission_codenames in role_permissions.items():
            try:
                role = Role.objects.get(codename=role_codename)
                
                for perm_codename in permission_codenames:
                    try:
                        permission = Permission.objects.get(codename=perm_codename)
                        
                        # Create role-permission relationship
                        role_permission, created = RolePermission.objects.get_or_create(
                            role=role,
                            permission=permission,
                            defaults={'is_active': True}
                        )
                        
                        if created:
                            assigned_count += 1
                            self.stdout.write(
                                self.style.SUCCESS(f'Assigned permission {permission.name} to role {role.name}')
                            )
                        else:
                            self.stdout.write(
                                self.style.WARNING(f'Permission {permission.name} already assigned to role {role.name}')
                            )
                    
                    except Permission.DoesNotExist:
                        self.stdout.write(
                            self.style.ERROR(f'Permission {perm_codename} not found')
                        )
            
            except Role.DoesNotExist:
                self.stdout.write(
                    self.style.ERROR(f'Role {role_codename} not found')
                )
        
        self.stdout.write(
            self.style.SUCCESS(f'Assigned {assigned_count} role-permission relationships')
        )

    def populate_role_hierarchy(self):
        """Populate role hierarchy relationships."""
        hierarchy_relationships = [
            ('super_admin', 'admin'),
            ('super_admin', 'government_official'),
            ('super_admin', 'auditor'),
            ('admin', 'data_analyst'),
            ('admin', 'support_agent'),
            ('data_analyst', 'driver'),
            ('data_analyst', 'passenger'),
            ('support_agent', 'driver'),
            ('support_agent', 'passenger'),
            ('driver', 'passenger'),
        ]
        
        created_count = 0
        
        for parent_codename, child_codename in hierarchy_relationships:
            try:
                parent_role = Role.objects.get(codename=parent_codename)
                child_role = Role.objects.get(codename=child_codename)
                
                hierarchy, created = RoleHierarchy.objects.get_or_create(
                    parent_role=parent_role,
                    child_role=child_role,
                    defaults={'can_inherit_permissions': True}
                )
                
                if created:
                    created_count += 1
                    self.stdout.write(
                        self.style.SUCCESS(f'Created hierarchy: {parent_role.name} -> {child_role.name}')
                    )
                else:
                    self.stdout.write(
                        self.style.WARNING(f'Hierarchy already exists: {parent_role.name} -> {child_role.name}')
                    )
            
            except Role.DoesNotExist as e:
                self.stdout.write(
                    self.style.ERROR(f'Role not found for hierarchy: {e}')
                )
        
        self.stdout.write(
            self.style.SUCCESS(f'Created {created_count} role hierarchy relationships')
        )
