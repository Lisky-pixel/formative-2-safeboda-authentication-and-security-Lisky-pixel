"""
Management command to populate privacy-related data.
"""

from django.core.management.base import BaseCommand
from privacy.models import ConsentType, DataRetentionPolicy, DataProcessingActivity


class Command(BaseCommand):
    help = 'Populate privacy-related data (consent types, retention policies, processing activities)'

    def handle(self, *args, **options):
        """Populate privacy data."""
        
        # Populate consent types
        self.populate_consent_types()
        
        # Populate retention policies
        self.populate_retention_policies()
        
        # Populate processing activities
        self.populate_processing_activities()
        
        self.stdout.write(
            self.style.SUCCESS('Successfully populated privacy-related data!')
        )

    def populate_consent_types(self):
        """Populate consent types."""
        consent_types_data = [
            {
                'name': 'Essential Cookies',
                'category': 'essential',
                'description': 'Required for basic website functionality and security.',
                'is_required': True,
                'retention_period_days': 365,
            },
            {
                'name': 'Analytics and Performance',
                'category': 'analytics',
                'description': 'Help us understand how you use our service to improve performance.',
                'is_required': False,
                'retention_period_days': 730,
            },
            {
                'name': 'Marketing Communications',
                'category': 'marketing',
                'description': 'Send you promotional offers, updates, and marketing communications.',
                'is_required': False,
                'retention_period_days': 1095,  # 3 years
            },
            {
                'name': 'Personalized Experience',
                'category': 'personalization',
                'description': 'Provide personalized recommendations and user experience.',
                'is_required': False,
                'retention_period_days': 365,
            },
            {
                'name': 'Location Data',
                'category': 'location',
                'description': 'Access your location to provide ride services and safety features.',
                'is_required': False,
                'retention_period_days': 90,
            },
            {
                'name': 'Third Party Sharing',
                'category': 'third_party',
                'description': 'Share your data with trusted partners for service improvement.',
                'is_required': False,
                'retention_period_days': 365,
            },
            {
                'name': 'Biometric Data',
                'category': 'biometric',
                'description': 'Process biometric data for identity verification and security.',
                'is_required': False,
                'retention_period_days': 180,
            },
        ]
        
        created_count = 0
        updated_count = 0
        
        for consent_data in consent_types_data:
            consent_type, created = ConsentType.objects.get_or_create(
                name=consent_data['name'],
                defaults={
                    'category': consent_data['category'],
                    'description': consent_data['description'],
                    'is_required': consent_data['is_required'],
                    'retention_period_days': consent_data['retention_period_days'],
                    'is_active': True
                }
            )
            
            if created:
                created_count += 1
                self.stdout.write(
                    self.style.SUCCESS(f'Created consent type: {consent_type.name}')
                )
            else:
                updated_count += 1
                self.stdout.write(
                    self.style.WARNING(f'Consent type already exists: {consent_type.name}')
                )
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Processed {len(consent_types_data)} consent types. '
                f'Created: {created_count}, Already existed: {updated_count}'
            )
        )

    def populate_retention_policies(self):
        """Populate data retention policies."""
        retention_policies_data = [
            {
                'data_type': 'user_profile',
                'retention_period_days': 2555,  # 7 years
                'retention_basis': 'legal_requirement',
                'description': 'User profile data retained for legal compliance and audit purposes.',
                'auto_delete': False,
                'requires_consent': True,
            },
            {
                'data_type': 'contact_info',
                'retention_period_days': 365,
                'retention_basis': 'business_necessity',
                'description': 'Contact information retained for service delivery and communication.',
                'auto_delete': True,
                'requires_consent': True,
            },
            {
                'data_type': 'location_data',
                'retention_period_days': 90,
                'retention_basis': 'business_necessity',
                'description': 'Location data retained for ride history and safety features.',
                'auto_delete': True,
                'requires_consent': True,
            },
            {
                'data_type': 'payment_info',
                'retention_period_days': 1825,  # 5 years
                'retention_basis': 'legal_requirement',
                'description': 'Payment information retained for financial compliance and dispute resolution.',
                'auto_delete': False,
                'requires_consent': True,
            },
            {
                'data_type': 'usage_data',
                'retention_period_days': 730,  # 2 years
                'retention_basis': 'business_necessity',
                'description': 'Usage data retained for service improvement and analytics.',
                'auto_delete': True,
                'requires_consent': False,
            },
            {
                'data_type': 'communication_data',
                'retention_period_days': 365,
                'retention_basis': 'business_necessity',
                'description': 'Communication records retained for customer support and service quality.',
                'auto_delete': True,
                'requires_consent': True,
            },
            {
                'data_type': 'biometric_data',
                'retention_period_days': 180,
                'retention_basis': 'user_consent',
                'description': 'Biometric data retained for identity verification and security.',
                'auto_delete': True,
                'requires_consent': True,
            },
        ]
        
        created_count = 0
        updated_count = 0
        
        for policy_data in retention_policies_data:
            policy, created = DataRetentionPolicy.objects.get_or_create(
                data_type=policy_data['data_type'],
                defaults={
                    'retention_period_days': policy_data['retention_period_days'],
                    'retention_basis': policy_data['retention_basis'],
                    'description': policy_data['description'],
                    'auto_delete': policy_data['auto_delete'],
                    'requires_consent': policy_data['requires_consent'],
                    'is_active': True
                }
            )
            
            if created:
                created_count += 1
                self.stdout.write(
                    self.style.SUCCESS(f'Created retention policy: {policy.get_data_type_display()}')
                )
            else:
                updated_count += 1
                self.stdout.write(
                    self.style.WARNING(f'Retention policy already exists: {policy.get_data_type_display()}')
                )
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Processed {len(retention_policies_data)} retention policies. '
                f'Created: {created_count}, Already existed: {updated_count}'
            )
        )

    def populate_processing_activities(self):
        """Populate data processing activities."""
        processing_activities_data = [
            {
                'activity_name': 'User Registration and Authentication',
                'description': 'Processing user data for account creation, authentication, and identity verification.',
                'legal_basis': 'contract',
                'data_categories': ['personal_info', 'contact_info', 'biometric_data'],
                'data_subjects': ['customers', 'drivers', 'employees'],
                'recipients': ['internal_systems', 'payment_processors'],
                'third_country_transfers': False,
                'retention_period': '7 years or until account deletion',
                'security_measures': ['encryption', 'access_controls', 'audit_logging'],
            },
            {
                'activity_name': 'Ride Services',
                'description': 'Processing location and ride data to provide transportation services.',
                'legal_basis': 'contract',
                'data_categories': ['location_data', 'usage_data', 'payment_info'],
                'data_subjects': ['customers', 'drivers'],
                'recipients': ['internal_systems', 'map_providers'],
                'third_country_transfers': False,
                'retention_period': '90 days for location data, 2 years for ride history',
                'security_measures': ['encryption', 'data_minimization', 'pseudonymization'],
            },
            {
                'activity_name': 'Customer Support',
                'description': 'Processing communication data to provide customer support services.',
                'legal_basis': 'legitimate_interests',
                'data_categories': ['communication_data', 'personal_info'],
                'data_subjects': ['customers', 'drivers'],
                'recipients': ['support_team', 'internal_systems'],
                'third_country_transfers': False,
                'retention_period': '1 year after resolution',
                'security_measures': ['access_controls', 'data_minimization'],
            },
            {
                'activity_name': 'Analytics and Service Improvement',
                'description': 'Processing usage data to analyze service performance and improve user experience.',
                'legal_basis': 'legitimate_interests',
                'data_categories': ['usage_data', 'analytics'],
                'data_subjects': ['customers', 'drivers'],
                'recipients': ['analytics_team', 'product_team'],
                'third_country_transfers': False,
                'retention_period': '2 years',
                'security_measures': ['anonymization', 'pseudonymization', 'data_minimization'],
            },
            {
                'activity_name': 'Marketing Communications',
                'description': 'Processing contact information to send promotional offers and updates.',
                'legal_basis': 'consent',
                'data_categories': ['contact_info', 'usage_data'],
                'data_subjects': ['customers'],
                'recipients': ['marketing_team', 'email_service_providers'],
                'third_country_transfers': True,
                'retention_period': 'Until consent is withdrawn',
                'security_measures': ['consent_management', 'opt_out_mechanisms'],
            },
            {
                'activity_name': 'Safety and Security',
                'description': 'Processing data for safety monitoring, incident reporting, and security purposes.',
                'legal_basis': 'legitimate_interests',
                'data_categories': ['location_data', 'usage_data', 'biometric_data'],
                'data_subjects': ['customers', 'drivers'],
                'recipients': ['safety_team', 'security_team', 'law_enforcement'],
                'third_country_transfers': False,
                'retention_period': 'As required by law or 2 years',
                'security_measures': ['encryption', 'access_controls', 'audit_logging'],
            },
        ]
        
        created_count = 0
        updated_count = 0
        
        for activity_data in processing_activities_data:
            activity, created = DataProcessingActivity.objects.get_or_create(
                activity_name=activity_data['activity_name'],
                defaults={
                    'description': activity_data['description'],
                    'legal_basis': activity_data['legal_basis'],
                    'data_categories': activity_data['data_categories'],
                    'data_subjects': activity_data['data_subjects'],
                    'recipients': activity_data['recipients'],
                    'third_country_transfers': activity_data['third_country_transfers'],
                    'retention_period': activity_data['retention_period'],
                    'security_measures': activity_data['security_measures'],
                    'is_active': True
                }
            )
            
            if created:
                created_count += 1
                self.stdout.write(
                    self.style.SUCCESS(f'Created processing activity: {activity.activity_name}')
                )
            else:
                updated_count += 1
                self.stdout.write(
                    self.style.WARNING(f'Processing activity already exists: {activity.activity_name}')
                )
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Processed {len(processing_activities_data)} processing activities. '
                f'Created: {created_count}, Already existed: {updated_count}'
            )
        )
