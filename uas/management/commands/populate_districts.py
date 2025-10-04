"""
Management command to populate Rwanda districts.
"""

from django.core.management.base import BaseCommand
from uas.models import RwandaDistrict


class Command(BaseCommand):
    help = 'Populate Rwanda districts data'

    def handle(self, *args, **options):
        """Populate Rwanda districts."""
        districts_data = [
            # Kigali City
            {'name': 'Nyarugenge', 'code': 'NYG', 'province': 'Kigali City'},
            {'name': 'Gasabo', 'code': 'GSB', 'province': 'Kigali City'},
            {'name': 'Kicukiro', 'code': 'KCK', 'province': 'Kigali City'},
            
            # Northern Province
            {'name': 'Burera', 'code': 'BRR', 'province': 'Northern Province'},
            {'name': 'Gakenke', 'code': 'GKN', 'province': 'Northern Province'},
            {'name': 'Gicumbi', 'code': 'GCM', 'province': 'Northern Province'},
            {'name': 'Musanze', 'code': 'MSZ', 'province': 'Northern Province'},
            {'name': 'Rulindo', 'code': 'RLD', 'province': 'Northern Province'},
            
            # Eastern Province
            {'name': 'Bugesera', 'code': 'BGS', 'province': 'Eastern Province'},
            {'name': 'Gatsibo', 'code': 'GTB', 'province': 'Eastern Province'},
            {'name': 'Kayonza', 'code': 'KYZ', 'province': 'Eastern Province'},
            {'name': 'Kirehe', 'code': 'KRH', 'province': 'Eastern Province'},
            {'name': 'Ngoma', 'code': 'NGM', 'province': 'Eastern Province'},
            {'name': 'Nyagatare', 'code': 'NYT', 'province': 'Eastern Province'},
            {'name': 'Rwamagana', 'code': 'RWM', 'province': 'Eastern Province'},
            
            # Southern Province
            {'name': 'Gisagara', 'code': 'GSG', 'province': 'Southern Province'},
            {'name': 'Huye', 'code': 'HYE', 'province': 'Southern Province'},
            {'name': 'Kamonyi', 'code': 'KMY', 'province': 'Southern Province'},
            {'name': 'Muhanga', 'code': 'MHG', 'province': 'Southern Province'},
            {'name': 'Nyamagabe', 'code': 'NMG', 'province': 'Southern Province'},
            {'name': 'Nyanza', 'code': 'NYZ', 'province': 'Southern Province'},
            {'name': 'Nyaruguru', 'code': 'NYR', 'province': 'Southern Province'},
            {'name': 'Ruhango', 'code': 'RHG', 'province': 'Southern Province'},
            {'name': 'Rusizi', 'code': 'RSZ', 'province': 'Southern Province'},
            {'name': 'Rutsiro', 'code': 'RTR', 'province': 'Southern Province'},
            {'name': 'Karongi', 'code': 'KRG', 'province': 'Southern Province'},
            
            # Western Province
            {'name': 'Rubavu', 'code': 'RBV', 'province': 'Western Province'},
            {'name': 'Nyabihu', 'code': 'NBH', 'province': 'Western Province'},
            {'name': 'Ngororero', 'code': 'NGR', 'province': 'Western Province'},
            {'name': 'Karongi', 'code': 'KRG', 'province': 'Western Province'},
            {'name': 'Rutsiro', 'code': 'RTR', 'province': 'Western Province'},
            {'name': 'Rubavu', 'code': 'RBV', 'province': 'Western Province'},
            {'name': 'Nyabihu', 'code': 'NBH', 'province': 'Western Province'},
            {'name': 'Ngororero', 'code': 'NGR', 'province': 'Western Province'},
        ]
        
        created_count = 0
        updated_count = 0
        
        for district_data in districts_data:
            district, created = RwandaDistrict.objects.get_or_create(
                code=district_data['code'],
                defaults={
                    'name': district_data['name'],
                    'province': district_data['province'],
                    'is_active': True
                }
            )
            
            if created:
                created_count += 1
                self.stdout.write(
                    self.style.SUCCESS(f'Created district: {district.name}')
                )
            else:
                updated_count += 1
                self.stdout.write(
                    self.style.WARNING(f'District already exists: {district.name}')
                )
        
        self.stdout.write(
            self.style.SUCCESS(
                f'Successfully processed {len(districts_data)} districts. '
                f'Created: {created_count}, Already existed: {updated_count}'
            )
        )
