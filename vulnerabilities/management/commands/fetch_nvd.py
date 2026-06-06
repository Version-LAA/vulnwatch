from django.core.management.base import BaseCommand
import vulnerabilities.services.nvd_service as nvd_service


class Command(BaseCommand):
    help = 'Obtain NVD data via api'

    def handle(self, *args, **options):
        self.stdout.write('Obtaining NVD Command')
        nvd_data = nvd_service.obtain_nvd()
        parsed_nvd = nvd_service.parse_nvd_data(nvd_data)
        nvd_service.save_nvd_data(parsed_nvd)

        self.stdout.write("\nSuccessfully inserted to database")
