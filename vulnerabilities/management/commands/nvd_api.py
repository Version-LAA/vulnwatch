from django.core.management.base import BaseCommand
import vulnerabilities.services as services


class Command(BaseCommand):
    help = 'Obtain NVD data via api'

    def handle(self, *args, **options):
        self.stdout.write('Obtaining NVD Command')
        nvd_data = services.obtain_nvd()
        parsed_nvd = services.parse_nvd_data(nvd_data)
        services.save_nvd_data(parsed_nvd)

        self.stdout.write("\nSuccessfully inserted to database")
