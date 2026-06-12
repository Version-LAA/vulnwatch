from django.core.management.base import BaseCommand
import vulnerabilities.services.nvd_service as nvd_service
import vulnerabilities.services.normalize_cve_data_service as normalize_cve


class Command(BaseCommand):
    help = 'Obtain NVD data via api'

    def handle(self, *args, **options):
        self.stdout.write('NVD Data command started:')

        nvd_data = nvd_service.obtain_nvd()
        parsed_nvd = nvd_service.parse_nvd_data(nvd_data)
        enhanced_epss = normalize_cve.enhance_with_epss(parsed_nvd)
        nvd_service.save_nvd_data(enhanced_epss)
