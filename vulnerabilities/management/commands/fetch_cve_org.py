from django.core.management.base import BaseCommand
import vulnerabilities.services.cve_org_service as cve_service
import vulnerabilities.services.normalize_cve_data_service as normalize_cve


class Command(BaseCommand):
    help = "CVE Org Parser"

    def handle(self, *args, **options):
        self.stdout.write("Fetching CVE.org data...")
        cve_data = cve_service.obtain_updates()

        if not cve_data:
            self.stdout.write(self.style.ERROR("Failed to fetch cve.org data"))
            return
        enahnced_epss = normalize_cve.enhance_with_epss(cve_data)
        # cve_service.save_cve_org_data(enahnced_epss)
        # self.stdout.write(self.style.SUCCESS(
        #     f"Successfully saved {len(cve_data)} vulnerabilities"))
