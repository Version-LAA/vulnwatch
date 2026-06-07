from django.core.management.base import BaseCommand
import vulnerabilities.services.cve_org_service as cve_service


class Command(BaseCommand):
    help = "CVE Org Parser"

    def handle(self, *args, **options):
        self.stdout.write("Fetching CVE.org data...")
        cve_data = cve_service.obtain_updates()

        if not cve_data:
            self.stdout.write(self.style.ERROR("Failed to fetch cve.org data"))
            return

        cve_service.save_cve_org_data(cve_data)
        self.stdout.write(self.style.SUCCESS(
            f"Successfully saved {len(cve_data)} vulnerabilities"))
