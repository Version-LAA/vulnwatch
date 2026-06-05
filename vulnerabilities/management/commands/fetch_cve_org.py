from django.core.management.base import BaseCommand
import vulnerabilities.services.cve_org_service as cve_service


class Command(BaseCommand):
    help = "CVE Org Parser"

    def handle(self, *args, **options):
        self.stdout.write("Testing CVE_ORG_Command")
        cve_data = cve_service.obtain_updates()
        cve_service.parse_cve_org_data(cve_data)
