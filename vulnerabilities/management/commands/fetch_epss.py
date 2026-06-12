from django.core.management.base import BaseCommand
from vulnerabilities.services.epss_service import fetch_cve_list, fetch_epss_score


class Command(BaseCommand):
    help = "Obtain EPSS Data"

    def handle(self, *args, **options):
        self.stdout.write("Fetching EPSS Data")

        # cve_data = [
        #     {'cve_id': 'CVE-2022-27225'},
        #     {'cve_id': 'CVE-2022-27223'},
        #     {'cve_id': 'CVE-2022-27218'},
        # ]
        # cve_list = fetch_cve_list(cve_data)
        # epss_scores = fetch_epss_score(cve_list)
        # print(epss_scores)
