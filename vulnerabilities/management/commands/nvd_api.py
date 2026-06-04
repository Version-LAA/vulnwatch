from django.core.management.base import BaseCommand
import requests
import pandas as pd
from datetime import datetime, timedelta
import json
import math
from vulnerabilities.models import Vulnerability


class Command(BaseCommand):
    help = 'Obtain NVD data via api'

    # [todo] make api call to obtain data
    # [todo] parse nvd data
    def obtain_nvd(self):
        pub_end = datetime.now()
        pub_start = pub_end + timedelta(days=-1)
        pub_start_str = str(pub_start.strftime("%Y-%m-%d"))+"T00:00:00.000"
        pub_end_str = str(pub_end.strftime("%Y-%m-%d"))+"T00:00:00.000"
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate={pub_start_str}&pubEndDate={pub_end_str}"
        try:
            response = requests.get(url)
            response.raise_for_status()
            self.stdout.write("Data pulled successfully")
            response_json = response.json()
            if response_json['totalResults'] <= 2000:
                return response_json
            else:
                # [todo - loop through pages]
                all_responses = []
                total_pages = math.ceil(response_json['totalResults'] / 2000)
                pass
        except requests.exceptions.HTTPError as errh:
            self.stdout.write("HTTP Error:", errh)
        except requests.exceptions.ConnectionError as errc:
            self.stdout.write("Connection Error:", errc)
        except requests.exceptions.Timeout as errt:
            self.stdout.write("Timeout Error:", errt)
        except requests.exceptions.RequestException as err:
            self.stdout.write("Something else:", err)

    def parse_nvd_data(self, response):
        vulnerabilities = response['vulnerabilities']
        vul_list = []
        for v in vulnerabilities:
            v = v['cve']
            metrics = v['metrics']

            metrics40 = metrics.get('cvssMetricV40', 'no data')
            metrics31 = metrics.get('cvssMetricV31', 'no data')
            metrics2 = metrics.get('cvssMetricV2', 'no data')

            description = v['descriptions'][0]['value']
            published_date = v['published']
            last_modification_date = v['lastModified']
            source = 'NVD'
            references = []

            for r in v['references']:
                references.append(r['url'])
            vuln_data = {
                'cve_id': v['id'],
                'title': '',
                'cvss_score': None,
                'source': source,
                'description': description,
                'epss_score': '',
                'application_name': '',
                'version': '',
                'published_date': published_date,
                'date_added': '',
                'last_modification_date': last_modification_date,
                'is_kev': ''

            }

            if metrics31 != 'no data':
                basescore = metrics31[0]['cvssData'].get('baseScore', None)
                if basescore:
                    basescore = float(basescore)
                vuln_data['cvss_score'] = basescore

            vul_list.append(vuln_data)
        return vul_list

        # print(vul_list)

    def obtain_epss_data(self):
        pass

    def test_function(self):
        self.stdout.write('This is testing this function')
        pub_end = datetime.now()
        pub_start = pub_end - timedelta(days=1)
        dt = str(pub_start)
        self.stdout.write(dt)

    def handle(self, *args, **options):
        self.stdout.write('Testing Running NVD Command')
        nvd_data = self.obtain_nvd()
        parsed_nvd = self.parse_nvd_data(nvd_data)

        # convert the list of dicts into an iterable of model instances
        instances = [Vulnerability(**data) for data in parsed_nvd]

        # single batch db insert
        Vulnerability.objects.bulk_create(instances)
        self.stdout.write("Successfully inserted to database")
