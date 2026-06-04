import requests
from datetime import datetime, timedelta
import math
import sys
from vulnerabilities.models import Vulnerability


# [todo] make api call to obtain data
# [todo] parse nvd data


def obtain_nvd():
    pub_end = datetime.now()
    pub_start = pub_end + timedelta(days=-1)
    pub_start_str = str(pub_start.strftime("%Y-%m-%d"))+"T00:00:00.000"
    pub_end_str = str(pub_end.strftime("%Y-%m-%d"))+"T00:00:00.000"
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate={pub_start_str}&pubEndDate={pub_end_str}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        sys.stdout.write("Data pulled successfully")
        response_json = response.json()
        if response_json['totalResults'] <= 2000:
            return response_json
        else:
            # [todo - loop through pages]
            all_responses = []
            total_pages = math.ceil(response_json['totalResults'] / 2000)
            pass
    except requests.exceptions.HTTPError as errh:
        sys.stdout.write(f"HTTP Error:{errh}")
    except requests.exceptions.ConnectionError as errc:
        sys.stdout.write(f"Connection Error: {errc}")
    except requests.exceptions.Timeout as errt:
        sys.stdout.write(f"Timeout Error:{errt}")
    except requests.exceptions.RequestException as err:
        sys.stdout.write(f"Something else:{err}")


def parse_nvd_data(response):
    today_date = datetime.now().strftime("%Y-%m-%d")
    vulnerabilities = response['vulnerabilities']
    vul_list = []
    for v in vulnerabilities:
        v = v['cve']
        metrics = v['metrics']

        metrics40 = metrics.get('cvssMetricV40', 'no data')
        metrics31 = metrics.get('cvssMetricV31', 'no data')
        metrics2 = metrics.get('cvssMetricV2', 'no data')

        description = v['descriptions'][0]['value']
        published_date = v['published'].split('T')[0]
        last_modification_date = v['lastModified'].split('T')[0]
        source = 'NVD'
        references = []

        for r in v['references']:
            references.append(r['url'])
        vuln_data = {
            'cve_id': v['id'],
            'title': None,
            'cvss_score': None,
            'source': source,
            'description': description,
            'epss_score': None,
            'application_name': None,
            'version': None,
            'published_date': published_date,
            'date_added': today_date,
            'last_modification_date': last_modification_date,
            'is_kev': False,
            'references': references

        }

        if metrics31 != 'no data':
            basescore = metrics31[0]['cvssData'].get('baseScore', None)
            if basescore:
                basescore = float(basescore)
            vuln_data['cvss_score'] = basescore

        vul_list.append(vuln_data)
    return vul_list

    # print(vul_list)


def obtain_epss_data(parsed_data):
    pass


def save_nvd_data(parsed_data):
    # convert the list of dicts into an iterable of model instances
    instances = [Vulnerability(**data) for data in parsed_data]

    # single batch db insert
    Vulnerability.objects.bulk_create(
        instances,
        update_conflicts=True,
        unique_fields=['cve_id'],
        update_fields=[
            'cvss_score',
            'description',
            'last_modification_date',
            'references'
        ]
    )
