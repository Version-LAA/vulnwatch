import requests
from datetime import datetime, timedelta
import math
import logging
from vulnerabilities.models import Vulnerability
from .cve_org_service import fetch_cve_data
from .update_affected_product import save_to_affected_products_db

# [todo] make api call to obtain data
# [todo] parse nvd data

logger = logging.getLogger(__name__)


def obtain_nvd():
    logger.info("Kicking of NVD data pull")
    pub_end = datetime.now()
    pub_start = pub_end - timedelta(days=1)
    pub_start_str = str(pub_start.strftime("%Y-%m-%d")) + \
        "T"+str(pub_start.strftime("%H:%M:%S"))
    pub_end_str = str(pub_end.strftime("%Y-%m-%d"))+"T" + \
        str(pub_end.strftime("%H:%M:%S"))

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate={pub_start_str}&pubEndDate={pub_end_str}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        logger.info("NVD Data pulled successfully")
        response_json = response.json()
        if response_json['totalResults'] <= 2000:
            return response_json
        else:
            # [todo - loop through pages]
            # all_responses = []
            # total_pages = math.ceil(response_json['totalResults'] / 2000)
            logger.warning(
                f"Result set exceeds 2000 ({response_json['totalResults']} results) — pagination not yet implemented, returning first page only")
            return response_json

    except requests.exceptions.HTTPError as errh:
        logger.error(f"HTTP Error:{errh}")
    except requests.exceptions.ConnectionError as errc:
        logger.error(f"Connection Error: {errc}")
    except requests.exceptions.Timeout as errt:
        logger.error(f"Timeout Error:{errt}")
    except requests.exceptions.RequestException as err:
        logger.error(f"Something else:{err}")


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


def update_existing_entries(vulnerabilities):
    print("")
    print(vulnerabilities)
    print("")
    print(len(vulnerabilities))

    for vuln in vulnerabilities:
        cve_id = vuln.cve_id
        year = cve_id.split('-')[1]
        number = cve_id.split('-')[2]
        folder = number[:-3] + 'xxx'

        url = f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{folder}/{cve_id}.json"

        cve_data = fetch_cve_data(url)
        updated = False

        if not vuln.cvss_score and cve_data.get('cvss_score'):
            vuln.cvss_score = cve_data['cvss_score']
            updated = True
        if not vuln.title and cve_data.get('title'):
            vuln.title = cve_data['title']
            updated = True
        if updated:
            vuln.save()
            logger.info(f"Enriched {cve_id} from CVE.org")

        if cve_data.get('raw_affected'):
            save_to_affected_products_db(cve_data['raw_affected'])
            logger.info(f"Updated AffectedProducts db {cve_id} from CVE.org")


def save_nvd_data(parsed_data):
    # convert the list of dicts into an iterable of model instances
    instances = [Vulnerability(**data) for data in parsed_data]

    # single batch db insert
    try:

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
        logger.info(f"Saved data {len(instances)} vulnerabilities to db")
        cve_ids = [v.cve_id for v in instances]
        vulnerabilities = Vulnerability.objects.filter(
            cve_id__in=cve_ids,
            epss_score__isnull=False)

        update_existing_entries(vulnerabilities)
    except Exception as e:
        logger.error(f"Failed to save vulnerabilities:{e}")
        raise
