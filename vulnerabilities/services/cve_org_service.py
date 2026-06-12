import requests
import logging
from vulnerabilities.models import Vulnerability, AffectedProduct


logger = logging.getLogger(__name__)


def parse_version(affected_list):
    # affected is a list of dictionaries
    # all seem to include vendor, product (another list of dictionsaries with version)
    # parse version list within cve.org dataset

    parsed_version = []
    # affected_products = affected_list.get('versions', None)
    if affected_list == None:
        return parse_version

    # for i in affected_list:
    #     print(i)
    #     print("")

    return parsed_version


def fetch_cve_data(url):

    try:
        response = requests.get(url)
        response.raise_for_status()
        response_json = response.json()
        published_date = response_json['cveMetadata']['datePublished'].split('T')[
            0]
        valid_cve_data = response_json.get('containers', False)
        if valid_cve_data:
            valid_cve_data = valid_cve_data.get('cna', False)

        cvss_score = None
        if valid_cve_data != False:
            available_metrics = valid_cve_data.get('metrics', [])
            for metric in available_metrics:
                if 'cvssV3_1' in metric:
                    cvss_score = metric['cvssV3_1'].get('baseScore', None)
                    break
                else:
                    cvss_score = None

            affected_version = valid_cve_data.get('affected', None)
            if affected_version:
                version_results = []
                for version in affected_version:
                    version_output = {
                        'vulnerability': response_json['cveMetadata']['cveId'],
                        'name': version.get('product', None),
                        'vendor': version.get('vendor', None),
                        'version': version.get('versions', [])
                    }
                    version_results.append(version_output)

            output = {
                'published_date': published_date,
                'title': valid_cve_data.get('title', None),
                'description': valid_cve_data.get('descriptions')[0].get('value', None),
                'cvss_score': cvss_score,
                'version': None,
                'application_name': valid_cve_data.get('affected')[0].get('product', None),
                'cve_id': response_json['cveMetadata']['cveId'],
                'raw_affected': version_results,
            }
            return output
        else:
            logger.debug(
                f'error parsing {response_json['cveMetadata']['cveId']}')
            return False
    except requests.exceptions.HTTPError as errh:
        logger.error(f"HTTP Error: {errh}")
    except requests.exceptions.ConnectionError as errc:
        logger.error(f"Connection error occured: {errc}")
    except requests.exceptions.Timeout as errt:
        logger.error(f"Timeout error occured: {errt}")
    except requests.exceptions.RequestException as err:
        logger.error(f"Something else: {err}")
        return None


def obtain_updates():
    delta_file_url = 'https://raw.githubusercontent.com/CVEProject/cvelistV5/refs/heads/main/cves/delta.json'
    try:
        all_vulns = []
        all_products = []
        response = requests.get(delta_file_url)
        response.raise_for_status()
        logger.info("CVE Org Data pulled successfully")
        response_json = response.json()
        new_vulns = response_json.get('new', False)

        if new_vulns != False:
            for vuln in new_vulns:
                cveid = vuln.get('cveId', None)
                github_url = vuln.get('githubLink', None)
                vuln_long_data = fetch_cve_data(github_url) or {}
                title = vuln_long_data.get('title', None)
                cvss_score = vuln_long_data.get('cvss_score', None)
                version = vuln_long_data.get('version', None)
                description = vuln_long_data.get('description', None)
                published_date = vuln_long_data.get('published_date', None)
                application_name = vuln_long_data.get(
                    'application_name', None),
                raw_affected = vuln_long_data.get('raw_affected', None)
                vuln_data = {
                    'cve_id': cveid,
                    'source': 'cve.org',
                    'title': title,
                    'cvss_score': cvss_score,
                    'description': description,
                    'application_name': application_name,
                    'version': version,
                    'published_date': published_date,
                    'last_modification_date': published_date,
                    'references': [vuln.get('cveOrgLink', None)],
                    'epss_score': None,

                }
                all_products.extend(raw_affected)
                all_vulns.append(vuln_data)

        return (all_vulns, all_products)
    except requests.exceptions.HTTPError as errh:
        logger.error(f"Http ERROR of CVE ORG: {errh}")
    except requests.exceptions.ConnectionError as errc:
        logger.error(f"Connection error obtaintin CVEORG: {errc}")
    except requests.exceptions.Timeout as errt:
        logger.error(f"Timeout error obtaintin cveorg data: {errt}")
    except requests.exceptions.RequestException as erro:
        logger.error(f"Other error: {erro}")


def save_cve_org_data(parsed_data):
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
                'published_date',
                'references',
                'title',
                'application_name',
                'version'
            ]
        )
        logger.info(f"updated data {len(instances)} vulnerabilities to db")

    except Exception as e:
        logger.error(f"Failed to save vulnerabilities:{e}")
        raise
