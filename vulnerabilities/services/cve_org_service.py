import requests
import logging
import pandas as pd


logger = logging.getLogger(__name__)


def obtain_updates():
    delta_file_url = 'https://raw.githubusercontent.com/CVEProject/cvelistV5/refs/heads/main/cves/delta.json'
    try:
        all_vulns = []
        response = requests.get(delta_file_url)
        response.raise_for_status()
        logger.info("CVE Org Data pulled successfully")
        response_json = response.json()
        new_vulns = response_json.get('new', False)

        if new_vulns != False:
            for vuln in new_vulns:
                print(vuln.get('cveId', None))
                vuln_data = {
                    'cve_id': vuln.get('cveId', None),
                    'url': vuln.get('githubLink', None),
                    'source': 'cve.org',
                    'tite': None,
                    'cvss_score': None,
                    'description': None,
                    'application_name': None,
                    'version': None,
                    'published_date': None,
                    'last_modification_date': None,
                    'references': [vuln.get('cveOrgLink', None)],
                    'epss_score': None,
                }
                all_vulns.append(vuln_data)

        return all_vulns
    except requests.exceptions.HTTPError as errh:
        logger.error(f"Http ERROR of CVE ORG: {errh}")
    except requests.exceptions.ConnectionError as errc:
        logger.error(f"Connection error obtaintin CVEORG: {errc}")
    except requests.exceptions.Timeout as errt:
        logger.error(f"Timeout error obtaintin cveorg data: {errt}")
    except requests.exceptions.RequestException as erro:
        logger.error(f"Other error: {erro}")


def parse_cve_org_data(data):
    vuln_df = pd.DataFrame(data)

    print(vuln_df)
