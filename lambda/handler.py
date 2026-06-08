import os
import json
import logging
import requests
import psycopg
from datetime import datetime, timedelta
from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def get_db_connection():
    # connects to Postgres
    return psycopg.connect(
        host=os.environ['DB_HOST'],
        dbname=os.environ['DB_NAME'],
        user=os.environ['DB_USER'],
        password=os.environ['DB_PASSWORD'],
        port=os.environ['DB_PORT'],
    )


def fetch_nvd():
    # obtain nvd data
    pub_end = datetime.now()
    pub_start = pub_end + timedelta(days=-1)
    pub_start_str = str(pub_start.strftime("%Y-%m-%d"))+"T00:00:00.000"
    pub_end_str = str(pub_end.strftime("%Y-%m-%d"))+"T00:00:00.000"
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate={pub_start_str}&pubEndDate={pub_end_str}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        logger.info("NVD Data pulled successfully")
        response_json = response.json()
        if response_json['totalResults'] <= 2000:
            return response_json
        else:
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
    # parse nvd data

    today_date = datetime.now().strftime("%Y-%m-%d")
    vulnerabilities = response['vulnerabilities']
    vul_list = []
    for v in vulnerabilities:
        v = v['cve']
        metrics = v['metrics']

        metrics31 = metrics.get('cvssMetricV31', 'no data')

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


def fetch_cve_org_delta(url):
    # obtain cve.org data
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

            output = {
                'published_date': published_date,
                'title': valid_cve_data['title'],
                'description': valid_cve_data.get('descriptions')[0].get('value', None),
                'cvss_score': cvss_score,
                'version': valid_cve_data.get('affected')[0].get('versions')[0].get('version'),
                'application_name': valid_cve_data.get('affected')[0].get('product', None),
                'cve_id': response_json['cveMetadata']['cveId']
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


def fetch_parse_cve_org_data():
    # parse cve data
    today_date = datetime.now().strftime("%Y-%m-%d")
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
                cveid = vuln.get('cveId', None)
                github_url = vuln.get('githubLink', None)
                vuln_long_data = fetch_cve_org_delta(github_url) or {}

                title = vuln_long_data.get('title', None)
                cvss_score = vuln_long_data.get('cvss_score', None)
                version = vuln_long_data.get('version', None)
                description = vuln_long_data.get('description', None)
                published_date = vuln_long_data.get('published_date', None)
                application_name = vuln_long_data.get('application_name', None)
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
                    'date_added': today_date,
                    'is_kev': False,

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


def save_to_db(data):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        for record in data:
            record['references'] = json.dumps(record.get('references', []))

            cursor.execute("""
    INSERT INTO vulnerabilities
        (cve_id, description, cvss_score, source, published_date,
         last_modification_date, is_kev, "references", title,
         application_name, version, epss_score, date_added)
    VALUES
        (%(cve_id)s, %(description)s, %(cvss_score)s, %(source)s,
         %(published_date)s, %(last_modification_date)s, %(is_kev)s,
         %(references)s, %(title)s, %(application_name)s,
         %(version)s, %(epss_score)s, %(date_added)s)
    ON CONFLICT (cve_id) DO UPDATE SET
        cvss_score = EXCLUDED.cvss_score,
        description = EXCLUDED.description,
        last_modification_date = EXCLUDED.last_modification_date
""", record)

        conn.commit()
        logger.info(f"Saved {len(data)} records to database")
    except Exception as e:
        conn.rollback()
        logger.error(f"DB save failed: {e}")
        raise
    finally:
        cursor.close()
        conn.close()


def handler(event, context):
    logger.info("VulnWatch Lambda Starting")

    try:
        nvd_raw = fetch_nvd()
        nvd_parsed = parse_nvd_data(nvd_raw)
        save_to_db(nvd_parsed)

        cve_parsed = fetch_parse_cve_org_data()
        save_to_db(cve_parsed)

        return {"statusCode": 200, "body": json.dumps("Success")}

    except Exception as e:
        logger.error(f"Lambda failed: {e}")
        return {"statusCode": 500, "body": json.dumps(str(e))}


# if __name__ == "__main__":

#     handler({}, {})
