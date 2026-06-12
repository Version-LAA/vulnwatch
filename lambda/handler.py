import os
import json
import logging
import requests
import psycopg
from datetime import datetime, timedelta
import math
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
    ssl_mode = os.environ.get('DB_SSLMODE', 'disable')
    return psycopg.connect(
        host=os.environ['DB_HOST'],
        dbname=os.environ['DB_NAME'],
        user=os.environ['DB_USER'],
        password=os.environ['DB_PASSWORD'],
        port=os.environ['DB_PORT'],
        sslmode=ssl_mode,
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


def fetch_parse_cve_org_data():
    # parse cve data
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
                    'date_added': datetime.now().strftime("%Y-%m-%d"),
                    'is_kev': False,

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
                last_modification_date = EXCLUDED.last_modification_date,
                epss_score = EXCLUDED.epss_score

        """, record)

        conn.commit()
        logger.info(f"Saved {len(data)} records to database")

        cve_ids = [r['cve_id'] for r in data]
        cursor.execute("""
            SELECT cve_id FROM vulnerabilities
            WHERE cve_id = ANY(%s)
            AND epss_score IS NOT NULL
        """, (cve_ids,))

        rows = cursor.fetchall()
        cve_ids_with_epss = [row[0] for row in rows]
        logger.info(
            f"Found {len(cve_ids_with_epss)} CVEs with EPSS scores for enrichment")
        return cve_ids_with_epss

    except Exception as e:
        conn.rollback()
        logger.error(f"DB save failed: {e}")
        raise
    finally:
        cursor.close()
        conn.close()


def fetch_cve_list(vul_list):

    cve_list = []

    for vul in vul_list:

        cve_list.append(vul['cve_id'])

    return cve_list


def fetch_epss_score(cve_list):
    if len(cve_list) == 0:
        return {}
    cve_list_str = ",".join(cve_list)
    logger.info(f"Submitting {len(cve_list)} CVE's to epss for evaluation")
    url = f"https://api.first.org/data/v1/epss?cve={cve_list_str}"

    try:
        response = requests.get(url)
        response.raise_for_status()
        response_json = response.json()
        cve_data = response_json.get('data', None)
        if cve_data:
            logger.info(
                f"Successfully pulled CVE of data. Found: {len(cve_data)}/{len(cve_list)}")
            epss_results = {}
            for cve in cve_data:
                epss_results[cve['cve']] = cve['epss']
            return epss_results

        else:
            return {}
    except requests.exceptions.HTTPError as errh:
        logger.error(f"HTTP error {errh}")
    except requests.exceptions.ConnectionError as errc:
        logger.error(f"Connection Error {errc}")
    except requests.exceptions.Timeout as errt:
        logger.error(f"Timeout Error {errt}")
    except requests.exceptions.RequestException as err:
        logger.error(f"Error: {err}")
    return {}


def enhance_with_epss(vuln_data):
    # Enhance CVE Data with EPSS data if available

    final_results = {}
    # call the epss_service and pass it cve_list
    cve_list = fetch_cve_list(vuln_data)

    # epss api only supports up to 2000 characters of cve (~ 125CVEs)
    if len(cve_list) >= 110:
        logger.info(
            f"CVE list for EPSS check is to large for one request:({len(cve_list)}), breaking up check. ")
        smaller_results = []
        num_calls = math.ceil(len(cve_list) / 110)
        startindex = 0
        endindex = 0

        while num_calls > 1:
            endindex += 110
            smaller_results.append(cve_list[startindex:endindex])
            startindex += 110
            num_calls -= 1
        if num_calls == 1:
            smaller_results.append(cve_list[startindex:])

        for sub_list in smaller_results:
            epss_scores = fetch_epss_score(sub_list)
            final_results.update(epss_scores)
        logger.info(
            f"Completed full check against epss - Found: {len(final_results)} / {len(cve_list)}")

    else:
        final_results = fetch_epss_score(cve_list)
        logger.info(
            f"Completed full check against epss - Found: {len(final_results)} / {len(cve_list)}")

    # updating vuln data with epss data
    updated_vuln_data = vuln_data.copy()
    for cve in updated_vuln_data:
        cve_id = cve['cve_id']

        epss_score = final_results.get(cve_id, None)
        cve['epss_score'] = epss_score
    logger.info("Completed updated CVE's with EPSS scores")
    return updated_vuln_data


def save_to_affected_products_db(conn, product_list):
    cursor = conn.cursor()
    try:
        for product in product_list:
            cve_id = product['vulnerability']

            cursor.execute("""
                INSERT INTO vulnerabilities_affectedproduct
                    (vulnerability_id, name, vendor, version)
                VALUES
                    (%s, %s, %s, %s)
                ON CONFLICT ON CONSTRAINT vulnerabilities_affected_vulnerability_id_vendor__49fd8640_uniq
                DO UPDATE SET
                    version = EXCLUDED.version
            """, (
                cve_id,
                product.get('name'),
                product.get('vendor') or 'unknown',
                json.dumps(product.get('version', []))
            ))

        conn.commit()
        logger.info(f"Saved {len(product_list)} affected products")
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to save affected products: {e}")
        raise
    finally:
        cursor.close()


def update_existing_entries(cve_ids):
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        for cve_id in cve_ids:
            year = cve_id.split('-')[1]
            number = cve_id.split('-')[2]
            folder = number[:-3] + 'xxx'
            url = f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{folder}/{cve_id}.json"

            cve_data = fetch_cve_data(url)
            if not cve_data:
                continue

            # only update fields that are currently null
            cursor.execute("""
                UPDATE vulnerabilities
                SET
                    cvss_score = CASE WHEN cvss_score IS NULL THEN %s ELSE cvss_score END,
                    title = CASE WHEN title IS NULL THEN %s ELSE title END
                WHERE cve_id = %s
            """, (
                cve_data.get('cvss_score'),
                cve_data.get('title'),
                cve_id
            ))
            logger.info(f"Updated {cve_id} from CVE.org")

            # save affected products
            if cve_data.get('raw_affected'):
                save_to_affected_products_db(conn, cve_data['raw_affected'])
                logger.info(f"Updated AffectedProducts for {cve_id}")

        conn.commit()
        logger.info("Completed update_existing_entries")

    except Exception as e:
        conn.rollback()
        logger.error(f"update_existing_entries failed: {e}")
        raise
    finally:
        cursor.close()
        conn.close()


def handler(event, context):
    logger.info("VulnWatch Lambda Starting")

    try:
        nvd_raw = fetch_nvd()
        nvd_parsed = parse_nvd_data(nvd_raw)
        enhanced_with_epss = enhance_with_epss(nvd_parsed)
        cve_ids_with_epss = save_to_db(enhanced_with_epss)
        if cve_ids_with_epss:
            update_existing_entries(cve_ids_with_epss)

        cve_parsed = fetch_parse_cve_org_data()
        if not cve_parsed[0]:
            logger.error("Failed to fetch cve.org data")
            return
        enhanced_with_data = enhance_with_epss(cve_parsed[0])
        save_to_db(enhanced_with_data)
        logger.info("VulnWatch Lambda Finished")

        return {"statusCode": 200, "body": json.dumps("Success")}

    except Exception as e:
        logger.error(f"Lambda failed: {e}")
        return {"statusCode": 500, "body": json.dumps(str(e))}


# if __name__ == "__main__":

#     handler({}, {})
