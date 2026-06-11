import requests
import logging

logger = logging.getLogger(__name__)


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
        logger.error(f"Error: {errc}")
    return {}
