from vulnerabilities.services.epss_service import fetch_cve_list, fetch_epss_score
import math
import logging


logger = logging.getLogger(__name__)


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
        # print(final_results)
    else:
        final_results = fetch_epss_score(cve_list)
        logger.info(
            f"Completed full check against epss - Found: {len(final_results)} / {len(cve_list)}")

    # updating vuln data with epss data
    updated_vuln_data = vuln_data
    for cve in updated_vuln_data:
        cve_id = cve['cve_id']

        epss_score = final_results.get(cve_id, None)
        cve['epss_score'] = epss_score
    logger.info("Completed updated CVE's with EPSS scores")
    return updated_vuln_data
