from vulnerabilities.services.epss_service import fetch_cve_list, fetch_epss_score


def enhance_with_epss(vuln_data):
    # Enhance CVE Data with EPSS data if available

    # call the epss_service and pass it cve_list
    cve_list = fetch_cve_list(vuln_data)
    print(cve_list)
    # call fetch epss score function passing it the
    epss_scores = fetch_epss_score(cve_list)

    # for cve in vuln_data:
    #     cve_id = cve['cve_id']
    #     epss_score = epss_scores.get(cve_id, None)
    #     cve['epss_score'] = epss_score
    # return vuln_data
