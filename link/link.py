from urllib.parse import urlparse
import numpy as np
import link.analysis as analysis
import logging

def validate_url(link: str) -> bool:
    parsed = urlparse(link)

    if not parsed.netloc or not parsed.scheme:
        return False
    else:
        return True


def build_input(link: str):
    log = logging.getLogger("simone_core")

    if not validate_url(link):
        raise RuntimeError("Failed to build dataset for processing: URL Invalid")

    result = np.zeros(shape=(1, 21))

    try:

        domain_str = analysis.check_domain_str(link)
        whois = analysis.check_whois(link)
        html = analysis.check_html(link)

        # Please work correctly...
        result[0][0] = analysis.detect_ip(link)
        result[0][1] = analysis.check_url_length(link)
        result[0][2] = analysis.check_short_url(link)
        result[0][3] = domain_str["at_result"]
        result[0][4] = analysis.check_http_www(link)
        result[0][5] = domain_str["dash_result"]
        result[0][6] = domain_str["dot_result"]
        result[0][7] = analysis.check_ssl(link)
        result[0][8] = whois["domain_expiry"]
        result[0][9] = html["favicon"]
        result[0][10] = domain_str["http_result"]
        result[0][11] = html["ext_res"]
        result[0][12] = html["ext_anchor"]
        result[0][13] = html["ext_script"]
        result[0][14] = whois["public_identity"]
        result[0][15] = analysis.check_redirects(link)
        result[0][16] = html["status_change"]
        result[0][17] = html["iframe"]
        result[0][18] = whois["domain_age"]
        result[0][19] = analysis.check_page_rank(link)
        result[0][20] = analysis.check_phishtank_reputation(link)

    except Exception:

        raise RuntimeError("Failed to build dataset. See output above for details.")

    return result
