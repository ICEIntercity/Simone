import re
from http import client as httpclient
from urllib.error import URLError
from urllib.request import urlopen
from urllib import parse as urlparse
from bs4 import BeautifulSoup
import ssl
import socket
import logging
import whois
import datetime
import config
import urllib
import sys

# Refer to included word document for full description of the following rules


# If an IP address is contained within the link, it is almost certainly malicious
def detect_ip(link: str) -> float:
    regex = re.compile("(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}")
    if re.search(regex, link) is not None:
        return -1
    else:
        return 1


# Excessive URL length is a potential symptom of phishing
def check_url_length(link: str) -> float:
    if len(link) < 55:
        return 1
    else:
        if len(link) < 75:
            return 0
        else:
            return -1


# Check for redirect - immediate redirect(s) will be marked as suspicious
# TODO: Find a better way to detect public shorteners only, as many businesses use their own internal redirects
def check_short_url(link: str) -> float:
    parsed = urlparse.urlparse(link)
    http = httpclient.HTTPConnection(parsed.netloc)
    http.request('HEAD', parsed.path)
    response = http.getresponse()

    if response.status // 100 == 3 and response.getheader('Location') != link:
        return -1
    else:
        return 1


# Some browsers ignore url elements before @ sign
# @deprecated?
def check_at_character(link: str) -> float:
    regex = re.compile("@")
    if re.search(regex, link) is not None:
        return -1
    else:
        return 1


# Some redirects might be visible in parameters - make sure that "//" or "www" only appear once
def check_http_www(link: str) -> float:
    search_slash = link.rfind("//")
    search_www = link.rfind("www.")
    search_http = link.rfind("http")

    if search_slash > 7 or search_www > 11 or search_http > 4:
        return -1
    else:
        return 1


# Check domain level and/or occurrences of "-" in domain
def check_domain_str(link: str) -> dict:
    domain_regex = re.compile("^(?:https?://)?(?:[^@\n]+@)?(?:www.)?([^:/\n?]+)")
    domain_find = re.search(domain_regex, link)

    results = {
        "dot_result": 0,
        "dash_result": -1,
        "http_result": 1,
    }

    if domain_find is not None:
        domain = domain_find.group(1)
        if domain.count("-") is -1:
            results.update(dash_result=0)

        dot_count = domain.count(".")

        # 1 dot = legit, 2 dots (default) = suspicious, > 2 dots = phishing
        if dot_count == 1:
            results.update(dot_result=1)
        else:
            if dot_count > 2:
                results.update(dot_result=-1)

        if domain.count("http") is not 0:
            results.update(http_result=-1)

    return results


# Make sure that all applicable SSL standards are being followed (Not sure how effective this is)
def check_ssl(link: str) -> float:
    log = logging.getLogger('simone_core')
    hostname = None

    hostname = urlparse.urlparse(link).hostname

    if hostname is None:
        log.warning("SSL check failed, invalid  URL")
        return -1

    try:
        # Strict x.509 SSL, secure
        ctx = ssl.create_default_context()
        ctx.set_default_verify_paths()
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.verify_flags = ssl.VERIFY_X509_STRICT  # Just to be safe
        ctx.set_ciphers("TLSv1.2")
        ctx.check_hostname = True
        ctx.load_default_certs()
        s = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
        s.connect((hostname, 443))
        s.close()
        return 1

    except ssl.SSLError:
        log.info("X.509 not followed, assuming insecure: " + link)
    except OSError:
        log.warning("Connection failed during SSL verification.")

    return -1


# Unfortunately, much of the WHOIS information is now redacted. Domain check had been replaced by analyst input
# until further notice
# TODO: Implement sender checks in conjunction with e-mail body
# Probably just check for proper nouns in the e-mail body and match them against the URL?
def check_whois(link: str) -> dict:
    log = logging.getLogger('simone_core')
    host = None

    results = {
        "record_exists": -1,
        "domain_age": -1,
        "domain_expiry": 1,
    }

    try:
        host = urlparse.urlparse(link)
    except ValueError:
        raise RuntimeError("WHOIS check failed, invalid URL")

    whois_info = whois.whois(host.hostname)

    if whois_info.domain_name is None:
        log.error("WHOIS check failed: no WHOIS information for ", host)
        return results
    else:
        results.update(record_exists=1)

    today = datetime.datetime.now()

    # Does not appear to work in practical applications. Retaining to comply with dataset format
    # expiry = (whois_info.expiration_date - today).days

    # The WHOIS lib used sometimes returns a list object instead of a plain datetime - must be handled
    creation_date = None
    if isinstance(whois_info.creation_date, (list,)):
        creation_date = whois_info.creation_date[0]
    else:
        creation_date = whois_info.creation_date

    domain_age = (today - creation_date).days

    if domain_age > 180:  # Domain older than 6 months, to comply with dataset requirements
        results.update(domain_age=1)

    # TODO: Finish

    return results


# Port scanning is not allowed by local security rules. May change in the future
def check_ports(link: str) -> float:
    return 1


# Several of the considered parameters are based on the HTML content of a phishing site
# NOTE: Does this count as clicking the link...?
def check_html(link: str) -> dict:
    log = logging.getLogger("simone_core")
    results = {
        "favicon": -1,
        "ext_res": 0,
        "ext_anchor": 0,
        "ext_script": 0,
        "status_change": -1,
    }
    link_parsed = urlparse.urlparse(link)
    if link_parsed.hostname is None:
        raise RuntimeError("HTML check failed, invalid URL supplied: " + link)

    page = None
    host = link_parsed.hostname  # Placeholder value
    try:
        req = urllib.request.Request(link, data=None, headers={
            "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"
        })
        page = urllib.request.urlopen(req)
        host = urlparse.urlparse(page.url).hostname

    except urllib.error.HTTPError as e:  # Exotic HTTP errors, Hackers can be sneaky...
        page = e.read().decode()

    except urllib.error.URLError:
        log.warning("Failed to open site.")

    soup = BeautifulSoup(page, features="html.parser")
    icon = soup.find("link", rel="shortcut icon")
    icon_link = icon['href']
    icon_host = urlparse.urlparse(icon_link).hostname

    # if favicon is hosted on the same server
    if (icon_host is None and icon_link.find("data:") == -1) or icon_host == host:
        results.update(favicon=1)

    resource_href = {host: 0, "data": 0}  # Initializing the value for locally-hosted resources without url
    anchor_href = {host: 0, "data": 0}  # Ditto, but limited to anchors and links ("<a>" tag)
    script_href = {host: 0, "data": 0}  # Ditto, but for <link>, <meta> and <script>

    # Get the % of externally requested resources for each category (phishing sites often use external resources to blend in)
    # This is probably going to be painfully slow...
    # TODO: Try to find a way to improve/fix this
    href_tags = soup.find_all(href=True)
    src_tags = soup.find_all(src=True)
    for tag in href_tags:

        # embedding data directly into phishing sites is the current equivalent of using external resources
        if tag['href'].find("data:") is not -1:
            print(tag)
            if tag.name == "a":
                anchor_href["data"] += 1
            else:
                if tag.name == "meta" or tag.name == "link" or tag.name == "script":
                    script_href["data"] += 1
                else:
                    resource_href["data"] += 1

            continue

        tag_url = urlparse.urlparse(tag['href'])

        if tag_url.hostname is not None:
            # print(tag)
            if tag.name == "a":
                if tag_url.hostname not in anchor_href:
                    anchor_href[tag_url.hostname] = 1
                else:
                    anchor_href[tag_url.hostname] += 1
            else:
                if tag.name == "meta" or tag.name == "link" or tag.name == "script":
                    if tag_url.hostname not in script_href:
                        script_href[tag_url.hostname] = 1
                    else:
                        script_href[tag_url.hostname] += 1
                else:
                    if tag_url.hostname not in resource_href:
                        resource_href[tag_url.hostname] = 1
                    else:
                        resource_href[tag_url.hostname] += 1
        else:
            if tag.name == "a":
                anchor_href[host] += 1
            else:
                if tag.name == "meta" or tag.name == "link" or tag.name == "script":
                    script_href[host] += 1
                else:
                    resource_href[host] += 1

    src_tags = soup.find_all(src=True)
    for src_tag in src_tags:

        # embedding data directly into phishing sites is the current equivalent of using external resources
        if src_tag['src'].find("data:") is not -1:
            if src_tag.name == "a":
                anchor_href["data"] += 1
            else:
                if src_tag.name == "meta" or src_tag.name == "link" or src_tag.name == "script":
                    script_href["data"] += 1
                else:
                    resource_href["data"] += 1

            continue

        tag_url = urlparse.urlparse(src_tag['src'])

        if tag_url.hostname is not None:
            # print(tag)
            if src_tag.name == "a":
                if tag_url.hostname not in anchor_href:
                    anchor_href[tag_url.hostname] = 1
                else:
                    anchor_href[tag_url.hostname] += 1
            else:
                if src_tag.name == "meta" or src_tag.name == "link" or src_tag.name == "script":
                    if tag_url.hostname not in script_href:
                        script_href[tag_url.hostname] = 1
                    else:
                        script_href[tag_url.hostname] += 1
                else:
                    if tag_url.hostname not in resource_href:
                        resource_href[tag_url.hostname] = 1
                    else:
                        resource_href[tag_url.hostname] += 1
        else:
            if src_tag.name == "a":
                anchor_href[host] += 1
            else:
                if src_tag.name == "meta" or src_tag.name == "link" or src_tag.name == "script":
                    script_href[host] += 1
                else:
                    resource_href[host] += 1

    total_res = sum(resource_href.values())
    total_a = sum(anchor_href.values())
    total_script = sum(script_href.values())

    print(total_res)
    print(total_script)
    print(total_a)

    ext_request_percentage = 1 - (resource_href[host] / total_res) if total_res != 0 else 0
    ext_anchor_percentage = 1 - (anchor_href[host] / total_a) if total_a != 0 else 0
    ext_script_percentage = 1 - (script_href[host] / total_script) if total_script != 0 else 0

    if ext_request_percentage < 0.25:
        results.update(ext_res=1)
    else:
        if ext_request_percentage > 0.6:
            results.update(ext_res=-1)

    if ext_anchor_percentage < 0.31:
        results.update(ext_anchor=1)
    else:
        if ext_anchor_percentage > 0.60:
            results.update(ext_anchor=-1)

    if ext_script_percentage < 0.17:
        results.update(ext_script=1)
    else:
        if ext_script_percentage > 0.80:
            results.update(ext_script=-1)

    # print(ext_script_percentage)
    # print(ext_request_percentage)
    # print(ext_anchor_percentage)

    # print(resource_href)
    # print(anchor_href)
    # print(script_href)

    # Probably not relevant anymore? (Check for changes of the status bar)
    body = soup.__repr__()
    if body.find("window.status") == -1:
        results.update(status_change=1)

    return results


# Checking Server Form Handlers heading to blank or external sites. Since this is no longer valid as per W3C standards,
# this check has been rendered moot.
def check_fsh(link: str):
    return 1


# Sending form information directly to e-mail is also an indication of phishing. This is also done server-side in most
# cases, it is virtually impossible to detect
def check_mail_handlers(link: str):
    return 1



