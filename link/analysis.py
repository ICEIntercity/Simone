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
import requests
import json
import xml.etree.ElementTree as xml


# Refer to included word document for full description of the following rules
# Developing a new dataset may be necessary in the future.


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


# Check for URL Shortener use
def check_short_url(link: str) -> float:
    # This thing is *long*. Go to line 794 for continuation.
    shortener_list = [
            "0rz.tw/",

            "1link.in/",

            "1url.com/",

            "2.gp/",

            "2big.at/",

            "2tu.us/",

            "3.ly/",

            "307.to/",

            "4ms.me/",

            "4sq.com/",

            "4url.cc/",

            "6url.com/",

            "7.ly/",

            "7vd.cn/",

            "a.gg/",

            "a.nf/",

            "aa.cx/",

            "abcurl.net/",

            "ad.vu/",

            "adcraft.co/",

            "adcrun.ch/",

            "adf.ly/",

            "adjix.com/",

            "afx.cc/",

            "aka.gr/",

            "all.fuseurl.com/",

            "alturl.com/",

            "amzn.to/",

            "ar.gy/",

            "arst.ch/",

            "atu.ca/",

            "azc.cc/",

            "b23.ru/",

            "b2l.me/",

            "bacn.me/",

            "bc.vc/",

            "bcool.bz/",

            "binged.it/",

            "bit.do/",

            "bit.ly/",

            "bitly.com/",

            "bizj.us/",

            "bloat.me/",

            "bravo.ly/",

            "bsa.ly/",

            "budurl.com/",

            "buzurl.com/",

            "canurl.com/",

            "chilp.it/",

            "chzb.gr/",

            "cl.lk/",

            "cl.ly/",

            "clck.ru/",

            "cli.gs/",

            "cliccami.info/",

            "clickthru.ca/",

            "clop.in/",

            "conta.cc/",

           "cort.as/",

            "cot.ag/",

            "crisco.com/",

            "crks.me/",

            "ctvr.us/",

            "cur.ly/",

            "cutt.us/",

            "dai.ly/",

            "db.tt/",

            "decenturl.com/",

            "dfl8.me/",

            "dft.ba/",

            "digbig.com/",

            "digg.com/",

            "disq.us/",

            "dld.bz/",

            "dlvr.it/",

            "do.my/",

            "doiop.com/",

            "dopen.us/",

            "easyuri.com/",

            "easyurl.net/",

            "eepurl.com/",

            "eweri.com/",

            "fa.by/",

            "fav.me/",

            "fb.me/",

            "fbshare.me/",

            "ff.im/",

            "fff.to/",

            "filoops.info/",

            "fire.to/",

            "firsturl.de/",

            "firsturl.net/",

            "flic.kr/",

            "flq.us/",

            "fly2.ws/",

            "fon.gs/",

            "freak.to/",

            "fuseurl.com/",

            "fuzzy.to/",

            "fwd4.me/",

            "fwib.net/",

            "g.ro.lt/",

            "gizmo.do/",

            "gl.am/",

            "go.9nl.com/",

            "go.ign.com/",

            "go.usa.gov/",

            "goo.gl/",

            "goshrink.com/",

            "gurl.es/",

            "hex.io/",

            "hiderefer.com/",

            "hmm.ph/",

            "href.in/",

            "hsblinks.com/",

            "htxt.it/",

            "huff.to/",

            "hulu.com/",

            "hurl.me/",

            "hurl.ws/",

            "icanhaz.com/",

            "idek.net/",

            "ilix.in/",

            "is.gd/",

            "its.my/",

            "ity.im/",

            "ix.lt/",

            "j.mp/",

            "jijr.com/",

            "kl.am/",

            "klck.me/",

            "korta.nu/",

            "krunchd.com/",

            "l9k.net/",

            "lat.ms/",

            "lemde.fr/",

            "liip.to/",

            "liltext.com/",

            "linkbee.com/",

            "linkbun.ch/",

            "liurl.cn/",

            "ln-s.net/",

            "ln-s.ru/",

            "lnk.gd/",

            "lnk.ms/",

            "lnkd.in/",

            "lnkurl.com/",

            "lru.jp/",

            "lt.tl/",

            "lurl.no/",

            "macte.ch/",

            "mash.to/",

            "merky.de/",

            "migre.me/",

            "miniurl.com/",

            "minurl.fr/",

            "mke.me/",

            "moby.to/",

            "moourl.com/",

            "mrte.ch/",

            "myloc.me/",

            "myurl.in/",

            "n.pr/",

            "nbc.co/",

            "nblo.gs/",

            "nn.nf/",

            "not.my/",

            "notlong.com/",

            "nsfw.in/",

            "nutshellurl.com/",

            "nxy.in/",

            "nyti.ms/",

            "o-x.fr/",

            "oc1.us/",

            "om.ly/",

            "omf.gd/",

            "omoikane.net/",

            "on.cnn.com/",

            "on.mktw.net/",

            "onforb.es/",

            "orz.se/",

            "ow.ly/",

            "ping.fm/",

            "pli.gs/",

            "pnt.me/",

            "politi.co/",

            "post.ly/",

            "pp.gg/",

            "prettylinkpro.com/",

            "profile.to/",

            "ptiturl.com/",

            "pub.vitrue.com/",

            "q.gs/",

            "qlnk.net/",

            "qr.ae/",

            "qr.net/",

            "qte.me/",

            "qu.tc/",

            "qy.fi/",

            "r.im/",

            "rb6.me/",

            "read.bi/",

            "readthis.ca/",

            "reallytinyurl.com/",

            "redir.ec/",

            "redirects.ca/",

            "redirx.com/",

            "retwt.me/",

            "ri.ms/",

            "rickroll.it/",

            "riz.gd/",

            "rt.nu/",

            "ru.ly/",

            "rubyurl.com/",

            "rurl.org/",

            "rww.tw/",

            "s4c.in/",

            "s7y.us/",

            "safe.mn/",

            "sameurl.com/",

            "scrnch.me/",

            "sdut.us/",

            "shar.es/",

            "shink.de/",

            "shorl.com/",

            "short.ie/",

            "short.to/",

            "shortlinks.co.uk/",

            "shorturl.com/",

            "shout.to/",

            "show.my/",

            "shrinkify.com/",

            "shrinkr.com/",

            "shrt.fr/",

            "shrt.st/",

            "shrten.com/",

            "shrunkin.com/",

            "simurl.com/",

            "slate.me/",

            "smallr.com/",

            "smsh.me/",

            "smurl.name/",

            "sn.im/",

            "snipr.com/",

            "snipurl.com/",

            "snurl.com/",

            "sp2.ro/",

            "spedr.com/",

            "srnk.net/",

            "srs.li/",

            "starturl.com/",

            "su.pr/",

            "surl.co.uk/",

            "surl.hu/",

            "t.cn/",

            "t.co/",

            "t.lh.com/",

            "ta.gd/",

            "tbd.ly/",

            "tcrn.ch/",

            "tgr.me/",

            "tgr.ph/",

            "tighturl.com/",

            "tiniuri.com/",

            "tiny.cc/",

            "tiny.ly/",

            "tiny.pl/",

            "tinylink.in/",

            "tinyuri.ca/",

            "tinyurl.com/",

            "tk./",

            "tl.gd/",

            "tmi.me/",

            "tnij.org/",

            "tnw.to/",

            "tny.com/",

            "to./",

            "to.ly/",

            "togoto.us/",

            "totc.us/",

            "toysr.us/",

            "tpm.ly/",

            "tr.im/",

            "tra.kz/",

            "trunc.it/",

            "tweez.me/",

            "twhub.com/",

            "twirl.at/",

            "twitclicks.com/",

            "twitterurl.net/",

            "twitterurl.org/",

            "twitthis.com/",

            "twiturl.de/",

            "twurl.cc/",

            "twurl.nl/",

            "u.bb/",

            "u.mavrev.com/",

            "u.nu/",

            "u.to/",

            "u76.org/",

            "ub0.cc/",

            "ulu.lu/",

            "updating.me/",

            "ur1.ca/",

            "url.az/",

            "url.co.uk/",

            "url.ie/",

            "url360.me/",

            "url4.eu/",

            "urlborg.com/",

            "urlbrief.com/",

            "urlcover.com/",

            "urlcut.com/",

            "urlenco.de/",

            "urli.nl/",

            "urls.im/",

            "urlshorteningservicefortwitter.com/",

            "urlx.ie/",

            "urlzen.com/",

            "usat.ly/",

            "use.my/",

            "v.gd/",

            "vb.ly/",

            "vgn.am/",

            "viralurl.biz/",

            "viralurl.com/",

            "virl.ws/",

            "vl.am/",

            "vm.lc/",

            "vur.me/",

            "vurl.bz/",

            "vzturl.com/",

            "w55.de/",

            "wapo.st/",

            "wapurl.co.uk/",

            "wipi.es/",

            "wp.me/",

            "x.co/",

            "x.vu/",

            "xr.com/",

            "xrl.in/",

            "xrl.us/",

            "xurl.es/",

            "xurl.jp/",

            "y.ahoo.it/",

            "yatuc.com/",

            "ye.pe/",

            "yep.it/",

            "yfrog.com/",

            "yhoo.it/",

            "yiyd.com/",

            "yourls.org/",

            "youtu.be/",

            "yuarel.com/",

            "z0p.de/",

            "zi.ma/",

            "zi.mu/",

            "zipmyurl.com/",

            "zud.me/",

            "zurl.ws/",

            "zz.gd/",

            "zzang.kr/",

            "›.ws/",

            "✩.ws/",

            "✿.ws/",

            "❥.ws/",

            "➔.ws/",

            "➞.ws/",

            "➡.ws/",

            "➨.ws/",

            "➯.ws/",

            "➹.ws/",

            "➽.ws/",
           ]

    for shortener in shortener_list:
        if link.find(shortener) != -1:
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
        "at_result": 1,
        "dot_result": 0,
        "dash_result": -1,
        "http_result": 1,
    }

    if domain_find is not None:
        domain = domain_find.group(1)
        if domain.count("-") is 0:
            results.update(dash_result=1)

        dot_count = domain.count(".")

        # 1 dot = legit, 2 dots (default) = suspicious, > 2 dots = phishing
        if dot_count == 1:
            results.update(dot_result=1)
        else:
            if dot_count > 2:
                results.update(dot_result=-1)

        if domain.count("http") is not 0:
            results.update(http_result=-1)

        if domain.count("@") is not 0:
            results.update(at_result=-1)

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
        "public_identity": 0,
    }

    host = urlparse.urlparse(link)

    if host.hostname is None:
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

    if whois_info.org is not None and whois_info.name is not None:
        # This serves as a replacement for the "containing org name", as that information is no longer easily accessible.
        if whois_info.org.lower().find("mask") == -1 and whois_info.org.lower().find("redacted") == -1:
            results.update(public_identity=1)

    return results


# Several of the considered parameters are based on the HTML content of a phishing site
# NOTE: Does this count as clicking the link...?
def check_html(link: str) -> dict:
    log = logging.getLogger("simone_core")
    results = {
        "favicon": 1,
        "ext_res": 0,
        "ext_anchor": 0,
        "ext_script": 0,
        "status_change": -1,
        "iframe": 1,
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

    if icon is not None:
        icon_link = icon['href']
        icon_host = urlparse.urlparse(icon_link).hostname

        # if favicon is hosted on the same server
        if (icon_host is None or icon_link.find("data:") != -1) and icon_host != host:
            results.update(favicon=-1)

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

    # print(total_res)
    # print(total_script)
    # print(total_a)

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

    iframe = soup.find('iframe')
    if iframe is not None:
        results.update(iframe=-1)

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


# Check the number of redirects
def check_redirects(link: str) -> float:
    log = logging.getLogger('simone_core')
    parsed = urlparse.urlparse(link)
    if parsed.netloc is None:
        log.warning('Redirect check failed, invalid URL')
        return 0

    redirect_count = 0

    for i in range(0, 4):
        r = requests.head(link)
        if 300 < r.status_code < 400:
            loc = r.headers['location']
            plink = urlparse.urlparse(loc)

            if plink.netloc is '':
                new_link = parsed._replace(path=plink.path)
                link = urlparse.urlunparse(new_link)  # Just WTF

            else:
                link = loc

            redirect_count += 1

    if redirect_count <= 1:
        return 1
    else:
        return 0 if redirect_count < 4 else -1


# Google's old PageRank API is no longer a thing, sadly. Some of the constants have been altered to reflect the new
# scoring API used (3 is a neutral value)
def check_page_rank(link: str):

    endpoint = config.analysis.get("pagerankAPIendpoint")
    api_key = config.analysis.get("pagerankAPIkey")
    domain = urlparse.urlparse(link).netloc
    payload = {'domains[0]': {domain}}

    r = requests.get(endpoint, params=payload, headers={'API-OPR': api_key})
    # print(r.url)
    result = r.json()

    if result['status_code'] == 200:
        page_rank = result['response'][0]['page_rank_decimal']

        if isinstance(page_rank, str):
            return -1

        if page_rank < 3:
            return -1
        else:
            if page_rank < 6:
                return 0
            else:
                return 1


# PhishTank has a handy API that can be used to check reputation
# What am I doing with my life
def check_phishtank_reputation(link: str):

    endpoint = config.analysis.get("phishtankAPIendpoint")
    api_key = config.analysis.get("phishtankAPIkey")
    payload = {
        'url': link,
        'format': "xml",  # Only XML API seems to function at the moment...
        'app_key': api_key
    }

    r = requests.post(endpoint, params=payload)

    if r.status_code != 200:
        raise RuntimeError("PhishTank HTTP Request failed: code " + r.status_code)

    response_str = r.content.decode('UTF-8').strip()
    response_tree = xml.fromstring(response_str)

    in_db = response_tree.find('./results/url0/in_database').text

    if in_db is None:
        raise RuntimeError("PhishTank check failed, invalid data received from endpoint")

    if in_db == 'true':  # If included in the PhishTank database and verified to be phishing
        return -1
    else:
        return 1

