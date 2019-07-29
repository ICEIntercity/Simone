import config
from link import link
import requests


def lookup(url: str):
    if not link.validate_url(url):
        return None

    endpoint = config.analysis["virustotalAPIendpoint"]
    apikey = config.analysis["virustotalAPIkey"]

    payload = {
        'apikey': apikey,
        'resource': url,
        'allinfo': False,
        'scan': 0
    }

    r = requests.get(endpoint, payload)

    if r.status_code == 200:
        result = r.json()
        if result['response_code'] == 1:
            return result['permalink'], result['positives'], result['total']
        elif result['permalink'] is not None:
            return result['permalink'], 0, 0

    return None

