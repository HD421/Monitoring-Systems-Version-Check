# -*- coding: utf-8 -*-

import argparse
import urllib2
import ssl
from BeautifulSoup import BeautifulSoup


parser = argparse.ArgumentParser(description='Command-line tool for Nagios fingerprint')

parser.add_argument("-H", "--host", help="Host to fingerprint")
parser.add_argument("-p", "--port", help="Port on which Nagios is located", type=int)

args = parser.parse_args()
link = '{}:{}/nagiosxi/login.php'.format(args.host, args.port)

def get_html(url):
    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'https://{}'.format(url)
        print "URL IS ", url
    ctx = ssl.create_default_context()  # avoid invalid ssl check
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    response = urllib2.urlopen(url, timeout=5, context=ctx)
    return response.read()

def parse(html):
    soup = BeautifulSoup(html)
    get_version = soup.find('input', {"name": "version"})['value']
    get_productName = soup.find('input', {"name": "product"})['value']
    get_buildV = soup.find('input', {"name": "build"})['value']
    print("[X] Nagios version is :", get_version)
    print("[X] Build is : ", get_buildV)
    print("[X] Product name is :", get_productName)

try:
    parse(get_html(link))
except urllib2.URLError:
    print("SSL is not avaliable, trying http://" + link)
    link = 'http://{}'.format(link)
    try:
        parse(get_html(link))
    except TypeError:
        print(
            "Something went wrong, unable to fingerprint this server. Maybe this Nagios is placed on specific port?"
        )
except TypeError:
    print(
        "Something went wrong, i didn't found a valid redirect or info about versions"
    )  # TODO need some refactoring
