# -*- coding: utf-8 -*-

import argparse
import json
import os
import jsonpath_rw as jp
import urllib2
import ssl
import pprint
from BeautifulSoup import BeautifulSoup

__author__ = 'H_D'
__version__ = '0.1'

VULNERS_LINK = {'bulletin':'https://vulners.com/api/v3/search/id/'}

ASCII = r"""
=================================================================
 __    __  _______         ______                                
/  |  /  |/       \       /      \                               
$$ |  $$ |$$$$$$$  |     /$$$$$$  |  _______   ______   _______  
$$ |__$$ |$$ |  $$ |     $$ \__$$/  /       | /      \ /       \ 
$$    $$ |$$ |  $$ |     $$      \ /$$$$$$$/  $$$$$$  |$$$$$$$  |
$$$$$$$$ |$$ |  $$ |      $$$$$$  |$$ |       /    $$ |$$ |  $$ |
$$ |  $$ |$$ |__$$ |     /  \__$$ |$$ \_____ /$$$$$$$ |$$ |  $$ |
$$ |  $$ |$$    $$/______$$    $$/ $$       |$$    $$ |$$ |  $$ |
$$/   $$/ $$$$$$$//      |$$$$$$/   $$$$$$$/  $$$$$$$/ $$/   $$/ 
                  $$$$$$/                                        
    NagiosXI version detector and Vulnerability scanner
                    based on Vulners API                                                                 
=================================================================                                                                 
"""

parser = argparse.ArgumentParser(description='Command-line tool for Nagios fingerprint')

parser.add_argument("-H", "--host", help="Host to fingerprint")
parser.add_argument("-p", "--port", help="Port on which Nagios is located", type=int)

args = parser.parse_args()

def get_html(url):
    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'https://{}'.format(url)
        print "URL IS ", url
    ctx = ssl.create_default_context()  # avoid invalid ssl check
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    response = urllib2.urlopen(url, timeout=5, context=ctx)
    return response.read()

def version_check(html):
    soup = BeautifulSoup(html)
    get_version = soup.find('input', {"name": "version"})['value']
    get_productName = soup.find('input', {"name": "product"})['value']
    get_buildV = soup.find('input', {"name": "build"})['value']

    print("[X] Nagios version is :", get_version)
    print("[X] Build is : ", get_buildV)
    print("[X] Product name is :", get_productName)

    payload = {'query':'{} version:<={}'.format(get_productName,get_version),
                'size':5,
                'sort':'cvss.score',
                'references':'true',
                'fields': ['id','cve']
               }
    print "payload", payload
    url = 'https://vulners.com/api/v3/search/lucene/'
    response = sendVulnRequest(url, payload)
    resultCode = response.get("result")
    if resultCode == "OK":
        # print "VULNS FOUND", vulnsFound
        cvelist = []
        references = response.get('data').get('references')
        for item in references:
            for reference in references[item]:
                for refID in references[item][reference]:
                    cvelist = cvelist + refID['cvelist']
        if len(cvelist) == 0:
            print("   - No vulnerabilities found.")
            return
        for cve in cvelist:
            print(' - ' + cve);

def sendVulnRequest(url, payload):
    req = urllib2.Request(url)
    req.add_header('Content-Type', 'application/json')
    req.add_header('User-Agent', 'hd-scan-v0.1')
    response = urllib2.urlopen(req, json.dumps(payload).encode('utf-8'))
    responseData = response.read()
    if isinstance(responseData, bytes):
        responseData = responseData.decode('utf8')
    responseData = json.loads(responseData)
    return responseData

def main():
    
    link = '{}:{}/nagiosxi/login.php'.format(args.host, args.port)

    try:
        version_check(get_html(link))
    except urllib2.URLError:
        print("SSL is not avaliable, trying http://" + link)
        link = 'http://{}'.format(link)
        try:
            version_check(get_html(link))
        except TypeError:
            print(
                "Something went wrong, unable to fingerprint this server. Maybe this Nagios is placed on specific port?"
            )
    except TypeError:
        print(
            "Something went wrong, i didn't found a valid redirect or info about versions"
        )  # TODO need some refactoring


if __name__ == '__main__':
    print('\n'.join(ASCII.splitlines()))
    main()