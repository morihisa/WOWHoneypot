#!/usr/bin/env python3
# -*- coding:utf-8 -*-
# author @morihi_soc
# (c) 2018 @morihi_soc
#
# This script require requests library.
# pip install requests
#
import os
import re
import requests
import urllib.request
import hashlib
import time
import json

VIRUSTOTAL_APIKEY = '-YOUR API KEY HERE-'
hunting_log_file = "./log/hunting.log"
last_seen_id_file = "./chase_id.txt"

def virustotal_check(url):
    if len(url) == 0 and not url.startswith("http"):
        return None

    headers = {
        "Accept-Encoding": "gzip, deflate",
        "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Trident/7.0; rv:11.0) like Gecko"
    }

    try:
        memory_cache = urllib.request.urlopen(url).read()
        filename = url[url.rindex("/")+1:]
    except Exception as e:
        print("[ERROR] {0} - {1}".format(url, e))
        return None
    hash = hashlib.sha256(memory_cache).hexdigest()
    if len(filename) == 0:
        filename = hash
    params = {'apikey': VIRUSTOTAL_APIKEY, 'resource': hash}

    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
    json_response = response.json()

    print("scan result response_code:{0}, scan hash: {1}, url:{2}".format(json_response['response_code'], hash, url))
    time.sleep(15)

    if json_response['response_code'] == 0:
        print("submit: {0}".format(url))
        params = {'apikey': VIRUSTOTAL_APIKEY}
        files = {'file': (filename, memory_cache)}
        response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
        json_response = response.json()
        print("response_code:{0}, permalink: {1}".format(json_response['response_code'], json_response['permalink']))
        time.sleep(15)

last_seen_id = 0
if os.path.exists(last_seen_id_file):
    with open(last_seen_id_file, "r") as f:
        n = f.readline()
        if len(n) > 0:
            last_seen_id = int(n)
print("Last seen id:{0}".format(last_seen_id))
lineno = 1
known_url = set("")
with open(hunting_log_file, "r") as f:
    for line in f:
        lineno = lineno + 1
        url = re.findall("https?://[\w/:\.\-]+", line)[0]
        if (lineno <= last_seen_id and len(url) > 0):
            known_url.add(url)
            continue
        if not url in known_url:
            virustotal_check(url)
            known_url.add(url)

with open(last_seen_id_file, "w") as f:
    f.write(str(lineno))
