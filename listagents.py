#!/usr/bin/env python3
# (c) 2022 tor houghton
import socket
import json
import urllib3
import ssl
import sys
import os
import time
import requests
import argparse
import re
from urllib3.contrib.socks import SOCKSProxyManager
from string import Template
from splunk_http_event_collector import http_event_collector 

## hardcoded according to script function (in case you have more scripts)
event_source = "http:hiab:listagents"
event_sourcetype = "hiab:api:json"
user_agent = "hiab-listagents-script"

def submit_url(url,postdata,proxies,timeout):
    with requests.Session() as s:
        r = requests.Request(method='POST', url=url, data=postdata, 
                             headers={ "User-Agent": user_agent })
        prep = r.prepare()
        prep.url = url
        return s.send(prep, verify=False, timeout=timeout, proxies=proxies)

def coalesce(values, default):
    return next((item for item in values if item is not None), default)

def validate_format(string, regex, errormsg):
    p = re.compile(regex)
    if not p.match(string):
            print("FATAL: {}".format(errormsg))
            exit(1)

parser = argparse.ArgumentParser(description='List all agents', prog='listagents.py')
parser.add_argument('--limit', type=str, dest='limit', action='store', help="Number of results to batch")
parser.add_argument('--url', type=str, dest='url', action='store', help="URL to HIAB scheduler")
parser.add_argument('--api-key', type=str, dest='api_key', action='store', help="A valid API key")
parser.add_argument('--hec-host', type=str, dest='hec_host', action='store', help='Your HEC host')
parser.add_argument('--hec-port', type=int, dest='hec_port', action='store', help='Your HEC port (default: 443)')
parser.add_argument('--hec-token', type=str, dest='hec_token', action='store', help='A valid HEC token')
parser.add_argument('--hec-ssl', type=bool, dest='hec_ssl', action='store', help='Use SSL (default: True)')
parser.add_argument('--socks', type=str, dest='socks', action='store', help="SOCKS5 config (host:port), overrides any http?-proxy config")
parser.add_argument('--http-proxy', type=str, dest='http_proxy', action='store', help="http proxy (setting only this will use same proxy for https requests)")
parser.add_argument('--https-proxy', type=str, dest='https_proxy', action='store', help="https proxy (if different proxy is used for https requests)")
parser.add_argument('--config-file', type=str, dest='config_file', action='store', help="Configuration file with key=value pairs")
parser.add_argument('--timeout', type=int, dest='timeout', action='store',help="Request timeout in seconds (default: 5)")
parser.add_argument('--sslwarnings', type=str, dest='sslwarnings', action='store',help="Print SSL certificate warnings, or not because self-signed certificates")
opts = parser.parse_args()

if not opts.config_file:
    config_file=os.environ['HOME']+"/.hiabclirc"
else:
    config_file = opts.config_file
    if (os.stat(config_file).st_mode & 0o077) != 0:
        print("Error: config file has insecure file permissions!")
        exit(1)

config = {}

try:
    with open(config_file) as f:
        for line in f:
            line = line.strip()
            (key,val) = line.split('=')
            config[key] = val
except:
    pass

# values that can be configured in the .hiabclirc file
timeout = int(coalesce([opts.timeout, config.get("timeout")], 5))
limit = int(coalesce([opts.limit, config.get("limit")], 4000))
hec_host = coalesce([opts.hec_host, config.get("hechost")], False)
hec_port = coalesce([opts.hec_host, config.get("hecport")], 443)
hec_ssl = coalesce([opts.hec_host], True)
socksConf = coalesce([opts.socks, config.get("socks")], False)
httpProxyConf = coalesce([opts.http_proxy, config.get("http_proxy")], False)
httpsProxyConf = coalesce([opts.https_proxy, config.get("https_proxy")], False)
sslWarnings = coalesce([opts.sslwarnings, config.get("sslwarnings")], False)

# self-signed certs are the default, amirite
if sslWarnings == False:
    urllib3.disable_warnings()

# define and validate hec token
hec_token = coalesce([opts.hec_token, config.get("hectoken")], "")
validate_format(hec_token, '[A-F0-9]{8}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{4}-[A-F0-9]{12}', "invalid HEC token format")

#Define and validate api_key
api_key = coalesce([opts.api_key, config.get("apikey")], "")
validate_format(api_key, '[A-F0-9]{64}', "invalid API key format")

#Define and validate url
url =  coalesce([opts.url, config.get("url")], "")
validate_format(url, '^https?://\S+[:\d+]?/opi/XMLAPI', "no valid HIAB scheduler XML API in "+url )

proxies = {}

if socksConf:
    try:
        (shost,sport) = socksConf.split(':')
    except:
        print("FATAL: SOCKS configuration seems wrong "+socksConf)
        exit(1)

    s = Template('$proto://$host:$port/')
    socksproxy = s.substitute(proto='http',host=shost,port=sport)
    proxies = { 'http': socksproxy,
                'https': socksproxy }  
else:
    if httpProxyConf:
        proxies = { 'http': http_proxy, 
                    'https': http_proxy }
    if httpsProxyConf:
        proxies.update = { 'https': https_proxy }

def get_targetdata(running_total,limit):
    payload = { 'ACTION': 'TARGETDATA', 'JSON': '1','offset':'0','GROUP': '-1',
                'filter[0][field]':'SCANNERNAME','filter[0][data][type]':'string',
                'filter[0][data][comparison]':'all','filter[0][data][value]':'Local',
                'filter[1][field]':'AGENTID','filter[1][data][type]':'string',
                'filter[1][data][comparison]':'any','filter[1][data][value]':'-',
                'start': running_total,'limit': limit, 'APPTOKEN': api_key }

    response = submit_url(url, payload, proxies, timeout)

    if response.status_code != 200:
        print("Error: Server returned error code " + response.status_code)
        exit(1)

    jres = json.loads(response.text)

    if len(jres["data"]) > 0:
        if "errorMessage" in jres["data"]:
            print("Error: ",jres["data"]["errorMessage"])
            exit(1)
    else:
        if jres["success"]:
            print ("No agents in target database")
            exit(0)
        else:
            print ("Error: could not parse TARGETDATA response")
            exit(1)

    totalcount = jres["totalcount"] # the total reported number of targets with agents
    thiscount = len(jres["data"]) # the number of results of current request

    return(jres["data"],thiscount,totalcount)

if hec_host:
    hec = http_event_collector(token = hec_token, 
                               http_event_server = hec_host, 
                               http_event_port = hec_port, 
                               http_event_server_ssl = hec_ssl)

    if not hec.check_connectivity():
        print("Error: HEC ",hec_host,":",hec_port," is unreachable")
        sys.exit(1)

# we need to list the agents in batches until there are no more

running_total = 0 # we start here
totalcount = 1 # to get the ball rolling

while running_total < totalcount:
    (data,resultcount,totalcount) = get_targetdata(running_total,limit)
    running_total += resultcount

    if hec_host:
        hec_payload = {}
        hec_payload.update({"source": event_source})
        hec_payload.update({"sourcetype": event_sourcetype})
        for row in data:
            print(row)
            hec_payload.update({"event": row}) 
            hec.batchEvent(hec_payload)
        hec.flushBatch()
    else:
        for row in data:
            print(row)
