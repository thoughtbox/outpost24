# intro
An example command line tool for Outpost24's vulnerability scanner (Netsec, aka HIAB). 

# listagents.py
Python script that will list all registered agents and their status using the HIAB's API, with an option to send the data to Splunk via the HTTP Event Collector (HEC) interface (defaults to stdout).

```
$ ./listagents.py -h
usage: listagents.py [-h] [--limit LIMIT] [--url URL] [--api-key API_KEY] [--hec-host HEC_HOST] [--hec-port HEC_PORT] [--hec-token HEC_TOKEN]
                     [--hec-ssl HEC_SSL] [--socks SOCKS] [--http-proxy HTTP_PROXY] [--https-proxy HTTPS_PROXY] [--config-file CONFIG_FILE]
                     [--timeout TIMEOUT] [--sslwarnings SSLWARNINGS]

List all agents

optional arguments:
  -h, --help            show this help message and exit
  --limit LIMIT         Number of results to batch
  --url URL             URL to HIAB scheduler
  --api-key API_KEY     A valid API key
  --hec-host HEC_HOST   Your HEC host
  --hec-port HEC_PORT   Your HEC port (default: 443)
  --hec-token HEC_TOKEN
                        A valid HEC token
  --hec-ssl HEC_SSL     Use SSL (default: True)
  --socks SOCKS         SOCKS5 config (host:port), overrides any http?-proxy config
  --http-proxy HTTP_PROXY
                        http proxy (setting only this will use same proxy for https requests)
  --https-proxy HTTPS_PROXY
                        https proxy (if different proxy is used for https requests)
  --config-file CONFIG_FILE
                        Configuration file with key=value pairs
  --timeout TIMEOUT     Request timeout in seconds (default: 5)
  --sslwarnings SSLWARNINGS
                        Print SSL certificate warnings, or not because self-signed certificates
```

# hiabclirc
This should reside in ~/.hiabclirc and would nominally contain the API key and HIAB URL. 

# end note
I have no affilation with Outpost24 (https://outpost24.com). This software is provided "as is", with no guarantees, warranties, express or implied, etc., and so forth.

# license
BSD Simplified 2-clause license.