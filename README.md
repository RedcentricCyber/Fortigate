# FG-IR-18-384 (CVE-2018-13379) Exploitation Tool
*Exploit allowing for the recovery of cleartext credentials. This tool is provided for testing purposes only. Only run it against infrastructure for which you have recieved permission to test.*

Headnod to those who discovered the exploit, more information by the researcher can be found here: https://blog.orange.tw/2019/08/attacking-ssl-vpn-part-2-breaking-the-fortigate-ssl-vpn.html

This exploit was developed to pull the interesting credentials straight out of the binary, rather than require someone to run strings and review the output.

Google Dork: `inurl:remote/login?lang=`

This vulnerability affects the following versions:
```
FortiOS 5.6.3 to 5.6.7
FortiOS 6.0.0 to 6.0.4
ONLY if the SSL VPN service (web-mode or tunnel-mode) is enabled
```

Video of tool in action

[![Tool in action](https://img.youtube.com/vi/xxoFAH1pZ_I/0.jpg)](https://www.youtube.com/watch?v=xxoFAH1pZ_I)

## Notes:
This tool is now multithreaded it's been 14 months since this exploit was released to the world as single threaded and multiple tools now exist to look up this vulnerablity enmass. Recent media also reports mass credentials from this vulnerability being sold on the "Darknet".

## Usage: 

Install Requirements: `pip3 install -r requirements.txt`, then use as below.
```
python3 fortigate.py -h
  ___ ___  ___ _____ ___ ___   _ _____ ___
 | __/ _ \| _ \_   _|_ _/ __| /_\_   _| __|
 | _| (_) |   / | |  | | (_ |/ _ \| | | _|
 |_| \___/|_|_\ |_| |___\___/_/ \_\_| |___|

Extract Useful info (credentials!) from SSL VPN Directory Traversal Vulnerability (FG-IR-18-384)
Tool originally developed by @x41x41x41 and @DavidStubley.

usage: fortigate.py [-h] [-i INPUT] [-o OUTPUT] [-t THREADS] [-c CREDSCAN]

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Line seperated list of targets i.e google.com or 127.0.0.1
  -o OUTPUT, --output OUTPUT
                        File to output discovered credentials too
  -t THREADS, --threads THREADS
                        threads
  -c CREDSCAN, --credscan CREDSCAN
                        Execute Credential Pull y/n With great power comes great
```
Note to pull credentials `-c y` must be used.

## Using with a proxy

It is often helpful to run this tool through a proxy. Burp being the most
obvious example. You can configure burp to use an upstream socks proxy which you
can create with the `-D` flag in SSH. 

For example, to make requests come from a jump box example.com, create the socks
proxy 

```bash
ssh -D 8081 user@example.com
```

Configure burp (Project or user settings) to use that proxy. Host: 127.0.0.1
port 8081.

This tool (or rather the requests library it uses) will honour the *_proxy
environment variables. Set these to burp:

```bash
export http_proxy="http://127.0.0.1:8080" https_proxy="http://127.0.0.1:8080"
```


## License / Terms of Use
This software should only be used for authorised testing activity and not for malicious use.

By downloading and/or running this software you are accepting the terms of use and the licensing agreement.
