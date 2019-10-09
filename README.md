# FG-IR-18-384 (CVE-2018-13379) Exploitation Tool
*Exploit allowing for the recovery of cleartext credentials. This tool is provided for testing purposes only. Only run it against infrastructure for which you have recieved permission to test.*

This exploit was developed to pull the interesting credentials straight out of the binary. Note that whilst this tool was originally multi-threaded/targeted we felt it was a little overpowered, we may release that version at a later date.

Headnod to those who discovered the exploit, more information by the researcher can be found here: https://blog.orange.tw/2019/08/attacking-ssl-vpn-part-2-breaking-the-fortigate-ssl-vpn.html

Google Dork: `inurl:remote/login?lang=`

This vulnerability affects the following versions:
```
FortiOS 5.6.3 to 5.6.7
FortiOS 6.0.0 to 6.0.4
ONLY if the SSL VPN service (web-mode or tunnel-mode) is enabled
```

![Tool in action](https://i.imgur.com/TnG84n2.png)

Usage: 

Install Requirements: `pip3 install -r requirements.txt`, then use as below.
```
python3 fortigate.py -h
  ___ ___  ___ _____ ___ ___   _ _____ ___
 | __/ _ \| _ \_   _|_ _/ __| /_\_   _| __|
 | _| (_) |   / | |  | | (_ |/ _ \| | | _|
 |_| \___/|_|_\ |_| |___\___/_/ \_\_| |___|

Extract Useful info (credentials!) from SSL VPN Directory Traversal Vulnerability (FG-IR-18-384)
Tool developed by @x41x41x41 and @DavidStubley

usage: fortigate.py [-h] [-i INPUT] [-o OUTPUT]

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Target URL or Domain
  -o OUTPUT, --output OUTPUT
                        File to output discovered credentials too
```

