'''

Created: March 12, 2014
Updated: May 2, 2014

This script contains the most comprehensive list of VirusTotal transforms.
Basic descriptions of each transform are at the bottom of this file.
Please check the documentation on GitHub for usage, inputs, and outputs.

Copyright (c) 2014, Lookingglass Cyber Solutions, Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

'''
import os, sys
import requests
from json import loads

from MaltegoClass import MaltegoTransform, EntityTypes

#declare required api params
api_base = "https://www.virustotal.com/vtapi/v2/"
api_key = "YOUR_API_KEY_HERE"

##############################################################################################

def iocToHash(me, string_in):
    try:
        response = requests.get(api_base + 'file/search?apikey=' + api_key + '&query=behavior:\"' + string_in + '\"')
        response_json = response.json()
        resp_code = int(response_json['response_code'])

        if resp_code == 1: 
            if 'hashes' in response_json:
                for hash in response_json['hashes']:
                    me.addEntity(EntityTypes.hash, '%s' % hash)
         
    except:
        me.addEntity(EntityTypes.textMessage, 'iocToHash Unknown Error:%sType: %s%sValue:%s' % 
                     (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return me

##############################################################################################

def ipToCommunicatingHash(me, string_in):
    try:
        response = requests.get(api_base + 'file/search?apikey=' + api_key + '&query=behavior:' + string_in)
        response_json = response.json()
        resp_code = int(response_json['response_code'])

        if resp_code == 1: 
            if 'hashes' in response_json:
                for hash in response_json['hashes']:
                    me.addEntity(EntityTypes.hash, '%s' % hash)
         
    except:
        me.addEntity(EntityTypes.textMessage, 'ipToCommunicatingHash Unknown Error:%sType: %s%sValue:%s' % 
                     (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return me

##############################################################################################

def domainToCommunicatingHash(me, string_in):
    try:
        response = requests.get(api_base + 'file/search?apikey=' + api_key + '&query=behavior:' + string_in)
        response_json = response.json()
        resp_code = int(response_json['response_code'])

        if resp_code == 1: 
            if 'hashes' in response_json:
                for hash in response_json['hashes']:
                    me.addEntity(EntityTypes.hash, '%s' % hash)
         
    except:
        me.addEntity(EntityTypes.textMessage, 'domainToCommunicatingHash Unknown Error:%sType: %s%sValue:%s' % 
                     (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return me

##############################################################################################
    
def hashToIP(me, string_in):
    try:
        response = requests.get(api_base + 'file/behaviour?apikey=' + api_key + '&hash=' + string_in)
        response_json = response.json()

        if not 'response_code' in response_json:
            hostlist = response_json['network']['hosts']
            if len(hostlist) > 0:   
                for host in hostlist:
                    if not (str(host).startswith('10.') | str(host).startswith('192.168.') | str(host).startswith('0.0.0.') | str(host).startswith('239.255.255.250') | str(host).startswith('8.8.8.8') | str(host).startswith('255.255.255.255') | str(host).startswith('224.0.0.22')):
                        me.addEntity(EntityTypes.IPv4, '%s' % host)
         
    except:
        me.addEntity(EntityTypes.textMessage, 'hashToIP Unknown Error:%sType: %s%sValue:%s' % 
                     (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return me

##############################################################################################

def hashToDomain(me, string_in):
    try:
        response = requests.get(api_base + 'file/behaviour?apikey=' + api_key + '&hash=' + string_in)
        response_json = response.json()

        if not 'response_code' in response_json:
            for item in response_json['network']['http']:
                me.addEntity(EntityTypes.Domain, '%s' % item['host'])
         
    except:
        me.addEntity(EntityTypes.textMessage, 'hashToDomain Unknown Error:%sType: %s%sValue:%s' % 
                     (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return me

##############################################################################################

def hashToURL(me, string_in):
    try:
        response = requests.get(api_base + 'file/behaviour?apikey=' + api_key + '&hash=' + string_in)
        response_json = response.json()

        if not 'response_code' in response_json:
            for item in response_json['network']['http']:
                me.addEntity(EntityTypes.Domain, '%s' % item['uri'])
         
    except:
        me.addEntity(EntityTypes.textMessage, 'hashToURL Unknown Error:%sType: %s%sValue:%s' % 
                     (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return me
    
##############################################################################################

def domainToDownloadedHash(me, string_in):
    try:
        response = requests.get(api_base + 'domain/report?apikey=' + api_key + '&domain=' + string_in)
        response_json = response.json()
        resp_code = int(response_json['response_code'])

        if resp_code == 1: 
            if 'detected_downloaded_samples' in response_json:
                for item in response_json['detected_downloaded_samples']:
                    me.addEntity(EntityTypes.hash, '%s' % item['sha256'])
         
    except:
        me.addEntity(EntityTypes.textMessage, 'domainToDownloadedHash Unknown Error:%sType: %s%sValue:%s' % 
                     (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return me

##############################################################################################

def ipToDownloadedHash(me, string_in):
    try:
        response = requests.get(api_base + 'ip-address/report?apikey=' + api_key + '&ip=' + string_in)
        response_json = response.json()
        resp_code = int(response_json['response_code'])

        if resp_code == 1: 
            if 'detected_downloaded_samples' in response_json:
                for item in response_json['detected_downloaded_samples']:
                    me.addEntity(EntityTypes.hash, '%s' % item['sha256'])
         
    except:
        me.addEntity(EntityTypes.textMessage, 'ipToDownloadedHash Unknown Error:%sType: %s%sValue:%s' % 
                     (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return me

##############################################################################################

def domainToIP(me, string_in):
    try:
        response = requests.get(api_base + 'domain/report?apikey=' + api_key + '&domain=' + string_in)
        response_json = response.json()
        resp_code = int(response_json['response_code'])

        if resp_code == 1: 
            if 'resolutions' in response_json:
                for resolutions in response_json['resolutions']:
                    me.addEntity(EntityTypes.IPv4, '%s' % resolutions['ip_address'])
         
    except:
        me.addEntity(EntityTypes.textMessage, 'domainToIP Unknown Error:%sType: %s%sValue:%s' % 
                     (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return me

##############################################################################################

def ipToDomain(me, string_in):
    try:
        response = requests.get(api_base + 'ip-address/report?apikey=' + api_key + '&ip=' + string_in)
        response_json = response.json()
        resp_code = int(response_json['response_code'])

        if resp_code == 1: 
            if 'resolutions' in response_json:
                for resolutions in response_json['resolutions']:
                    me.addEntity(EntityTypes.Domain, '%s' % resolutions['hostname'])
         
    except:
        me.addEntity(EntityTypes.textMessage, 'domainToIP Unknown Error:%sType: %s%sValue:%s' % 
                     (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return me

##############################################################################################

def hashToThreat(me, string_in):
    try:
        response = requests.get(api_base + 'file/report?apikey=' + api_key + '&resource=' + string_in)
        response_json = response.json()
        resp_code = int(response_json['response_code'])

        if resp_code == 1:
            if 'Microsoft' in response_json['scans']:
                if response_json['scans']['Microsoft']['detected']:
                    me.addEntity(EntityTypes.threat, '%s' % response_json['scans']['Microsoft']['result'])
                else:
                    if 'TrendMicro' in response_json['scans']:
                        if response_json['scans']['TrendMicro']['detected']:
                            me.addEntity(EntityTypes.threat, '%s' % response_json['scans']['TrendMicro']['result'])
                        else:
                            if 'Kaspersky' in response_json['scans']:
                                if response_json['scans']['Kaspersky']['detected']:
                                    me.addEntity(EntityTypes.threat, '%s' % response_json['scans']['Kaspersky']['result'])
                                else:
                                    if 'Sophos' in response_json['scans']:
                                        if response_json['scans']['Sophos']['detected']:
                                            me.addEntity(EntityTypes.threat, '%s' % response_json['scans']['Sophos']['result'])     
         
    except:
        me.addEntity(EntityTypes.textMessage, 'hashToThreat Unknown Error:%sType: %s%sValue:%s' % 
                     (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return me

##############################################################################################

def threatToHash(me, string_in):
    try:
        response = requests.get(api_base + 'file/search?apikey=' + api_key + '&query=engines:\"' + string_in + '\"')
        response_json = response.json()
        resp_code = int(response_json['response_code'])

        if resp_code == 1: 
            if 'hashes' in response_json:
                for hash in response_json['hashes']:
                    me.addEntity(EntityTypes.hash, '%s' % hash)
         
    except:
        me.addEntity(EntityTypes.textMessage, 'threatToHash Unknown Error:%sType: %s%sValue:%s' % 
                     (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return me

##############################################################################################

def hashToRegKey(me, string_in):
    try:
        response = requests.get(api_base + 'file/behaviour?apikey=' + api_key + '&hash=' + string_in)
        response_json = response.json()

        if not 'response_code' in response_json:
            for regkey in response_json['behavior']['summary']['keys']:
                me.addEntity(EntityTypes.ioc, '%s' % regkey)
         
    except:
        me.addEntity(EntityTypes.textMessage, 'hashToRegKey Unknown Error:%sType: %s%sValue:%s' % 
                     (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return me
    
##############################################################################################

def hashToBehavioralFileName(me, string_in):
    try:
        response = requests.get(api_base + 'file/behaviour?apikey=' + api_key + '&hash=' + string_in)
        response_json = response.json()

        if not 'response_code' in response_json:
            for file in response_json['behavior']['summary']['files']:
                me.addEntity(EntityTypes.ioc, '%s' % file)
         
    except:
        me.addEntity(EntityTypes.textMessage, 'hashToBehavioralFileName Unknown Error:%sType: %s%sValue:%s' % 
                     (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return me
    
##############################################################################################

def hashToMutex(me, string_in):
    try:
        response = requests.get(api_base + 'file/behaviour?apikey=' + api_key + '&hash=' + string_in)
        response_json = response.json()

        if not 'response_code' in response_json:
            for mutex in response_json['behavior']['summary']['mutexes']:
                me.addEntity(EntityTypes.ioc, '%s' % mutex)
         
    except:
        me.addEntity(EntityTypes.textMessage, 'hashToMutex Unknown Error:%sType: %s%sValue:%s' % 
                     (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return me
    
##############################################################################################

def hashToCommandRun(me, string_in):
    try:
        response = requests.get(api_base + 'file/behaviour?apikey=' + api_key + '&hash=' + string_in)
        response_json = response.json()

        if not 'response_code' in response_json:
            for call in response_json['behavior']['processes'][0]['calls']:
                if call['api'] == 'CreateProcessInternalW':
                    for callname in call['arguments']:
                        if callname['name'] == 'lpCommandLine':
                            if callname['value'] != "(null)":
                                me.addEntity(EntityTypes.ioc, '%s' % callname['value'])
         
    except:
        me.addEntity(EntityTypes.textMessage, 'hashToCommandRun Unknown Error:%sType: %s%sValue:%s' % 
                     (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return me
    
##############################################################################################

def hashToDetectionRatio(me, string_in):
    try:
        response = requests.get(api_base + 'file/report?apikey=' + api_key + '&resource=' + string_in)
        response_json = response.json()
        resp_code = int(response_json['response_code'])

        if resp_code == 1:
            ratio = 'Detection Ratio: ' + str(response_json['positives']) + '/' + str(response_json['total'])
            me.addEntity(EntityTypes.textMessage, '%s' % ratio)
         
    except:
        me.addEntity(EntityTypes.textMessage, 'hashToDetectionRatio Unknown Error:%sType: %s%sValue:%s' % 
                     (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return me
    
##############################################################################################

def hashToScanDate(me, string_in):
    try:
        response = requests.get(api_base + 'file/report?apikey=' + api_key + '&resource=' + string_in)
        response_json = response.json()
        resp_code = int(response_json['response_code'])

        if resp_code == 1:
            me.addEntity(EntityTypes.textMessage, '%s' % 'Scan Date: ' + str(response_json['scan_date']))
         
    except:
        me.addEntity(EntityTypes.textMessage, 'hashToScanDate Unknown Error:%sType: %s%sValue:%s' % 
                     (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return me
    
##############################################################################################

def hashToRescan(me, string_in):
    try:
        response = requests.post(api_base + 'file/report?apikey=' + api_key + '&resource=' + string_in)
        response_json = response.json()
        resp_code = int(response_json['response_code'])

        if resp_code == 1:
            me.addEntity(EntityTypes.textMessage, '%s' % 'Rescan successfully in queue, \nrun hashToDetectionRatio or hashToScanDate again soon.')
         
    except:
        me.addEntity(EntityTypes.textMessage, 'hashToRescan Unknown Error:%sType: %s%sValue:%s' % 
                     (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return me
    
##############################################################################################

def hashToPositiveAVList(me, string_in):
    try:
        response = requests.get(api_base + 'file/report?apikey=' + api_key + '&resource=' + string_in)
        response_json = response.json()
        resp_code = int(response_json['response_code'])

        if resp_code == 1:
            for av in response_json['scans']:
                if response_json['scans'][av]['detected']:
                    me.addEntity(EntityTypes.avcompany, '%s' % av)
         
    except:
        me.addEntity(EntityTypes.textMessage, 'hashToPositiveAVList Unknown Error:%sType: %s%sValue:%s' % 
                     (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return me
    
##############################################################################################

def partialURLtoDownloadedHash(me, string_in):
    try:
        response = requests.get(api_base + 'file/search?apikey=' + api_key + '&query=itw:\"' + string_in + '\"')
        response_json = response.json()
        resp_code = int(response_json['response_code'])

        if resp_code == 1: 
            if 'hashes' in response_json:
                for hash in response_json['hashes']:
                    me.addEntity(EntityTypes.hash, '%s' % hash)
         
    except:
        me.addEntity(EntityTypes.textMessage, 'partialURLtoDownloadedHash Unknown Error:%sType: %s%sValue:%s' % 
                     (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return me

##############################################################################################

def peSectionMD5toHash(me, string_in):
    try:
        response = requests.get(api_base + 'file/search?apikey=' + api_key + '&query=sectionmd5:\"' + string_in + '\"')
        response_json = response.json()
        resp_code = int(response_json['response_code'])

        if resp_code == 1: 
            if 'hashes' in response_json:
                for hash in response_json['hashes']:
                    me.addEntity(EntityTypes.hash, '%s' % hash)
         
    except:
        me.addEntity(EntityTypes.textMessage, 'peSectionMD5toHash Unknown Error:%sType: %s%sValue:%s' % 
                     (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return me

##############################################################################################

def importHashToHash(me, string_in):
    try:
        response = requests.get(api_base + 'file/search?apikey=' + api_key + '&query=imphash:\"' + string_in + '\"')
        response_json = response.json()
        resp_code = int(response_json['response_code'])

        if resp_code == 1: 
            if 'hashes' in response_json:
                for hash in response_json['hashes']:
                    me.addEntity(EntityTypes.hash, '%s' % hash)
         
    except:
        me.addEntity(EntityTypes.textMessage, 'importHashToHash Unknown Error:%sType: %s%sValue:%s' % 
                     (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return me

##############################################################################################

def exploitToHash(me, string_in):
    try:
        response = requests.get(api_base + 'file/search?apikey=' + api_key + '&query=tag:exploit%20tag:\"' + string_in + '\"')
        response_json = response.json()
        resp_code = int(response_json['response_code'])

        if resp_code == 1: 
            if 'hashes' in response_json:
                for hash in response_json['hashes']:
                    me.addEntity(EntityTypes.hash, '%s' % hash)
         
    except:
        me.addEntity(EntityTypes.textMessage, 'exploitToHash Unknown Error:%sType: %s%sValue:%s' % 
                     (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return me

##############################################################################################

def urlToDetectionRatio(me, string_in):
    try:
        response = requests.get(api_base + 'url/report?apikey=' + api_key + '&resource=' + string_in)
        response_json = response.json()
        resp_code = int(response_json['response_code'])

        if resp_code == 1:
            ratio = 'Detection Ratio: ' + str(response_json['positives']) + '/' + str(response_json['total'])
            me.addEntity(EntityTypes.textMessage, '%s' % ratio)
         
    except:
        me.addEntity(EntityTypes.textMessage, 'urlToDetectionRatio Unknown Error:%sType: %s%sValue:%s' % 
                     (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return me
    
##############################################################################################

def urlToScan(me, string_in):
    try:
        response = requests.post(api_base + 'url/scan?apikey=' + api_key + '&url=' + string_in)
        response_json = response.json()
        resp_code = int(response_json['response_code'])

        if resp_code == 1:
            me.addEntity(EntityTypes.textMessage, '%s' % 'Scan request successfully queued,\n run urlToDetectionRatio later')
         
    except:
        me.addEntity(EntityTypes.textMessage, 'urlToDetectionRatio Unknown Error:%sType: %s%sValue:%s' % 
                     (os.linesep, sys.exc_info()[0], os.linesep, sys.exc_info()[1]))
    return me
    
##############################################################################################
    
    
functions = {
             'iocToHash': iocToHash,                                    #all hashes containing IOC
             'hashToIP': hashToIP,                                      #all IPs hash communicates with
             'hashToDomain': hashToDomain,                              #all domains hash communicates with
             'hashToURL': hashToURL,                                    #all URLs hash makes requests to
             'ipToCommunicatingHash': ipToCommunicatingHash,            #all hashes communicating with IP
             'domainToCommunicatingHash': domainToCommunicatingHash,    #all hashes communicating with domain
             'domainToDownloadedHash': domainToDownloadedHash,          #all hashes downloaded from domain
             'ipToDownloadedHash': ipToDownloadedHash,                  #all hashes downloaded from IP
             'domainToIP': domainToIP,                                  #all IPs which domain has resolved to
             'ipToDomain': ipToDomain,                                  #all domains which have resolved to IP
             'hashToThreat': hashToThreat,                              #all threats associated with hash
             'threatToHash': threatToHash,                              #all hashes associated with threat
             'hashToRegKey': hashToRegKey,                              #all registry keys associated with behavior of hash
             'hashToBehavioralFileName': hashToBehavioralFileName,      #all file names associated with behavior of hash
             'hashToMutex': hashToMutex,                                #all mutexes associated with behavior of hash
             'hashToCommandRun': hashToCommandRun,                      #all commands run via CreateProcessInternalW by a hash
             'hashToDetectionRatio': hashToDetectionRatio,              #detection ratio of a hash
             'hashToPositiveAVList': hashToPositiveAVList,              #all AVs which have detected a hash
             'hashToScanDate': hashToScanDate,                          #scan date and time of a hash
             'hashToRescan': hashToRescan,                              #rescans a hash (note: scans via API are lower priority and can take several hours)
             'partialURLtoDownloadedHash': partialURLtoDownloadedHash,  #all hashes downloaded from any URL containing a specific string
             'peSectionMD5toHash': peSectionMD5toHash,                  #all hashes which have the given MD5 as a PE Section
             'importHashToHash': importHashToHash,                      #all hashes which have the given import hash
             'exploitToHash': exploitToHash,                            #all hashes which are tagged as given exploit in CVE format
             'urlToDetectionRatio': urlToDetectionRatio,                #detection ratio of a URL
             'urlToScan': urlToScan                                     #scan a URL (note: scans via API are lower priority and can take several hours)
             }

##############################################################################################
###                                     BEGIN MAIN                                         ###
##############################################################################################

if __name__ == '__main__':
    transform = sys.argv[1]
    data = sys.argv[2]    
    
    me = MaltegoTransform()
    
    m_result = functions[transform](me, data)
    m_result.returnOutput()
