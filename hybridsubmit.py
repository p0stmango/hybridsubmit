#!/usr/bin/python3
import sys, requests, json, argparse

apikey = ""

parser = argparse.ArgumentParser(description='Scan files using the Hybrid Analysis Cloud Sandbox')
parser.add_argument('file', metavar = 'FILE-TO-UPLOAD', type=str)
parser.add_argument('-f', "--full", choices=['windows','linux'],help="Run file through full emulation in cloud sandbox on the provided operating system (Windows/Linux)")
parser.add_argument('-s', "--search", help="Search for a file hash in the database of reports", action='store_true')

args = parser.parse_args()

def fullEmulationSubmit(sus_file, os):
    url = "https://www.hybrid-analysis.com/api/v2/submit/file"
    if os == "linux":
        id = 300
    elif os == "windows":
        id = 120
    payload = {"environment_id":id}
    upload_file ={"file":open(sus_file, 'rb')}
    header = {"api-key":apikey, 'User-agent':'Falcon'}
    r = requests.post(url, data=payload, files=upload_file, headers=header)
    json_data = r.json()
    if json_data['submission_id']:
        print("Successfully submitted for emulation. Submission ID: " + json_data['submission_id'])

def quickLookup(sus_file):
    url = "https://www.hybrid-analysis.com/api/v2/quick-scan/file"
    payload = {'scan_type' : 'all'}
    upload_file={'file':open(sus_file, 'rb')}
    header = {'api-key': apikey, 'User-agent':"Falcon"}
    r = requests.post(url, data=payload, files=upload_file, headers=header)
    json_data = r.json()
    #print(json_data)
    print("File SHA256: " + json_data['sha256'])
    print("Scan ID: " + json_data['id'])
    for current_scanner in json_data['scanners']:
        print('Scanner Name: ' + current_scanner['name'])
        print('\tDetection Percentage: ' + str(current_scanner['percent']))
        print('\tDetermined Status: ' + current_scanner['status'])
        print('\tScanned by ' + str(current_scanner['total']))
    if json_data['whitelist'][0]['value']:
        print("File is whitelisted")
    else:
        print("File is not whitelisted")

def searchDatabase(filehash):
    payload = {'hash':filehash}
    header = {'api-key':apikey,'User-agent':'Falcon'}
    r = requests.post('https://www.hybrid-analysis.com/api/v2/search/hash', data=payload, headers=header)
#    print(r.request.url)
#    print(r.text)
    json_data = r.json()
    report_data = json_data[0]
    print("File verdict is " + report_data['verdict'])
    print("Malware Type: " + report_data['vx_family'])
    print("Threat Score: " + str(report_data['threat_score']))
    print("Threat Level: " + str(report_data['threat_level']))
    print("Total Signatures Matched: " + str(report_data['total_signatures']))
    print("Type: " + report_data['type'])
    print("MITRE ATT&CK Matches---------------------------------------------------")
    for tacmatch in report_data['mitre_attcks']:
        print("Tactic Matched: " + tacmatch['tactic'])
        print("Technique Used: " + tacmatch['technique'])
        print("\tMalicious Identifiers Matched: " + str(tacmatch['malicious_identifiers_count']))
        print("\tSuspicious Identifiers Matched: " + str(tacmatch['suspicious_identifiers_count']))
        print("\tInformative Identifiers Matched: " + str(tacmatch['informative_identifiers_count']))
    print("Hosts contacted------------------------------------------------------- ")
    if report_data['extracted_files'] != []:
        for extfile in report_data['extracted_files']:
            print('File Name: ' + extfile['name'])
            print('\tFile Path: ' + extfile['file_path'])
            print('\tFile Size: ' + extfile['file_size'])
            print('\tFile MD5: ' + extfile['md5'])
            print('\tThreat Level: ' + str(extfile['threat_level']))
    for host in report_data['hosts']:
        print("\t" + host)
    print("Domains contacted----------------------------------------------------")
    for domain in report_data['domains']:
        print("\t" + domain)
    print("Total Network Connections: " + str(report_data['total_network_connections']))
    print("Emulated on: " + report_data['environment_description'])
    print("Analysed on " + report_data['analysis_start_time'])

if args.full:
    quickLookup(args.file)
    fullEmulationSubmit(args.file, args.full)
elif args.search:
    searchDatabase(args.file)
else:
    quickLookup(args.file)
