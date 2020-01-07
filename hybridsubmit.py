#!/usr/bin/python3
import sys, requests, json, argparse

apikey = ""

parser = argparse.ArgumentParser(description='Scan files using the Hybrid Analysis Cloud Sandbox')
parser.add_argument('file', metavar = 'FILE-TO-UPLOAD', type=str)
parser.add_argument('-f', "--full", choices=['windows','linux'],help="Run file through full emulation in cloud sandbox on the provided operating system (Windows/Linux)")

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

quickLookup(args.file)
if args.full:
    fullEmulationSubmit(args.file, args.full)
