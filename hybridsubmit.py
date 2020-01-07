#!/usr/bin/python3
import sys, requests, json
apikey = ""
url = "https://www.hybrid-analysis.com/api/v2/quick-scan/file"
payload = {'scan_type' : 'all'}
upload_file={'file':open(sys.argv[1], 'rb')}
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
        print('\tScanned by ' + str(current_scanner['total']) + " agents")
if json_data['whitelist'][0]['value']:
    print("File is whitelisted")
else:
    print("File is not whitelisted")
