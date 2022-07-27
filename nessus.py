import requests
import argparse
import json

base_url = ''

def get_token(username, password):
	payload = {"username": username, "password": password}
	r = requests.post(base_url + "session", data=payload, verify=False)
	return r.json()['token']

def get_history_id(session_token, scan_id):
	custom_header = {"X-Cookie": ("token=%s" % session_token)}
	# get history id
	r = requests.get(base_url  + ("scans/%d" % scan_id) , headers=custom_header, verify=False)
	return r.json()['history'][0]['history_id']

def get_file_id(session_token, scan_id, history_id):
	payload = {"format": "nessus"}
	custom_header = {"X-Cookie": ("token=%s" % session_token), "Content-Type": "application/json"}
	r = requests.post(base_url +  ("scans/%d/export?history_id=%d" % (scan_id, history_id)),data=json.dumps(payload, ensure_ascii=False), headers=custom_header, verify=False)
	return r.json()['file']

def check_file_status(session_token, scan_id, file_id):
	payload = {"file": file_id}
	custom_header = {"X-Cookie": ("token=%s" % session_token)}
	r = requests.get(base_url +  ("scans/%d/export/%d/status" % (scan_id, file_id)), headers=custom_header, verify=False)
	return r.json()['status']

def download_report(session_token, scan_id, file_id):
	# payload = {"file": file_id}
	custom_header = {"X-Cookie": ("token=%s" % session_token)}
	r = requests.get(base_url +  ("scans/%d/export/%d/download" % (scan_id, file_id)), headers=custom_header, verify=False)
	return r.text


def  main():
	global base_url
	
	parser = argparse.ArgumentParser(description='Arguments for Nessus API')
	parser.add_argument('-s', '--scan-id', type=int, required=True, help='Scan ID from Nessus (Can be found in the URL of scan)')
	parser.add_argument('-u', '--username', type=str, required=True, help='Username for Nessus instance')
	parser.add_argument('-p', '--password', type=str, required=True, help='Password for Nessus Instance')
	parser.add_argument('-H', '--host', type=str, required=True, help='Host IP:Port for Nessus Instance; For example: https://127.0.0.1:8834/')
	arguments = parser.parse_args()
	
	base_url = arguments.host

	token = get_token(arguments.username, arguments.password)
	history_id = get_history_id(token, arguments.scan_id)
	file_id = get_file_id(token, arguments.scan_id, history_id)
	
	while True:
		if check_file_status(token, arguments.scan_id, file_id) == 'ready':
			print download_report(token, arguments.scan_id, file_id)
			break

if __name__ == '__main__':
	main()