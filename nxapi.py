import urllib3, requests, json, sys, getpass

switch_password = ""

#def get_switch_password():
#    global switch_password
#    switch_password = getpass.getpass()

def post_clis(switch_IP, switch_user, switch_password, clis, rollback = False):
    payload = []
    myheaders={'content-type':'application/json-rpc'}
    url = "https://%s/ins" % (switch_IP)

    nxapi_id = 1
    for cli in clis:
        dict_entry = {
            "jsonrpc": "2.0",
            "method": "cli",
            "params": {
                "cmd": cli,
                "version": 1
            },
            "id": nxapi_id
        }
        if rollback:
            dict_entry["rollback"] = "rollback-on-error"
        payload.append(dict_entry)
        nxapi_id += 1

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    #print(json.dumps(payload, indent=4))
    response = requests.post(url, data = json.dumps(payload), headers = myheaders,
                             auth = (switch_user, switch_password),
                             verify = False).json()
    #print(json.dumps(response, indent=4))
    print
    return response
