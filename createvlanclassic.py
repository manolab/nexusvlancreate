#!/usr/bin/python3 -B

import requests
import json
import sys
from nxapi import *

vteps_file = "tuttinexus"
try:
    command_arg = sys.argv[1]
    if command_arg != 'create' and command_arg != 'destroy':
        raise IndexError
except IndexError:
    print("create or destroy command needed!")
    sys.exit(1)
try:
    vlan_arg = sys.argv[2]
except IndexError:
    print("vlan id nedeed!")
    sys.exit(1)
try:
    name_arg = sys.argv[3]
except IndexError:
    if command_arg == 'create':
        print("name needed!")
        sys.exit(1)

clis = []


def create_vlan(vlan, name):
    clis.append("vlan %s" % vlan)
    clis.append("  name %s" % name)


def destroy_vlan(vlan):
    clis.append("no vlan %s" % vlan)


#def set_vlan_on_access_port(vlan, access_port):
#    clis.append("int %s" % access_port)
#    clis.append("  switchport")
#    clis.append("  switchport access vlan %s" % vlan)


def check_vlan(switch, user, passw, vlan):
    resp = post_clis(switch, user, passw, ["show vlan id %s" % vlan])
    if resp["result"]["body"]["TABLE_vlanbriefid"]["ROW_vlanbriefid"]["vlanshowbr-vlanstate"] != "active":
        print("ERROR: VLAN %s validation failed on switch %s" %
              (vlan, switch))


def findpass(device):
    dotcloginrc = '/var/lib/rancid/.cloginrc'
    user = ''
    password = ''

    with open(dotcloginrc) as f:
        for line in f:
            line = line.strip()
            if line == '':
                continue
            if '#' in line[0]:
                continue
            chunks = line.split()
            if chunks[0] == 'add':
                if chunks[1] == 'password':
                    if device == chunks[2]:
                        password = chunks[3]
                if chunks[1] == 'user':
                    if device == chunks[2]:
                        user = chunks[3]
            if user and password:
                break

    return (user, password)

def main():

    if command_arg == 'create':
        create_vlan(vlan_arg, name_arg)
    else:
        destroy_vlan(vlan_arg)
    #if access_arg != 'NONE':
    #    set_vlan_on_access_port(vlan_arg, access_arg)

    clis.append("copy run sta")

    vteps=[line.rstrip('\n') for line in open(vteps_file)]

    for vtep in vteps:
        switch_password=''
        if '#' not in vtep:
            print("****** Switch: %s ******" % (vtep))
            (switch_user, switch_password) = findpass(vtep)
            if switch_password:
                print("****** Sending Commands To Switch ******")
                post_clis(vtep, switch_user, switch_password, clis)
                if command_arg == 'create':
                    print("****** Verify Switch Configuration ******")
                    check_vlan(vtep, switch_user, switch_password, vlan_arg)

if __name__ == "__main__":
    main()
