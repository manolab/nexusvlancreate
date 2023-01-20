#! /usr/bin/python3 -B

import requests, json, sys, coloredlogs, logging
from nxapi import *

logger = logging.getLogger(__name__)
if '-d' in sys.argv:
    logger.setLevel(logging.DEBUG)
    coloredlogs.install(level='DEBUG', logger=logger, fmt='%(asctime)s %(levelname)s %(message)s')
    logger.debug("debug mode!") 
    sys.argv.remove('-d')
else:
    logger.setLevel(logging.INFO)
    coloredlogs.install(level='INFO', logger=logger, fmt='%(asctime)s %(levelname)s %(message)s')
    
debug = False
if '-dry' in sys.argv:
    debug = True
    sys.argv.remove('-dry')

logger.info("started!")

vteps_file = "vteps"
logger.debug("switch list in file: "+vteps_file)

try:
    command_arg = sys.argv[1]
    if command_arg != 'create' and command_arg != 'destroy':
        raise IndexError
except IndexError:
    logger.error("create or destroy command needed!")
    sys.exit(1)
try:
    vlan_arg = int(sys.argv[2])
except IndexError:
    logger.error("vlan id nedeed!")
    sys.exit(1)
except ValueError:
    logger.error("vlan id should be a number!")
    exit(1)
try:
    name_arg = sys.argv[3]
except IndexError:
    if command_arg == 'create':
        logger.error("vlan name needed!")
        sys.exit(1)
try:
    which_vteps = sys.argv[4]
except IndexError:
    logger.error("switch selection empty!")
    exit(1)


l2vni_arg = vlan_arg+10000
logger.debug("vni: "+str(l2vni_arg))
clis = []

#def enable_features():
#    clis.append("feature bgp")
#    clis.append("feature interface-vlan")
#    clis.append("feature vn-segment-vlan-based")
#    clis.append("feature nv overlay")
#    clis.append("nv overlay evpn")

def findpass(device):
    dotcloginrc = '/var/lib/rancid/.cloginrc'
    logger.debug("using dotcloginrc: "+dotcloginrc)
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
                        logger.debug("found password!")
                if chunks[1] == 'user':
                    if device == chunks[2]:
                        user = chunks[3]
                        logger.debug("found username!")
            if user and password:
                break

    return (user, password)

def vlantomcg(vlan):

    if vlan < 256:
        mc = '0.'+str(vlan)
    else:
        if len(str(vlan)) == 4:
            mc = str(vlan)[0:2]+'.'+str(vlan)[2:]
        else:
            mc = str(vlan)[0:1]+'.'+str(vlan)[1:]
    return '239.0.'+mc

def create_vlan_and_l2vni(vlan, l2vni, name):
    clis.append("vlan %s" % vlan)
    clis.append("  vn-segment %s" % l2vni)
    clis.append("  name %s" % name)

def add_l2vni_to_nve(l2vni, mcast_group):
    clis.append("int nve1")
    #clis.append("  host-reachability protocol bgp")
    clis.append("  member vni %s" % l2vni)
    clis.append("  mcast-group %s" % mcast_group)
    #clis.append("  suppress-arp")

def add_l2vni_to_evpn(l2vni):
    clis.append("evpn")
    clis.append("  vni %s l2" % l2vni)
    clis.append("  rd auto")
    clis.append("  route-target import auto")
    clis.append("  route-target export auto")

#def set_vlan_on_access_port(vlan, access_port):
#    clis.append("int %s" % access_port)
#    clis.append("  switchport")
#    clis.append("  switchport access vlan %s" % vlan)

def delete_vlan_and_l2vni(vlan):
    clis.append("no vlan %s" % vlan)

def remove_l2vni_from_nve(l2vni):
    clis.append("int nve1")
    clis.append("  no member vni %s" % l2vni)

def remove_l2vni_from_evpn(l2vni):
    clis.append("evpn")
    clis.append("  no vni %s l2" % l2vni)

#def reset_access_port(access_port):
#    clis.append("int %s" % access_port)
#    clis.append("  switchport access vlan 1")

def check_vlan(switch, user, passw, vlan):
    resp = post_clis(switch, user, passw, ["show vlan id %s" % vlan])
    if resp["result"]["body"]["TABLE_vlanbriefid"]["ROW_vlanbriefid"]["vlanshowbr-vlanstate"] != "active":
        logger.critical("ERROR: VLAN %s validation failed on switch %s" % (vlan, switch))
    else:
        logger.info("configuration ok on "+switch)

def main():
    if command_arg == 'create':
        #enable_features()
        create_vlan_and_l2vni(vlan_arg, l2vni_arg, name_arg)
        add_l2vni_to_nve(l2vni_arg, vlantomcg(vlan_arg))
        add_l2vni_to_evpn(l2vni_arg)
        #set_vlan_on_access_port(vlan_arg, access_port_arg)
    else:
        #reset_access_port(access_port_arg)
        remove_l2vni_from_evpn(l2vni_arg)
        remove_l2vni_from_nve(l2vni_arg)
        delete_vlan_and_l2vni(vlan_arg)
    clis.append("copy r s")
    try:
        vteps = [line.rstrip('\n') for line in open(vteps_file)]
    except FileNotFoundError:
        logger.error('\''+vteps_file+'\' file not found!')
        sys.exit(1)
    if which_vteps == 'all':
        quali = vteps.copy()
    else:
        quali = list(which_vteps.split(','))
    for vtep in quali:
        switch_password=''
        if '#' not in vtep:
            logger.info("VTEP %s" % (vtep))
            (switch_user, switch_password) = findpass(vtep)
            if switch_password:
                logger.debug("password found for VTEP "+vtep)
                logger.info("sending commands to switch "+vtep)
                logger.debug(clis)
                if not debug: post_clis(vtep, switch_user, switch_password, clis)
                logger.info("verifying switch configuration")
                if not debug and command_arg =='create': check_vlan(vtep, switch_user, switch_password, vlan_arg)
            else:
                logger.warning("password not found for vtep "+vtep)
    logger.info(sys.argv[0]+" ended!")
    sys.exit(0)

if __name__ == "__main__":
    main()
logger.info(sys.argv[0]+" ended!")
sys.exit(0)
