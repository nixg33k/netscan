#!/usr/bin/env python3

import req_mods
import argparse
import importlib.util
import logging
import netaddr
import netifaces
import nmap
import os
import pprint
import re
import resource
import socket
import subprocess
import sys
import time
import distro

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from netaddr import *
from portscan import scan_ports

global addr, netmask, cidr, allhosts, curip, ip


# function to determine the class of an ipaddraddress
def findClass(ipaddr2):
    if 0 <= ipaddr2[0] <= 127:
        return "A"

    elif 128 <= ipaddr2[0] <= 191:
        return "B"

    elif 192 <= ipaddr2[0] <= 223:
        return "C"

    elif 224 <= ipaddr2[0] <= 239:
        return "D"

    else:
        return "E"


# function to separate network and host id from the given ipaddraddress
def seperate(ipaddr2, className):
    # for class A network
    if className == "A":
        print("Network Address is : ", ipaddr2[0])
        print("Host Address is : ", ".".join(ipaddr2[1:4]))

    # for class B network
    elif className == "B":
        print("Network Address is : ", ".".join(ipaddr2[0:2]))
        print("Host Address is : ", ".".join(ipaddr2[2:4]))

    # for class C network
    elif className == "C":
        print("Network Address is : ", ".".join(ipaddr2[0:3]))
        print("Host Address is : ", ipaddr2[3])

    else:
        print("In this Class, ipaddraddress is not divided into Network and Host ID")


def chkmodules():
    required = {'socket', 'time', 'os', 'netifaces', 'netaddr', 'nmap', 'pprint', 're', 'subprocess', 'logging',
                'argparse', 'resource', 'pkg_resources', 'netaddr', 'portscan'}

    zmodules = []
    mods_installed = []
    req_count = len(required)

    for module in required:
        exists = importlib.util.find_spec(module) is not None
        # print("req_count: %d" % req_count)
        if (exists is True) and (req_count == 14):
            mods_installed.append(module)
        else:
            print("module: %s not installed" % module)
            zmodules.append(module)

    is_zmodules_not_empty = bool(zmodules)

    if is_zmodules_not_empty:
        print("These Python modules must first be installed: %s" % zmodules)
        sys.exit(13)

    if req_count == 14:
        print("All required modules are installed!")
        # print("All required modules are installed: \n%s" % required)


def OpenFile():
    global f
    f = open('portscan_output.txt', 'at+')


def WriteFile(string):
    f.write(str(string))


def CloseFile():
    f.close()


def OpenFileLimit():
    ssoft, hhard = resource.getrlimit(resource.RLIMIT_OFILE)

    ulimitmax = ssoft
    nulimitmax = int(ulimitmax)

    print(ssoft, hhard)
    # print(nulimitmax)

    if os.name.split()[0] == 'posix':
        if nulimitmax < 30000:
            print()
            print("Soft Open File limit too small, setting Open Files limit to 30000")
            getdistro = distro.id()
            getdistro = getdistro.replace("'", "")
            #

            # print(subprocess.getoutput('ulimit -Sn'))
            print("Current Open File settings - Soft: %s, Hard: %s" % (ssoft, hhard))
            print("Linux Distro: %s" % getdistro)
            if getdistro == 'centos':
                ssoft, hhard = resource.getrlimit(resource.RLIMIT_NOFILE)
                print("Host OS is CentOS")
                resource.setrlimit(resource.RLIMIT_NOFILE, (30000, 30000))
                print("Open File now set to %s" % subprocess.getoutput('ulimit -Sn'))
            else:
                print("Not CentOS!")
                ssoft, hhard = resource.getrlimit(resource.RLIMIT_OFILE)
                resource.setrlimit(resource.RLIMIT_OFILE, (30000, hhard))

            soft2, hard2 = resource.getrlimit(resource.RLIMIT_OFILE)
            print("Current Open File settings after change - Soft: %s, Hard: %s" % (soft2, hard2))

            print()


def GetIPAndHostName():
    fqdn = socket.getfqdn()
    global curip
    curip = socket.gethostbyname(fqdn)
    print("FQDN: %s, IP: %s" % (fqdn, curip))


def GetSubNet():
    global ip
    ip = IPNetwork(curip)


def CurDateAndTime():
    os.environ['TZ'] = 'US/Pacific'
    time.tzset()
    ztime = time.strftime("%a, %d %b %Y %H:%M:%S %Z", time.localtime())
    print("%s" % ztime)


def get_address_in_network():
    global addr, netmask, cidr, allhosts
    network = netaddr.IPNetwork(ip)
    interfaces = netifaces.interfaces()
    interfaces.remove('lo')
    # get data type for interfaces
    # print(type(interfaces))
    print("This host has %d configured (UP) network adapters" % len(interfaces))
    print("If the nic does not have an IP address it will not be scanned.")
    print("Adapter 'lo' is removed and ignored...")
    print(interfaces)
    for iface in interfaces:
        if iface == 'lo':
            continue

        addresses = netifaces.ifaddresses(iface)
        #   print(addresses)

        if network.version == 4 and netifaces.AF_INET in addresses:
            addr = addresses[netifaces.AF_INET][0]['addr']
            netmask = addresses[netifaces.AF_INET][0]['netmask']
            cidr = netaddr.IPNetwork("%s/%s" % (addr, netmask))
            # elif network.version == 6 and netifaces.AF_INET6 in addresses:
            #    addr = addresses[netifaces.AF_INET6][0]['addr']
            #    netmask = addresses[netifaces.AF_INET6][0]['netmask']
            #    cidr = netaddr.IPNetwork("%s/%s" % (addr, netmask))

            # print("==========================================================")
            print("using Current interface: %s" % iface)

            allhosts = IPNetwork(cidr)

            print("IPADDR: %s" % addr)
            print("NETMASK: %s" % netmask)
            print("CIDR: %s " % cidr)

            ipaddr = addr
            ipaddr = ipaddr.split(".")
            ipaddr = [int(i) for i in ipaddr]

            # getting the network class
            networkClass = findClass(ipaddr)
            print("Given IP: %s belongs to class : %s " % (addr, networkClass))

            # printing network and host id
            ipaddr = [str(i) for i in ipaddr]
            seperate(ipaddr, networkClass)

            print("IP Address: %s" % ipaddr)

            # print("Network is Class: %s" % theclass)
            print()

            nm = nmap.PortScanner()
            starttime = time.time()

            # a = nm.scan(hosts=str(cidr), arguments='-T4 -sS -PE --min-rate 1000 --max-retries 1')
            # -sS required root
            # a = nm.scan(hosts=str(cidr), arguments='-T4 -sP -PE -vv --min-rate 1000 --max-retries 1')
            # a = nm.scan(hosts=str(cidr), arguments='-T4 -n -A -sP -PE -vv --min-rate 1000 --max-parallelism 100  --max-rtt-timeout 200ms --max-retries 0')
            a = nm.scan(hosts=str(cidr), arguments='-T4 -sn -PE -v --max-retries 0')
            # a = nm.scan(hosts=str(cidr), arguments='-T4 -n -R -sn -PE -v --min-rate 1000 --max-retries 1')
            endtime = time.time()
            totaltime = endtime - starttime
            n = 0
            print('----------------------------------------------------------------------------------------------------------------')
            print("%32s :: %16s :: %20s :: %32s " % ("Hostname/FQDN", "IP Address", "Mac", "Vendor"))
            print('----------------------------------------------------------------------------------------------------------------')
            print()
            for k, v in a['scan'].items():
                if str(v['status']['state']) == 'up':
                    n += 1
                    pp = pprint.PrettyPrinter(indent=0)
                    splithost = str(v['hostnames'])
                    splitip = str(v['addresses']['ipv4'])
                    splitvendor = str(v['vendor'])
                    zhost = str(splithost.split("'")[7:8])
                    newzhost = re.sub('[\[\]\']', '', zhost)
                    ZipAddr = splitip
                    try:
                        name, alias, addresslist = socket.gethostbyaddr(ZipAddr)

                    except:
                        name = "-NULL-"

                    # print(name)
                    # if len(name) != 0:
                    #    print("hostnamelookup: %s" % str(name))

                    # print("zhost: %s" % zhost)
                    # print("v.hostname: %s" % v.hostname())

                    if len(name) == 0:
                        Znewzhost = 'NULL'
                    else:
                        Znewzhost = name

                    # ZipAddr = splitip
                    zvendor1 = str(splitvendor.split("'")[1:2])
                    zvendor2 = str(splitvendor.split("'")[3:4])
                    newzvendor1 = re.sub('[\[\]\'\{\}]', '', zvendor1)
                    newzvendor2 = re.sub('[\[\]\'\{\}]', '', zvendor2)

                    if len(newzvendor1) != 0:
                        Znewzvendor1 = newzvendor1
                    else:
                        Znewzvendor1 = 'NULL'

                    if len(newzvendor2) != 0:
                        Znewzvendor2 = newzvendor2
                    else:
                        Znewzvendor2 = 'NULL'

                    print("%32s :: %16s :: %20s :: %32s" % (Znewzhost, ZipAddr, Znewzvendor1, Znewzvendor2))
                    parser = argparse.ArgumentParser()
                    parser.add_argument('-p', action='store_true', help='scan ports')
                    parser.add_argument('-f', action='store_true', help='write output to a file')
                    # parser.add_argument('eno1', action='store_true', help='eno1 nic specified.')
                    results = parser.parse_args()

                    if results.p:
                        scan_ports(ZipAddr, 1)

                    if results.f:
                        strscan = str(scan_ports(ZipAddr, 1))
                        # print(strscan)
                        WriteFile(strscan)
            print()
            print()
            print("Nodes in Subnet: %d" % n)
            print("Arp scan in %f seconds...." % totaltime)


def chkargs():
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', action='store_true', help='scan ports')
    parser.add_argument('-f', action='store_true', help='write output to a file')
    # parser.add_argument('eno1', action='store_true', help='eno1 nic specified.')
    results = parser.parse_args()
    return results
    # exit(0)


def chkargs2():
    if len(sys.argv) > 1:
        if sys.argv[1] == "-h":
            chkargs()
        elif sys.argv[1] == "-p":
            print("\nScanning ports now...")


def main():
    sys.excepthook = req_mods.ensure_enviroment_excepthook
    chkargs2()
    global soft, hard
    soft, hard = resource.getrlimit(resource.RLIMIT_OFILE)
    astarttime = time.time()
    # chkmodules()
    OpenFile()
    OpenFileLimit()
    CurDateAndTime()
    GetIPAndHostName()
    GetSubNet()
    get_address_in_network()
    CloseFile()

    aendtime = time.time()

    atotaltime = aendtime - astarttime
    print()
    print("Total time: %f seconds" % atotaltime)
    print()
    getdistro = distro.id()
    getdistro = getdistro.replace("'", "")

    soft2, hard2 = resource.getrlimit(resource.RLIMIT_OFILE)

    if getdistro == 'centos':
        if soft2 == 30000:
            print("reverting soft Open files to original setting %d" % soft)
            resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))
        if hard2 == 30000:
            print("reverting hard Open files to original setting %d" % hard)
            resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))

    else:
        if soft2 == 30000:
            print("reverting soft Open files to original setting %d" % soft)
            resource.setrlimit(resource.RLIMIT_OFILE, (soft, hard))
        if hard2 == 30000:
            print("reverting hard Open files to original setting %d" % hard)
            resource.setrlimit(resource.RLIMIT_OFILE, (soft, hard))

    if soft2 == 30000 or hard2 == 30000:
        soft4, hard4 = resource.getrlimit(resource.RLIMIT_NOFILE)
        print("Reverting Open File settings - Soft: %s, Hard: %s" % (soft4, hard4))


main()
