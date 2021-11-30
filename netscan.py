#!/usr/bin/env python3

import argparse
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

import pkg_resources

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from netaddr import *
from portscan import scan_ports

global addr, netmask, cidr, allhosts


def chkmodules():
    required = {'socket', 'time', 'os', 'netifaces', 'netaddr', 'nmap', 'pprint', 're', 'subprocess', 'logging', 'argparse', 'resource', 'pkg_resources', 'netaddr', 'portscan'}
    installed = {pkg.key for pkg in pkg_resources.working_set}
    missing = required - installed

    if missing:
        # python = sys.executable
        # "%s, %s" % (fqdn, curip))
        print("Modules are missing... %s" % missing)
        print("Please install before running netscan.")
        sys.exit(13)
        # subprocess.check_call([python, '-m', 'pip', 'install', *missing], stdout=subprocess.DEVNULL)
    else:
        print("Python modules installed: %s" % installed)


def OpenFile():
    global f
    f = open('portscan_output.txt', 'at+')


def WriteFile(string):
    f.write(str(string))


def CloseFile():
    f.close()


def OpenFileLimit():
    ulimitmax = subprocess.getoutput('ulimit -Sn')
    nulimitmax = int(ulimitmax)
    global soft, hard
    soft, hard = resource.getrlimit(resource.RLIMIT_OFILE)
    # print(soft,hard)
    # print(nulimitmax)

    if os.name.split()[0] == 'posix':
        if nulimitmax < 20000:
            print()
            print("Open File limit too small, setting Open Files limit to 20000")
            resource.setrlimit(resource.RLIMIT_OFILE, (20000, hard))
            # print('Please set open files too 20000.. ulimit -Sn 20000')
            # os.popen("bash -c ulimit -Sn 20000")
            # print(subprocess.getoutput('ulimit -Sn'))
            print()
            # raise SystemExit()


def GetIPAndHostName():
    fqdn = socket.getfqdn()
    global curip
    curip = socket.gethostbyname(fqdn)
    print("%s, %s" % (fqdn, curip))


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
    for iface in netifaces.interfaces():
        if iface == 'lo':
            continue

        addresses = netifaces.ifaddresses(iface)

        if network.version == 4 and netifaces.AF_INET in addresses:
            addr = addresses[netifaces.AF_INET][0]['addr']
            netmask = addresses[netifaces.AF_INET][0]['netmask']
            cidr = netaddr.IPNetwork("%s/%s" % (addr, netmask))

            print("using Current interface: %s" % iface)

            allhosts = IPNetwork(cidr)

            print("IPADDR: %s" % addr)
            print("NETMASK: %s" % netmask)
            print("CIDR: %s " % cidr)
            print("Nodes in Subnet: %s" % (len(allhosts) - 2))
            print()

            nm = nmap.PortScanner()

            starttime = time.time()

            # a = nm.scan(hosts=str(cidr), arguments='-T4 -sS -PE --min-rate 1000 --max-retries 1')
            # -sS required root
            a = nm.scan(hosts=str(cidr), arguments='-T4 -sP -PE --min-rate 1000 --max-retries 1')

            endtime = time.time()
            totaltime = endtime - starttime
            n = 0
            print('-------------------------------------------------------------------------------')
            print('Hostname/FQDN   ::  IP Address  ::    Mac    ::     Vendor')
            print('-------------------------------------------------------------------------------')
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

                    if len(newzhost) <= 4:
                        Znewzhost = 'NULL'
                    else:
                        Znewzhost = newzhost

                    ZipAddr = splitip
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

                    print("%s :: %s :: %s :: %s" % (Znewzhost, ZipAddr, Znewzvendor1, Znewzvendor2))
                    parser = argparse.ArgumentParser()
                    parser.add_argument('-p', action='store_true', help='scan ports')
                    parser.add_argument('-f', action='store_true', help='write output to a file')
                    results = parser.parse_args()

                    if results.p:
                        scan_ports(ZipAddr, 1)

                    if results.f:
                        strscan = str(scan_ports(ZipAddr, 1))
                        # print(strscan)
                        WriteFile(strscan)

            print("Nodes in Subnet: %d" % n)
            print("Arp scan in %f seconds...." % (totaltime))


def main():
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
    if soft < 20000:
        print("reverting Open files to original setting %d" % soft)
        resource.setrlimit(resource.RLIMIT_OFILE, (soft, hard))
    # print(subprocess.getoutput('ulimit -Sn'))


main()
