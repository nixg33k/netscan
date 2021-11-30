# netscan

*  Open File limit too small, setting Open Files limit to 20000
   Note: This script requires Open File limit to be at least 20000 or larger.
   the script will temporarily set this and revert it back at the end.

-Mon, 29 Nov 2021 12:26:14 PST
-abc.somedomain.com, 192.168.144.3
-using Current interface: eno1
  -IPADDR: 192.168.143.3
  -NETMASK: 255.255.255.0
  -CIDR: 192.168.104.3/24
  -Nodes in Subnet: 256

-Sample output ^^^^

  -The script will autodiscover your current network adapters and/or subnets,
  -and scan each subnet individually. Add the -p switch to run a port scan per host.


