# netscan

    git clone https://github.com/nixg33k/netscan.git


    Open File limit too small, setting Open Files limit to 20000.
    Note: This script requires Open File limit to be at least 20000 or larger, 
    the script will temporarily set this and revert it back at the end.

    Mon, 29 Nov 2021 12:26:14 PST
    abc.somedomain.com, 192.168.144.3
    using Current interface: eno1
    IPADDR: 192.168.143.3
    NETMASK: 255.255.255.0
    CIDR: 192.168.104.3/24
    Nodes in Subnet: 256

    Sample output ^^^^  of one of your subnets and interface.

    Note: This script requires nmap to be installed
        Debian/Ubuntu apt install nmap
        Redhat/Fedora yum install nmap


    The script will autodiscover your current configured (UP) network adapters and/or subnets,
    and scan each subnet individually. Add the -p switch to run a port scan per host.
    Note: Only network adapters with a valid IP address will be scanned.

    Grab this from GitHub.com  git clone https://github.com/nixg33k/netscan.git
    cd to netscan, then just run ./netscan or ./netscan -p to scan ports as well.
    This can run as a non-root user, but you will see more details if run this as root.

    This script runs very fast. On my home lab the host I run this on has 5 configured
    Network adapters and it runs this in 4.18 seconds or less.  With portscan it takes about
    57 seconds to complete.


