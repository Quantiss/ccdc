#! /bin/bash
#
#	ORDER ORDER ORDER MATTERS! The first rule listed is the first rule to be implemented. 
#	If we dropped all INPUT/OUTPUT traffic from the beggining we would not be able to send or recieve traffic
#	
#
#
#   
#
#
#
#	INPUT == incoming traffic to host
#	OUTPUT == traffic leaving our host

#	Dipslays current firewall rules
#iptables -L

#	Save iptables to master config file 
#	iptables-save > /etc/iptables.up.rules

#	Activate new iptables rules
#	iptables-restore < 'absolute file path'

#	'-j ACCEPT'ing 'OUTPUT' traffic to '-d emuccdc.com' our ecomm website via '-p TCP' protocol
#iptables -A OUTPUT -p tcp -d emuccdc.com -j ACCEPT


#'-j DROP'ing any 'OUTPUT' traffic on port '--dport 80' via the '-p TCP' protocol
#iptables -A OUTPUT -p tcp --dport 80 -j DROP


#'-j DROP'ing any 'OUTPUT' traffic on port '--dport 443' via the '-p TCP' protocol
#iptables -A OUTPUT -p tcp --dport 443 -j DROP


#	'-j ACCEPT'ing 'INPUT' traffic to address '-s 172.16.10.2' our ecomm website on port '--dport 22' via '-p TCP' protocol
#iptables -A INPUT -p tcp -s 172.16.10.2 --dport 22 -j ACCEPT


#'-j DROP'ing any 'OUTPUT' traffic on range '-s 0.0.0.0/0' on port '--dport 22' via the '-p TCP' protocol
#iptables -A INPUT -p tcp -s 0.0.0.0/0 --dport 22 -j DROP

# FOR SPLUNK ONLY
-A INPUT -p tcp -s ip.addr.for.splunk --dport 8089 -j ACCEPT
-A INPUT -p tcp -s 0.0.0.0/0 --dport 8089 -j DROP

#FOR EVERY BOX
-A INPUT -p tcp -s ip.addr.for.splunk --dport 8089 -j ACCEPT
-A INPUT -p tcp -s ip.addr.for.splunk --dport 9997 -j ACCEPT

-A INPUT -p tcp -s 0.0.0.0/0 --dport 8089 -j DROP
-A INPUT -p tcp -s 0.0.0.0/0 --dport 9997 -j DROP




###############################################################################
# The MIT License
#
# Copyright 2012-2014 Jakub Jirutka <jakub@jirutka.cz>.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

###############################################################################
#
#           Basic iptables/IPv4 template for an ordinary servers
#
# This file is in iptables-restore format. See the man pages for 
# iptables-restore(8) and iptables-save(8).
#
# The following is a set of firewall rules that should be applicable to Linux 
# servers running within departments. It is intended to provide a useful 
# starting point from which to devise a comprehensive firewall policy for 
# a host.
#
# Parts 1 and 3 of these rules are the same for each host, whilst part 2 can be 
# populated with rules specific to particular hosts. The optional part 4 is
# prepared for a NAT rules, e.g. for port forwarding, redirect, masquerade...
#
# This template is based on http://jdem.cz/v64a3 from University of Leicester.
#
# For the newest version go to https://gist.github.com/jirutka/3742890.
#
# @author Jakub Jirutka <jakub@jirutka.cz>
# @version 1.3.1
# @date 2014-01-28
#

###############################################################################
# 1. COMMON HEADER                                                            #
#                                                                             #
# This section is a generic header that should be suitable for most hosts.    #
###############################################################################

#filter
#The following example allows all incoming SSH, HTTP and HTTPS traffic.

#iptables -A INPUT -i eth0 -p tcp -m multiport --dports 22,80,443 -m state --state NEW,ESTABLISHED -j ACCEPT
#iptables -A OUTPUT -o eth0 -p tcp -m multiport --sports 22,80,443 -m state --state ESTABLISHED -j ACCEPT

# prevent DOS
#iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT

#log dropped packets
-N LOGGING
-A INPUT -j LOGGING
-A LOGGING -m limit --limit 2/min -j LOG --log-prefix "IPTables Packet Dropped: " --log-level 7
-A LOGGING -j DROP


# Base policy
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]

# Don't attempt to firewall internal traffic on the loopback device.
-A INPUT -i lo -j ACCEPT

# Continue connections that are already established or related to an established 
# connection.
-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Drop non-conforming packets, such as malformed headers, etc.
-A INPUT -m conntrack --ctstate INVALID -j DROP

# Block remote packets claiming to be from a loopback address.
-A INPUT -s 127.0.0.0/8 ! -i lo -j DROP

# Drop all packets that are going to broadcast, multicast or anycast address.
-A INPUT -m addrtype --dst-type BROADCAST -j DROP
-A INPUT -m addrtype --dst-type MULTICAST -j DROP
-A INPUT -m addrtype --dst-type ANYCAST -j DROP
-A INPUT -d 224.0.0.0/4 -j DROP

# Chain for preventing SSH brute-force attacks.
# Permits 10 new connections within 5 minutes from a single host then drops 
# incomming connections from that host. Beyond a burst of 100 connections we 
# log at up 1 attempt per second to prevent filling of logs.
-N SSHBRUTE
-A SSHBRUTE -m recent --name SSH --set
-A SSHBRUTE -m recent --name SSH --update --seconds 300 --hitcount 2 -m limit --limit 1/second --limit-burst 100 -j LOG --log-prefix "iptables[SSH-brute]: "
-A SSHBRUTE -m recent --name SSH --update --seconds 300 --hitcount 2 -j DROP
-A SSHBRUTE -j ACCEPT

# Chain for preventing ping flooding - up to 6 pings per second from a single 
# source, again with log limiting. Also prevents us from ICMP REPLY flooding 
# some victim when replying to ICMP ECHO from a spoofed source.
-N ICMPFLOOD
-A ICMPFLOOD -m recent --set --name ICMP --rsource
-A ICMPFLOOD -m recent --update --seconds 1 --hitcount 6 --name ICMP --rsource --rttl -m limit --limit 1/sec --limit-burst 1 -j LOG --log-prefix "iptables[ICMP-flood]: "
-A ICMPFLOOD -m recent --update --seconds 1 --hitcount 6 --name ICMP --rsource --rttl -j DROP
-A ICMPFLOOD -j ACCEPT


###############################################################################
# 2. HOST SPECIFIC RULES                                                      #
#                                                                             #
# This section is a good place to enable your host-specific services.         #
# ! DO NOT FORGOT TO COPY THESE RULES TO firewall.ip6tables TO ALLOW IPV6 !   #
###############################################################################

# Accept HTTP and HTTPS
#-A INPUT -p tcp -m multiport --dports 80,443 --syn -m conntrack --ctstate NEW -j ACCEPT


###############################################################################
# 3. GENERAL RULES                                                            #
#                                                                             #
# This section contains general rules that should be suitable for most hosts. #
###############################################################################

# Accept worldwide access to SSH and use SSHBRUTE chain for preventing 
# brute-force attacks.
-A INPUT -p tcp --dport 22 --syn -m conntrack --ctstate NEW -j SSHBRUTE

# Permit useful ICMP packet types.
# Note: RFC 792 states that all hosts MUST respond to ICMP ECHO requests.
# Blocking these can make diagnosing of even simple faults much more tricky.
# Real security lies in locking down and hardening all services, not by hiding.
-A INPUT -p icmp --icmp-type 0  -m conntrack --ctstate NEW -j ACCEPT
-A INPUT -p icmp --icmp-type 3  -m conntrack --ctstate NEW -j ACCEPT
-A INPUT -p icmp --icmp-type 8  -m conntrack --ctstate NEW -j ICMPFLOOD
-A INPUT -p icmp --icmp-type 11 -m conntrack --ctstate NEW -j ACCEPT

# Do not log packets that are going to ports used by SMB 
# (Samba / Windows Sharing).
-A INPUT -p udp -m multiport --dports 135,445 -j DROP
-A INPUT -p udp --dport 137:139 -j DROP
-A INPUT -p udp --sport 137 --dport 1024:65535 -j DROP
-A INPUT -p tcp -m multiport --dports 135,139,445 -j DROP

# Do not log packets that are going to port used by UPnP protocol.
-A INPUT -p udp --dport 1900 -j DROP

# Do not log late replies from nameservers.
-A INPUT -p udp --sport 53 -j DROP

# Good practise is to explicately reject AUTH traffic so that it fails fast.
-A INPUT -p tcp --dport 113 --syn -m conntrack --ctstate NEW -j REJECT --reject-with tcp-reset

# Prevent DOS by filling log files.
-A INPUT -m limit --limit 1/second --limit-burst 100 -j LOG --log-prefix "iptables[DOS]: "

COMMIT

-A INPUT ANY ANY DROP
-A OUTPUT ANY ANY DROP


###############################################################################
# 4. HOST SPECIFIC NAT RULES                                                  #
#                                                                             #
# Uncomment this section if you want to use NAT table, e.g. for port          #
# forwarding, redirect, masquerade...                                         #
###############################################################################

#*nat

# Base policy
#:PREROUTING ACCEPT [0:0]
#:POSTROUTING ACCEPT [0:0]
#:OUTPUT ACCEPT [0:0]

# Redirect port 21 to local port 2121
#-A PREROUTING -i eth0 -p tcp --dport 21 -j REDIRECT --to-port 2121

# Forward port 8080 to port 80 on host 192.168.1.10
#-A PREROUTING -i eth0 -p tcp --dport 8080 -j DNAT --to-destination 192.168.1.10:80

#COMMIT