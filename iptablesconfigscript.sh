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
iptables -L

#	Save iptables to master config file 
#	iptables-save > /etc/iptables.up.rules

#	Activate new iptables rules
#	iptables-restore < 'absolute file path'

#	'-j ACCEPT'ing 'OUTPUT' traffic to '-d emuccdc.com' our ecomm website via '-p TCP' protocol
iptables -A OUTPUT -p tcp -d emuccdc.com -j ACCEPT


#'-j DROP'ing any 'OUTPUT' traffic on port '--dport 80' via the '-p TCP' protocol
iptables -A OUTPUT -p tcp --dport 80 -j DROP


#'-j DROP'ing any 'OUTPUT' traffic on port '--dport 443' via the '-p TCP' protocol
iptables -A OUTPUT -p tcp --dport 443 -j DROP


#	'-j ACCEPT'ing 'INPUT' traffic to address '-s 172.16.10.2' our ecomm website on port '--dport 22' via '-p TCP' protocol
iptables -A INPUT -p tcp -s 172.16.10.2 --dport 22 -j ACCEPT


#'-j DROP'ing any 'OUTPUT' traffic on range '-s 0.0.0.0/0' on port '--dport 22' via the '-p TCP' protocol
iptables -A INPUT -p tcp -s 0.0.0.0/0 --dport 22 -j DROP