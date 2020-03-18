# aws2aliyun-vpc

Amazon Web Services
Virtual Private Cloud

AWS utilizes unique identifiers to manipulate the configuration of
a VPN Connection. Each VPN Connection is assigned an identifier and is
associated with two other identifiers, namely the
Customer Gateway Identifier and Virtual Private Gateway Identifier.

Your VPN Connection ID                  : vpn-02a23e09b5d24483b
Your Virtual Private Gateway ID         : vgw-080ff142f34883b44
Your Customer Gateway ID                : cgw-09a7d8137328ee7c0


This configuration consists of two tunnels. Both tunnels must be configured on your Customer Gateway. If you are configuring your tunnels as policy-based, only a single tunnel may be up at a time. If you are configuring your tunnels as route-based, both tunnels may be up simultaneously. Please note this configuration file is intended for a route-based VPN solution.

At this time this configuration has been tested for Strongswan 5.5.1 on the Ubuntu 16.04 LTS operating system on aliyun, but may work with later versions as well. Due to an interoperational issue discovered with AWS VPN and earlier versions of Strongswan, it's not recommended to use a version prior to 5.5.1.

Aliyun ecs with trongswan 5.5.1


--------------------------------------------------------------------------------------------------------------------
IPSEC Tunnel #1
--------------------------------------------------------------------------------------------------------------------
#1: Enable Packet Forwarding and Configure the Tunnel

This configuration assumes that you already have a default Strongswan 5.5.1+ installation in place on the Ubuntu 16.04 LTS operating system (but may work with other distros as well). It is not recommended to use a Strongswan version prior to 5.5.1. Please check which version your distro's repository has by default and install the latest stable release if necessary.

1) Open /etc/sysctl.conf and uncomment the following line to enable IP packet forwarding:
   net.ipv4.ip_forward = 1

2) Apply the changes in step 1 by executing the command 'sudo sysctl -p'

3) Create a new file at /etc/ipsec.conf if doesn't already exist, and then open it. Uncomment the line "uniqueids=no" under the 'config setup' section. Append the following configuration to the end of the file:

# AWS VPN will also support AES256 and SHA256 for the "ike" (Phase 1) and "esp" (Phase 2) entries below.
# For Phase 1, AWS VPN supports DH groups 2, 14-18, 22, 23, 24. Phase 2 supports DH groups 2, 5, 14-18, 22, 23, 24
# To see Strongswan's syntax for these different values, please refer to https://wiki.strongswan.org/projects/strongswan/wiki/IKEv1CipherSuites

conn Tunnel1
	auto=start
	left=%defaultroute
	leftid=aliyun_public_ip
	right=aws_public_ip
	type=tunnel
	leftauth=psk
	rightauth=psk
	keyexchange=ikev1
	ike=aes128-sha1-modp1024
	ikelifetime=8h
	esp=aes128-sha1-modp1024
	lifetime=1h
	keyingtries=%forever
	leftsubnet=0.0.0.0/0
	rightsubnet=0.0.0.0/0
	dpddelay=10s
	dpdtimeout=30s
	dpdaction=restart
	## Please note the following line assumes you only have two tunnels in your Strongswan configuration file. This "mark" value must be unique and may need to be changed based on other entries in your configuration file.
	mark=100
	## Uncomment the following line to utilize the script from the "Automated Tunnel Healhcheck and Failover" section. Ensure that the integer after "-m" matches the "mark" value above, and <VPC CIDR> is replaced with the CIDR of your VPC
	## (e.g. 192.168.1.0/24)
	#leftupdown="/etc/ipsec.d/aws-updown.sh -ln Tunnel1 -ll 169.254.24.30/30 -lr 169.254.24.29/30 -m 100 -r <VPC CIDR>"

4) Create a new file at /etc/ipsec.secrets if it doesn't already exist, and append this line to the file (be mindful of the spacing!). This value authenticates the tunnel endpoints:
aliyun_public_ip aws_public_ip : PSK "password"

5) If you would like to configure your route-based tunnels manually, please complete the following steps #2 - #5. These steps may be omitted if you decide to follow the steps in the "Automated Tunnel Healthcheck and Failover" section of the document.  

--------------------------------------------------------------------------------
#2: Tunnel Interface Configuration

A tunnel interface is a logical interface associated with tunnel traffic. All traffic to/from the VPC will be logically transmitted and received by the tunnel interface.

1) If your device is in a VPC or behind a device performing NAT on your local network, replace <LOCAL IP> with the private IP of the device. Otherwise, use aliyun-public_ip. The "key" value below MUST match the integer you placed as the "mark" value in your configuration file.

sudo ip link add Tunnel1 type vti local aliyun_local_subnet remote aws_public_ip key 100
sudo ip addr add 169.254.24.30/30 remote 169.254.24.29/30 dev Tunnel1
sudo ip link set Tunnel1 up mtu 1419

2) Depending on how you plan to handle routing, you can optionally set up a static route pointing to your VPC for your new tunnel interface. Replace <VPC CIDR> with the CIDR of your VPC (e.g. 192.168.1.0/24):
sudo ip route add aws_local_subnet dev Tunnel1 metric 100

3) By default, Strongswan will create a routing entry in a different route table at launch. To disable this feature and use the default route table:
- Open the file /etc/strongswan.d/charon.conf
- Uncomment the line "install_routes=yes"
- Change the value of the line to "install_routes=no"

--------------------------------------------------------------------------------
#3: iptables Configuration

iptables is a program designed to act as a firewall for the Linux kernel. It can be used to set up, maintain, and inspect packet filter values entered into several different tables.

iptables rules must be set when using tunnel interfaces so the Linux kernel knows to forward and accept packets on the logical interface. The "--set-xmark" value MUST match the integer you placed as the "mark" value in your configuration file.

sudo iptables -t mangle -A FORWARD -o Tunnel1 -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
sudo iptables -t mangle -A INPUT -p esp -s aws_public_ip -d aliyun_public_ip -j MARK --set-xmark 100

--------------------------------------------------------------------------------
#4: sysctl Modifications

In order to use your tunnel interface effectively, you will need to do some additional sysctl modifications.

1) Open /etc/sysctl.conf and append the following values to the end of the file. Replace <PHYSICAL INTERFACE> with the name of the physical interface your logical tunnel interface resides on (e.g. eth0).
net.ipv4.conf.Tunnel1.rp_filter=2 #This value allows the Linux kernel to handle asymmetric routing
net.ipv4.conf.Tunnel1.disable_policy=1 #This value disables IPsec policy (SPD) for the interface
net.ipv4.conf.<PHYSICAL INTERFACE>.disable_xfrm=1 #This value disables crypto transformations on the physical interface
net.ipv4.conf.<PHYSICAL INTERFACE>.disable_policy=1 #This value disables IPsec policy (SPD) for the interface

2) Apply the changes in step 1 by executing the command 'sudo sysctl -p'

--------------------------------------------------------------------------------
#5: Persistent Configuration

Your tunnel interface is now ready for use, however if your device ever reboots the changes you've made will not persist. Complete the following steps so your changes will remain persistent after reboot.

1) Save your running iptables configuration by executing the command 'sudo iptables-save > /etc/iptables.conf'

2) Open /etc/rc.local and append the following to the end of the file, before the line 'exit 0':

ip link add Tunnel1 type vti local aliyun_local_ip  remote aws_public_ip key 100
ip addr add 169.254.24.30/30 remote 169.254.24.29/30 dev Tunnel1
ip link set Tunnel1 up mtu 1419
ip route add aws_local_subnet dev Tunnel1 metric 100
iptables-restore < /etc/iptables.conf

#5: vpc route table update &Testing
update both aws and aliyun ,then
Please use another instances instead of openswan instances to do ping 





=== DONE ===

=== HOW-TO-HA OPTIONAL ===
1) Create a new file at /etc/ipsec.d/aws-updown.sh if it doesn't already exist, and append the following script to the file:

#!/bin/bash

while [[ $# > 1 ]]; do
	case ${1} in
		-ln|--link-name)
			TUNNEL_NAME="${2}"
			TUNNEL_PHY_INTERFACE="${PLUTO_INTERFACE}"
			shift
			;;
		-ll|--link-local)
			TUNNEL_LOCAL_ADDRESS="${2}"
			TUNNEL_LOCAL_ENDPOINT="${PLUTO_ME}"
			shift
			;;
		-lr|--link-remote)
			TUNNEL_REMOTE_ADDRESS="${2}"
			TUNNEL_REMOTE_ENDPOINT="${PLUTO_PEER}"
			shift
			;;
		-m|--mark)
			TUNNEL_MARK="${2}"
			shift
			;;
		-r|--static-route)
			TUNNEL_STATIC_ROUTE="${2}"
			shift
			;;
		*)
			echo "${0}: Unknown argument \"${1}\"" >&2
			;;
	esac
	shift
done

command_exists() {
	type "$1" >&2 2>&2
}

create_interface() {
	ip link add ${TUNNEL_NAME} type vti local ${TUNNEL_LOCAL_ENDPOINT} remote ${TUNNEL_REMOTE_ENDPOINT} key ${TUNNEL_MARK}
	ip addr add ${TUNNEL_LOCAL_ADDRESS} remote ${TUNNEL_REMOTE_ADDRESS} dev ${TUNNEL_NAME}
	ip link set ${TUNNEL_NAME} up mtu 1419
}

configure_sysctl() {
	sysctl -w net.ipv4.ip_forward=1
	sysctl -w net.ipv4.conf.${TUNNEL_NAME}.rp_filter=2
	sysctl -w net.ipv4.conf.${TUNNEL_NAME}.disable_policy=1
	sysctl -w net.ipv4.conf.${TUNNEL_PHY_INTERFACE}.disable_xfrm=1
	sysctl -w net.ipv4.conf.${TUNNEL_PHY_INTERFACE}.disable_policy=1
}

add_route() {
	IFS=',' read -ra route <<< "${TUNNEL_STATIC_ROUTE}"
    	for i in "${route[@]}"; do
	    ip route add ${i} dev ${TUNNEL_NAME} metric ${TUNNEL_MARK}
	done
	iptables -t mangle -A FORWARD -o ${TUNNEL_NAME} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
	iptables -t mangle -A INPUT -p esp -s ${TUNNEL_REMOTE_ENDPOINT} -d ${TUNNEL_LOCAL_ENDPOINT} -j MARK --set-xmark ${TUNNEL_MARK}
	ip route flush table 220
}

cleanup() {
        IFS=',' read -ra route <<< "${TUNNEL_STATIC_ROUTE}"
        for i in "${route[@]}"; do
            ip route del ${i} dev ${TUNNEL_NAME} metric ${TUNNEL_MARK}
        done
	iptables -t mangle -D FORWARD -o ${TUNNEL_NAME} -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
	iptables -t mangle -D INPUT -p esp -s ${TUNNEL_REMOTE_ENDPOINT} -d ${TUNNEL_LOCAL_ENDPOINT} -j MARK --set-xmark ${TUNNEL_MARK}
	ip route flush cache
}

delete_interface() {
	ip link set ${TUNNEL_NAME} down
	ip link del ${TUNNEL_NAME}
}

# main execution starts here

command_exists ip || echo "ERROR: ip command is required to execute the script, check if you are running as root, mostly to do with path, /sbin/" >&2 2>&2
command_exists iptables || echo "ERROR: iptables command is required to execute the script, check if you are running as root, mostly to do with path, /sbin/" >&2 2>&2
command_exists sysctl || echo "ERROR: sysctl command is required to execute the script, check if you are running as root, mostly to do with path, /sbin/" >&2 2>&2

case "${PLUTO_VERB}" in
	up-client)
		create_interface
		configure_sysctl
		add_route
		;;
	down-client)
		cleanup
		delete_interface
		;;
esac

2) To make the file executable, run the command 'sudo chmod 744 /etc/ipsec.d/aws-updown.sh'

3) Open the file /etc/ipsec.conf and ensure the "leftupdown" parameter at the end of each of your 'conn' entries is uncommented. You will need to modify <VPC CIDR> to match the CIDR of your VPC (e.g. 192.168.1.0/24). Please also verify the integer value after the "-m" option matches the "mark" parameter of your configuration if you have made changes to the default values of this configuration file.

4) Restart the Strongswan daemon by executing the command 'sudo ipsec restart'

5) Check if your updown script worked properly. You can use the following commands to test if there are entries created for each of your tunnels:
- Execute 'sudo ipsec status' to ensure both of your tunnels are ESTABLISHED
- Execute 'sudo ip route' to ensure route table entires were created for each of your tunnel interfaces, and the destination is the remote VPC CIDR
- Execute 'sudo iptables -t mangle -L -n' to ensure entries were made for both of your tunnels in both the INPUT and FORWARD chains
- Execute 'ifconfig' to ensure the correct 169.254.x addresses were assigned to each end of your peer-to-peer virtual tunnel interfaces
- Attempt to ping a destination in the remote VPC from a host within your local network. If there is no response, check to see if your instance's security groups are allowing traffic and verify your settings entered above are correct once again

6) Verify failover is working properly. You can test this by blocking traffic from the remote virtual private gateway (VGW) public IPs. For example:
sudo iptables -A INPUT -s <VGW PUBLIC IP> -j DROP


  Additional Notes and Questions
  - Amazon Virtual Private Cloud Getting Started Guide:
        http://docs.amazonwebservices.com/AmazonVPC/latest/GettingStartedGuide
  - Amazon Virtual Private Cloud Network Administrator Guide:
        http://docs.amazonwebservices.com/AmazonVPC/latest/NetworkAdminGuide
  - XSL Version: 2009-07-15-1119716
# aws2aliyun-vpc
# aws2aliyun-vpc
