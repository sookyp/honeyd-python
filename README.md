# Honeyd-python
---

Honeyd-python is a low-interaction honeypot implementation based on the core principles of [Honeyd](http://www.honeyd.org/) honeypot. The honeypot allows a single host machine to claim unused IP addresses on LAN and simulate a virtual network of honeypots. The virtual honeypots can be configured to emulate the network stack of an operating system from [Nmap's OS detection database](https://nmap.org/book/nmap-os-db.html). Honeyd-python can redirect attacks to remote honeypots via network tunneling. Honeyd-python provides basic attack data statistics on a web server accessible at ``localhost:8080``.

### INSTALLATION
---

Honeyd-python supports integration into [Modern Honey Network](https://github.com/threatstream/mhn), the required files can be located in ``deploy/``. The honeypot supports Ubuntu 16.04 LTS and CentOS 7 distributions.

In case Modern Honey Network integration is not desired, then
1. Install pip2.7:
```
wget https://bootstrap.pypa.io/ez_setup.py
/usr/local/bin/python2.7 ./ez_setup.py install
/usr/local/bin/easy_install-2.7 pip
```
2. Install dependencies (CentOS 7):
```
wget http://repo.mysql.com/mysql-community-release-el7-5.noarch.rpm
rpm -ivh mysql-community-release-el7-5.noarch.rpm
yum -y update
yum -y install git mysql-server mysql-devel python-devel python-setuptools MySQL-python libpcap-devel tkinter tk-devel
```
2. Install dependencies (Ubuntu 16.04 LTS):
```
apt-get -y install git farpd mysql-server libmysqlclient-dev python-mysqldb libpcap-dev python-tk
```
3. Through pip2.7 install requirements from repository:
```
pip2.7 install -r requirements.txt
```

### CONFIGURATION
---
Honeyd-python's logging and tunnel creation can be configured in ``honeyd/templates/honeyd.cfg``:
```ini
[hpfeeds]
; section defines the settings for HPfeeds logging
enabled  = { True | False }
; enable or disable HPfeeds logging
host     = <HPfeeds-server>
; access location of the HPfeeds broker
port     = <integer>
; access port that the HPfeeds broker listens on
timeout  = <integer>
; connection socket timeout in seconds
ident    = <identification>
; authentication id
secret   = <secret>
; authentication secret
channels = [list-of-channels, ]
; list of logging channels

[mysql]
; section defines the settings for MySQL logging
enabled    = { True | False }
; enable or disable MySQL logging
host       = <mysql-server>
; access location of the MySQL server
port       = <integer>
; access port that the MySQL server listens on
db         = <database-name>
; name of the database provided for logging
username   = <db-login-name>
; username for login to the particular database
passphrase = <db-login-passwd>
; passphrase for login to the particular database
logsocket  = { tcp | dev }
; type of the connection socket
logdevice  = <path-to-socket>
; path to device socket

[tunnel]
; section defines the tunnel creation for proxy functionality
use_public = { True | False }
; enable or disable the use of public IP address for tunnel interface creation
interface  = <interface>
; name of the interface facing the intermediate network
urls       = [list-of-urls, ]
; list of URLs used for obtaining public IP address
start_id   = <integer>
; starting number for tunnel interface identification
subnet     = <CIDR-subnet>
; IP range is used to define the local IPs for the tunnel interfaces
```

The simulated virtual network can be configured in ``honeyd/templates/network.xml``:
```xml
<network_configuration>
<!--defines the start and end of the configuration file, required element-->
  <device_information>
  <!--defines the behavior of devices and their assigned IPs, required element, can be empty-->
    <device>
    <!--defines the start and end of a device definition-->
      <name> STRING </name>
      <!--defines the name of the device for easier identification, required element-->
      <personality> STRING </personality>
      <!--defines the name of the Nmap OS fingerprint the device runs on, required element, STRING has to be an exact match-->
      <action tcp="ACTION" udp="ACTION" icmp="ACTION"/>
      <!--defines the default bahavior of ports for that device, required element, ACTION can be [open, closed, filtered, block, proxy <ip>:{gre|ipip}]-->
      <service_list>
      <!--defines more granular configuration of individual ports, optional element-->
        <service protocol="PROTO" port="INTEGER" execute="ACTION"/>
        <!--PROTO can be [tcp, udp, icmp], ACTION can be [open, closed, filtered, bloxk, proxy <ip>:{gre|ipip}, SCRIPT], SCRIPT can be any command or script that can be invoked from shell-->
      </service_list>
      <bind_list>
      <!--defines the list of IPs the device occupies-->
        <bind ip="IP-STRING"/>
        <!--IP-STRING has to be in format of a valid IPv4 address-->
      </bind_list>
    </device>
  </device_information>
  <routing_information>
  <!--defines the connections between the routers in the network, required element, can be empty-->
    <router ip="IP-STRING" subnet="SUBNET-STRING" entry="BOOLEAN"/>
    <!--defines the start and end of a router definition, 'ip' defines the address of the router, 'subnet' defines the address range the router can possibly reach, 'entry' defines the role of the router-->
    <!--IP-STRING has to be in a format of a valid IPv4 address, SUBNET-STRING has to be in a format of a valid CIDR subnet notation-->
      <connect>IP-STRING</connect>
      <!--defines direct connection between individual routers-->
      <link>IP-SUBNET</link>
      <!--defines a subnet where the router has direct links-->
    </router>
  </routing_information>
  <external>
  <!--defines physical machines connected to the NIC-->
    <bind ip="IP-STRING" interface="STRING"/>
    <!--defines connections between IP addresses in the network and the NIC interfaces-->
  </external>
</network_configuration>
```

### USAGE
---

Honeyd-python supports the following flags:
* -v, --verbose : Enables logging of debug messages
* -l, --logfile : Set logfile name
* -n, --network : Set network configuration file name
* -c, --config : Set honeypot configuration file name
* -i, --interface : Set interface name for listening
* -a, --address : Claim addresses matching the IP range
* -o, --os-fingerprint : Set nmap-os-db file location
* -m, --mac-prefix : Set nmap-mac-prefixes file location

Example usage of Honeyd-python for the given sample configuration:
* with active traffic interception:  
``# sudo python2.7 honeyd.py -i enp0s3 -a 10.66.0.0/16``
* without active interception traffic has to be routed to the honeypot (currently required for CentOS 7):  
``# sudo python2.7 honeyd.py -i enp0s3``

### LICENSE
---
Licensed under the Apache License, Version 2.0. You may obtain a copy of the License [here](http://www.apache.org/licenses/LICENSE-2.0).