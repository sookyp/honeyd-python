#!/bin/bash

set -e
set -x

if [ $# -ne 2 ]; then
    echo "Wrong number of arguments supplied."
    echo "Usage: $0 <server_url> <deploy_key>"
    exit 1
fi

server_url=$1
deploy_key=$2

wget $server_url/static/registration.txt -O registration.sh
chmod 755 registration.sh
. ./registration.sh $server_url $deploy_key "honeyd-python"

if  [ ! -f /usr/local/bin/python2.7 ]; then
    # install python
    wget --no-check-certificate https://www.python.org/ftp/python/2.7.6/Python-2.7.6.tar.xz
    tar xf Python-2.7.6.tar.xz
    cd Python-2.7.6
    ./configure --prefix=/usr/local
    make && make install
fi

if  [ ! -f /usr/local/bin/pip2.7 ]; then
    #install pip
    wget https://bootstrap.pypa.io/ez_setup.py
    /usr/local/bin/python2.7 ./ez_setup.py install
    /usr/local/bin/easy_install-2.7 pip
    #install virtualenv
    /usr/local/bin/pip2.7 install virtualenv
fi

# install requirements
if [ -f /etc/redhat-release ] || [ -f /etc/centos-release ]; then
    yum -y update
    yum -y install git farpd mysql-server mysql-devel python-devel python-setuptools MYSQLdb-python libpcap-dev
elif [ -f /etc/debian-version ] || [ -f /etc/lsb-release ]; then
    apt-get update
    apt-get -y install git farpd mysql-server libmysqlclient-dev python-mysqldb libpcap-dev
else
    echo -e "ERROR: Not supported OS\nExiting..."
    exit -1
fi

# get network interface
INTERFACE=`ip route get 8.8.8.8 | awk '{ print $5; exit}'`

# install supoervisor
mkdir -p /etc/supervisor
mkdir -p /etc/supervisor/conf.d
/usr/local/bin/pip2.7 install supervisor

HONEYD_HOME=/opt/honeyd-python
mkdir -p $HONEYD_HOME
# git clone https://github.com/sookyp/honeyd-python.git $HONEYD_HOME
git clone https://github.com/sookyp/honeyd-python.git --branch development $HONEYD_HOME
cd $HONEYD_HOME
virtualenv env
source env/bin/activate

/usr/local/bin/pip2.7 install -r requirements.txt

# setup hpfeeds config
cat > $HONEYD_HOME/honeyd/templates/honeyd.cfg <<EOF
[hpfeeds]
enabled = True
host = $HPF_HOST
port = $HPF_PORT
timeout = 15
ident = $HPF_IDENT
secret = $HPF_SECRET
channels = ["honeyd.events", ]

[mysql]
enabled = False
host = localhost
port = 3306
db = honeyd
username = honeyd
passphrase = honeyd
logdevice = /tmp/mysql.sock
logsocket = dev ; logsocket = [ tcp | dev ]

[tunnel]
use_public = False ; used for testing in private network - sets the use of public ip address for tunnel interface creation
interface = enp0s3 ; used for testing in private network - sets interface facing the intermediate network
startid = 0 ; numbering of tunnel interfaces (startid+1)
subnet = 172.168.1.0/24 ; ip range used to define tunnel interfaces
urls = ["http://queryip.net/ip/",
        "http://ifconfig.me/ip",
        "http://ip.42.pl/raw",
        "http://ip.dnsexit.com",
        "http://ipecho.net/plain",
        "http://myexternalip.com/raw",
        "http://icanhazip.com/",
        "https://api.ipify.org"
        ]
EOF

# setup supervisor
# traffic interception is not active, to activate issue "-a [<IP_STRING>|<IP-RANGE>|<CIDR-SUBNET>]"
# to choose active interface for listening issue "-i <INTERFACE>"
cat > /etc/supervisor/conf.d/honeyd-python.conf <<EOF
[program:honeyd-python]
command=/usr/local/bin/python2.7 /opt/honeyd-python/honeyd.py -i $INTERFACE
directory=/opt/honeyd-python
stdout_logfile=/var/log/honeyd-python.out
stderr_logfile=/var/log/honeyd-python.err
autostart=true
autorestart=true
redirect_stderr=true
stopsignal=QUIT
EOF

supervisorctl update
