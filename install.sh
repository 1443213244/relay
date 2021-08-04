#!/bin/bash
echo "首次使用正在安装运行环境"
mkdir ./data
systemctl stop firewalld.service
systemctl disable firewalld.service
yum install epel-release -y
yum install python-devel supervisor iptables-services -y
systemctl enable iptables.service
if [ $(sysctl -n net.ipv4.ip_forward) == 0 ]; then
	echo -e "net.ipv4.ip_forward=1" >>/etc/sysctl.conf
	sysctl -p >/dev/null
fi
pip install -r ./requirements.txt
cp ./relay.ini /etc/supervisord.d/
echo "Install done"
