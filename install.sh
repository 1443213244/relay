#!/bin/bash

yum install epel-release python-devel supervisor
pip install -r ./requirements.txt
cp ./relay.ini /etc/supervisord.d/
echo "Install done"


