#!/bin/bash

yum install python-devel supervisor
pip install -r ./requirements.txt
cp ./relay.ini /etc/supervisord.d/
echo "Install done"


