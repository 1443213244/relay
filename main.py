# coding=utf-8
# This is a sample Python script.

import cProfile
import json
from sqlalchemy import create_engine
import schedule
import time
import pandas as pd
import hashlib
import os
import logging


logging.basicConfig(level = logging.INFO,format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
LOGGING = logging.getLogger(__name__)
PATH = os.path.dirname(os.path.realpath(__file__))
CONFIG_PATH = PATH+'/config.json'
LOCAL_RULES = PATH+'/data/local'
LATEST_RULES = PATH+'/data/latest'


def get_export_Info(fpath):
    with open(fpath,'r') as f:
        content = f.readlines()
    return content


def write_export_info(f,content):
    for i in range(len(content)):
        f.write(content[i])


def get_config(configpath):
    with open(configpath, 'r') as cnfigfile:
        config = json.load(cnfigfile)
        return config


def get_latest(config):
    user = config['dbuser']
    password = config['dbpassword']
    dbhost = config['dbhost']
    port = config['dbport']
    dbname = config['dbname']
    sqlEngine = create_engine('mysql+pymysql://'+user+':'+password+'@'+dbhost+':'+str(port)+'/'+dbname, pool_recycle=3600)
    dbConnection = sqlEngine.connect()
    sql = "select * from relay"
    frame = pd.read_sql_query(sql, dbConnection);
    pd.set_option('display.expand_frame_repr', False)
    dbConnection.close()
    return frame


def get_Local_rule():
    os.system('iptables-save -t nat > %s' %(LOCAL_RULES))


def set_relay_rules(config,relay,ipt):
    if config["mode"] == "master":
       return master_mode(config,relay,ipt)
    else:
      return  relay_mode(config,relay,ipt)



def relay_mode(config, relay, ipt):
    ipt_head = ipt[0:6]
    ipt_tail = ipt[-2:]
    with open(LATEST_RULES, 'wr') as f:
        write_export_info(f,ipt_head)
        for i in relay.index:
            if relay.loc[i, "relay"] == config["publice_ip"]:
                sport = relay.loc[i, "sport"]
                dport = relay.loc[i, "dport"]
                dip = relay.loc[i, "dip"]
                hkip = relay.loc[i, "relay"]
                f.write("-A PREROUTING -d %s/32 -p tcp -m tcp --dport %s -m tcp --dport %s -j DNAT --to-destination %s:%s\n" % (hkip, sport, sport, dip, dport))
                f.write("-A PREROUTING -d %s/32 -p udp -m udp --dport %s -m udp --dport %s -j DNAT --to-destination %s:%s\n" % (hkip, sport, sport, dip, dport))

        for i in relay.index:
            if relay.loc[i, "relay"] == config["publice_ip"]:
                sport = relay.loc[i, "sport"]
                dport = relay.loc[i, "dport"]
                dip = relay.loc[i, "dip"]
                hkip = relay.loc[i, "relay"]
                f.write("-A POSTROUTING -d %s/32 -p tcp -m tcp --dport %s -m tcp --dport %s -j SNAT --to-source %s\n" % (dip, dport, dport, hkip))
                f.write("-A POSTROUTING -d %s/32 -p udp -m udp --dport %s -m udp --dport %s -j SNAT --to-source %s\n" % (dip, dport, dport, hkip))
        write_export_info(f,ipt_tail)
        LOGGING.info("%s mode rules generation complete", config['mode'])
        return True


def master_mode(config, relay, ipt):
    ipt_head = ipt[0:6]
    ipt_tail = ipt[-2:]
    port = "10000:60000"
    ip = config['publice_ip']
    result = relay[relay['ip'].str.contains(ip, na=False)]
    sum = len(result.index)
    if sum >= 1:
        hkip =  result.loc[0,'relay']
        with open(LATEST_RULES, 'wr') as f:
            write_export_info(f,ipt_head)
            f.write("-A PREROUTING -p tcp -m tcp --dport %s -j DNAT --to-destination %s\n" %(port,hkip))
            f.write("-A PREROUTING -p udp -m udp --dport %s -j DNAT --to-destination %s\n" % (port, hkip))
            f.write("-A POSTROUTING -d %s -p udp -m udp --dport %s -j SNAT --to-source %s\n" % (hkip, port, ip))
            f.write("-A POSTROUTING -d %s -p tcp -m tcp --dport %s -j SNAT --to-source %s\n" % (hkip, port, ip))
            write_export_info(f,ipt_tail)
            LOGGING.info("%s mode rules generation complete"%(config['mode']))
            return True
    else:
        LOGGING.info("Not found ip: %s", ip)
        return False


def compare_hash(hashvalue1, hashvalue2):
    result = False
    if hashvalue1 == hashvalue2:
        result = True
    return result


def file_hash(fpath):
    file = fpath # Location of the file (can be set a different way)
    BLOCK_SIZE = 65536  # The size of each read from the file

    file_hash = hashlib.sha256()  # Create the hash object, can use something other than `.sha256()` if you wish
    with open(file, 'rb') as f:  # Open the file to read it's bytes
        fb = f.read(BLOCK_SIZE)  # Read from the file. Take in the amount declared above
        while len(fb) > 0:  # While there is still data being read from the file
            file_hash.update(fb)  # Update the hash
            fb = f.read(BLOCK_SIZE)  # Read the next block from the file

    return file_hash.hexdigest()


def worker():
    config = get_config(CONFIG_PATH)
    get_Local_rule()
    ipt = get_export_Info(LOCAL_RULES)
    relays = get_latest(config)
    if set_relay_rules(config,relays, ipt):
        datahash = file_hash(LATEST_RULES);
        localhash = file_hash(LOCAL_RULES);
        if compare_hash(datahash, localhash) == False:
            print datahash,localhash
            os.system("iptables-restore < %s" %(LATEST_RULES))
            LOGGING.info("Update rules in %s mode!", config['mode'])
    else:
        LOGGING.info("%s mode no need to update!" ,config['mode'])


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    worker()
    # cProfile.run('worker(config)')
    schedule.every(1).minutes.do(worker)
    while True:
         schedule.run_pending()






