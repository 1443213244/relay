from sqlalchemy import create_engine
import logging
import pandas as pd
import iptc
import config
import schedule
import os
import time


logging.basicConfig(level = logging.INFO,format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_nat_rules():
    table = iptc.Table(iptc.Table.NAT)
    chain=iptc.easy.dump_table('nat',ipv6=False)
    info = []
    for i in chain['PREROUTING']:
        relay_ip  = i['target']['DNAT']['to-destination'].split(':')[0]
        ip = i['dst'].split('/')[0]
        sport = i['tcp'][0]['dport']
        dport = i['target']['DNAT']['to-destination'].split(':')[1]
        info.append([ip,relay_ip,sport, dport])
    rule = pd.DataFrame(info, columns=['ip','relay', 'sport', 'dport'])
    logging.info("Get local iptables rule done!")
    return rule

def get_mysql_rules():
    engine = create_engine('mysql+pymysql://'+config.dbuser+':'+config.dbpassword+'@'+config.dbhost+':'+config.dbport+'/'+config.dbname)
    sql = "select * from relay where ip='"+config.publice_ip+"' or relay='"+config.publice_ip+"'"
    try:
        df = pd.read_sql_query(sql, engine)
        rules = pd.DataFrame([df['ip'], df['relay'], df['dip'], df['sport'], df['dport']])
        logging.info("Database select done!")
        return rules.T
    except Exception as e:
        logging.error("Database connetion failed!")
        print e


def batch_add_rule(data, chain1):
    chain = iptc.Chain(iptc.Table(iptc.Table.NAT), chain1)
    for index, r in data.iterrows():
        if chain1 == 'PREROUTING':
            rule = iptc.Rule()
            rule.protocol = 'tcp'
            rule.dst = r['ip']
            match = rule.create_match('tcp')
            match.dport = r['sport']
            rule.add_match(match)
            target = rule.create_target('DNAT')
            if config.mode == 'master':
                target.to_destination = str(r['relay']+':'+r['sport'])
            else:
                target.to_destination = str(r['relay']+':'+r['dport'])
            logging.info("Relay PREROUTING %s  to %s sport %s dport %s done!" % (r['ip'], r['relay'], r['sport'],r['dport']))
        else:
            rule = iptc.Rule()
            rule.protocol = 'tcp'
            rule.dst = r['relay']
            match = rule.create_match('tcp')
            if config.mode == 'master':
                match.dport = r['sport']
            else:
                match.dport = r['dport']
            rule.add_match(match)
            target = rule.create_target('SNAT')
            target.to_source = r['ip']
            logging.info("Relay POSTROUTING %s  to %s sport %s dport %s done!" % (r['ip'], r['relay'], r['sport'],r['dport']))
        try:
            chain.insert_rule(rule)
        except Exception as e:
            print e

def add_rule(data, chain1):
    chain = iptc.Chain(iptc.Table(iptc.Table.NAT), chain1)
    if chain1 == 'PREROUTING':
        rule = iptc.Rule()
        rule.protocol = 'tcp'
        rule.dst = data['ip']
        match = rule.create_match('tcp')
        match.dport = data['sport']
        rule.add_match(match)
        target = rule.create_target('DNAT')
        if config.mode == 'master':
            target.to_destination = str(data['relay'] + ':' + data['sport'])
        else:
            target.to_destination = str(data['relay'] + ':' + data['dport'])
        logging.info(
            "Relay PREROUTING %s  to %s sport %s dport %s done!" % (data['ip'], data['relay'], data['sport'], data['dport']))
    else:
        rule = iptc.Rule()
        rule.protocol = 'tcp'
        rule.dst = data['relay']
        match = rule.create_match('tcp')
        if config.mode == 'master':
            match.dport = data['sport']
        else:
            match.dport = data['dport']
        rule.add_match(match)
        target = rule.create_target('SNAT')
        target.to_source = data['ip']
        logging.info("Relay POSTROUTING %s  to %s sport %s dport %s done!" % (data['ip'], data['relay'], data['sport'], data['dport']))
    try:
        chain.insert_rule(rule)
    except Exception as e:
        print e

def clear_rule():
    os.system('iptables -t nat -F')
    logging.info("Clear all rule done!")



def del_rule(data, chain1):
    chain = iptc.Chain(iptc.Table(iptc.Table.NAT), chain1)
    if chain1 == 'PREROUTING':
        chain = iptc.Chain(iptc.Table(iptc.Table.NAT), chain1)
        for rule in chain.rules:
            port = []
            for m in rule.matches:
                port.append(m.dport)
                ip = rule.dst.split('/')[0]
                relay_ip = rule.target.to_destination.split(':')[0]
            if  ip == data['ip'] and  relay_ip == data['relay'] and port[0] == data['sport']:

                chain.delete_rule(rule)
                logging.info("Delete relay PREROUTING %s  to %s port %s done!" % (data['ip'], data['relay'], data['dport']))
    else:
        for rule in chain.rules:
            port = []
            for m in rule.matches:
                port.append(m.dport)
                relay_ip = rule.dst.split('/')[0]
                ip = rule.target.to_source

            if relay_ip == data['relay'] and ip == data['ip'] and port[0] == data['dport']:

                chain.delete_rule(rule)
                logging.info("Delete relay POSTROUTING %s  to %s port %s done!" % (data['ip'], data['relay'], data['dport']))

def job():
    #Get iptable rules from local
    rule = get_nat_rules()
    #Get iptables rules from mysql
    data_rule = get_mysql_rules()

    #Check work mode , Prepare data
    if config.mode == 'master':
        del data_rule['dip']
        data_rule['dport'] = data_rule['sport']
    else:
        del data_rule['ip']
        data_rule.columns = ['ip', 'relay', 'sport', 'dport']

    if config.private_ip != '':
        data_rule['ip'] = data_rule['ip'].replace([config.publice_ip], config.private_ip)


    #Judge whether the program is executed for the first time
    if rule.empty and data_rule.notnull:
        batch_add_rule(data_rule, 'PREROUTING')
        batch_add_rule(data_rule, 'POSTROUTING')
    elif data_rule.empty:
        clear_rule()
    else:

        #Data Compare
        data_rule = data_rule.append(rule)
        data_rule = data_rule.drop_duplicates(subset=['ip', 'relay', 'sport', 'dport'], keep=False)
        print data_rule
        #Traverse the new data and determine the source
        for inex, i in data_rule.iterrows():
            if i['ip'] in rule.values and i['dport'] in rule.values:
                del_rule(i, 'PREROUTING')
                del_rule(i, 'POSTROUTING')
            else:
                add_rule(i, 'PREROUTING')
                add_rule(i, 'POSTROUTING')


if __name__ == '__main__':
    job()
    schedule.every(2).minutes.do(job)
    while True:
        schedule.run_pending()
    time.sleep(1)

