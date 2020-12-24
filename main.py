#coding=utf-8
from sqlalchemy import create_engine
import logging
import pandas as pd
import iptc
import config
import schedule
import time

name = "longsongpong"
schedule.every(10).minutes.do(job, name)
schedule.every().hour.do(job, name)
schedule.every().day.at("10:30").do(job, name)
schedule.every(5).to(10).days.do(job, name)
schedule.every().monday.do(job, name)
schedule.every().wednesday.at("13:15").do(job, name)

logging.basicConfig(level = logging.INFO,format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_nat_rules():
    table = iptc.Table(iptc.Table.NAT)
    chain=iptc.easy.dump_table('nat',ipv6=False)
    info = []
    for i in chain['POSTROUTING']:
        info.append([i['target']['SNAT']['to-source'],i['dst'][0:-3],i['tcp'][0]['dport']])
    rule = pd.DataFrame(info, columns=['ip','relay', 'port'])
    logging.info("Get local iptables rule done!")
    return rule


def get_mysql_rules():
    engine = create_engine('mysql+pymysql://'+config.dbuser+':'+config.dbpassword+'@'+config.dbhost+':'+config.dbport+'/'+config.dbdatase)
    sql = "select * from relay where ip='"+config.publice_ip+"'"
    try:
        df = pd.read_sql_query(sql, engine)
        rules = pd.DataFrame([df['ip'], df['relay'], df['dip'], df['port']])
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
            match.dport = r['port']
            rule.add_match(match)
            target = rule.create_target('DNAT')
            target.to_destination = str(r['relay'])
            logging.info("Relay PREROUTING %s  to %s port %s done!" % (r['ip'], r['relay'], r['port']))
        else:
            rule = iptc.Rule()
            rule.protocol = 'tcp'
            rule.dst = r['relay']
            match = rule.create_match('tcp')
            match.dport = r['port']
            rule.add_match(match)
            target = rule.create_target('SNAT')
            target.to_source = r['ip']
            logging.info("Relay POSTROUTING %s  to %s port %s done!" % (r['ip'], r['relay'], r['port']))
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
        match.dport = data['port']
        rule.add_match(match)
        target = rule.create_target('DNAT')
        target.to_destination = str(data['relay'])
        logging.info("Relay PREROUTING %s  to %s port %s done!" % (data['ip'], data['relay'], data['port']))
    else:
        rule = iptc.Rule()
        rule.protocol = 'tcp'
        rule.dst = data['relay']
        match = rule.create_match('tcp')
        match.dport = data['port']
        rule.add_match(match)
        target = rule.create_target('SNAT')
        target.to_source = data['ip']
        logging.info("Relay POSTROUTING %s  to %s port %s done!" % (data['ip'], data['relay'], data['port']))
    try:
        chain.insert_rule(rule)
    except Exception as e:
        print e

def batch_del_rule(data, chain1):
    chain = iptc.Chain(iptc.Table(iptc.Table.NAT), chain1)
    for index, r in data.iterrows():
        if chain1 == 'PREROUTING':
            for rule in chain.rules:
                if rule.dst.split('/')[0] == r.ip and rule.target.to_destination == r['relay']:
                    chain.delete_rule(rule)
                    logging.info("Delete relay PREROUTING %s  to %s port %s done!" % (r['ip'], r['relay'], r['port']))
        else:
            for rule in chain.rules:
                if rule.dst.split('/')[0] == r['relay'] and rule.target.to_source == r['ip']:
                    logging.info("Delete relay POSTROUTING %s  to %s port %s done!" % (r['ip'], r['relay'], r['port']))
                    chain.delete_rule(rule)



def del_rule(data, chain1):
    chain = iptc.Chain(iptc.Table(iptc.Table.NAT), chain1)
    if chain1 == 'PREROUTING':
        for rule in chain.rules:
            if rule.dst.split('/')[0] == data.ip and rule.target.to_destination == data['relay']:
                logging.info("Delete relay PREROUTING %s  to %s port %s done!" % (data['ip'], data['relay'], data['port']))
                chain.delete_rule(rule)
    else:
        for rule in chain.rules:
            if rule.dst.split('/')[0] == data['relay'] and rule.target.to_source == data['ip']:
                logging.info("Delete relay POSTROUTING %s  to %s port %s done!" % (data['ip'], data['relay'], data['port']))
                chain.delete_rule(rule)

def job():
    #Get iptable rules from local
    rule = get_nat_rules()
    #Get iptables rules from mysql
    data_rule = get_mysql_rules()

    #Check work mode , Prepare data
    if config.mode == 'master':
        del data_rule['dip']
    else:
        del data_rule['ip']
        data_rule.columns = ['ip', 'relay', 'port']

    if config.private_ip != '':
        data_rule['ip'] = data_rule['ip'].replace([config.publice_ip], config.private_ip)
    print data_rule

    #Judge whether the program is executed for the first time
    if rule.empty and data_rule.notnull:
        batch_add_rule(data_rule, 'PREROUTING')
        batch_add_rule(data_rule, 'POSTROUTING')
    elif data_rule.empty:
        batch_del_rule(data_rule, 'PREROUTING')
        batch_del_rule(data_rule, 'POSTROUTING')
    else:

        #Data Compare
        data_rule = data_rule.append(rule)
        data_rule = data_rule.drop_duplicates(subset=['ip', 'relay', 'port'], keep=False)


        #Traverse the new data and determine the source
        for inex, i in data_rule.iterrows():
            if i['ip'] in rule.values and i['port'] in rule.values:
                del_rule(i, 'PREROUTING')
                del_rule(i, 'POSTROUTING')
            else:
                add_rule(i, 'PREROUTING')
                add_rule(i, 'POSTROUTING')


if __name__ == '__main__':
    job()
    schedule.every(3).minutes.do(job)
    while True:
        schedule.run_pending()
    time.sleep(1)

