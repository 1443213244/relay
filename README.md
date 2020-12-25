## Raly是什么?
一个通过数据库管理linux防火墙SNAT,DNAT自动转发脚本

## Raly有哪些功能？

* 数据化管理iptables规则
*  通过web前端或api接口统一管理转发数据
*  自动同步数据和本地规则对比

## 安装使用
1. 克隆源代码到linux服务器
2. cd relay
3. 执行安装脚本./install.sh
4. 修改配置文件config.py
    * publice_ip公网IP地址
    * private_ip内网IP地址，适用部分无法直接通公网转发的云服务器（阿里），通过公网转发此选项请保持默认！
    * dbhost数据库地址
    * dbuser数据库用户
    * dbport数据库端口
    * dbname数据库名称
    * dbpassword数据库密码
 * mode运行模式(maters/relay)
    * master模式，此模式转发国内IP到中转Ip。
    * relay模式，此模式转发中转IP到目标IP

 

## 有问题反馈
在使用中有任何问题，欢迎反馈给我，可以用以下联系方式跟我交流

* 邮件(1443213244#qq.com, 把#换成@)




