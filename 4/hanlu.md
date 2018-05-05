
#信息收集
## 企业域名收集

企业域名收集分两类：


    1、子域名收集
    2、兄弟域名收集

子域名是顶级域名（一级域名）的下一级，比如：mail.example.com和calendar.example.com是二级域example.com的两个子域，而example.com则是顶级域com的子域。

兄弟域名这里是指同一个邮箱所注册的所有域名。

对于收集到的兄弟域名不一定就是同一个企业的域名，但是可能性很高，非常值得尝试。

###1、子域名收集
***
**1.1 利用域传送漏洞**

如果利用域传送漏洞获取子域名是最快速最全的方式。

假设test.com的DNS服务器为192.168.5.6，并且该DNS服务器有域传送的漏洞

手工检测方法,使用dig直接请求

    dig @192.168.5.6 test.com axfr
自动检测方法，调用nmap进行扫描

    nmap --script dns-zone-transfer --script-args dns-zone-transfer.domain=test.com -p 53 -Pn 192.168.5.6
参考：[DNS 域传送漏洞](http://wiki.wooyun.org/doku.php?id=server:zone-transfer)

**1.2 爆破子域名**

如果域名没有域传送漏洞的话，可以采用最原始的爆破方式，例如尝试mail.test.com，test.test.com等等。

现已有开源工具可供爆破子域名，如：dnsmap，目录下有程序自带的爆破的子域名列表，也可以自己添加。

也可以使用白帽子写的开源工具，还可以递归爆破三级四级域名subDomainsBrute

1.3 搜索引擎

Google与Baidu爬虫可能会爬到一些域名的子域名，可以使用site语法来限定域名查看结果中的子域名。

例如Google中搜索：

    site:qq.com
常用搜索技巧

    intitle   标题关键字包含
    site      所在域
    inurl     链接包含

命令可以组合 例如

    intitle:后台
    site:qq.com
    inurl:admin
即可看到qq.com被Google收录的一些域名，可以通过程序来把所有搜到的子域名收集起来。

已有开源程序theHarvester.py可以做到。

所使用的搜索引擎除了Google之外还有bing、shodan等等，并且可以在twitter与googleplus上搜索相关企业员工。

程序为开源程序，可以自己动手改成weibo等国内社交媒体搜索。

**1.4 Spider信息**

除了利用公开的搜索引擎之外，也可以自己写爬虫爬目标企业的网站，遇到其子域名继续爬下去。

这样可以收集到所有该网站上有链接过去的子域名（和搜索引擎可能有些重复）。

**1.5 IP反查域名**

某些情况下确定一个IP为某企业之后，可以利用一些网站的域名反查接口，查询有哪些绑定在该IP上的域名。

例如：IP反查域名（在有CDN的情况下会不准确）。

这样有可能查询到相关的子域名甚至该公司的其他域名，便可获得更多寻找更多信息的机会。

**1.6 在线查询子域名的网站**
FOFA的根域名网段透视功能可以帮助我们很快的了解子域名及其ip分布情况：

    http://fofa.so/lab/ips


2、兄弟域名
***
兄弟域名这里是指：whois信息同注册邮箱域名，这种查询到的域名与企业也极可能存在关系。

这里也有接口可以查询：

[whois反查](http://whois.chinaz.com/reverse)

## 企业IP收集

企业IP的收集与域名收集是相互结合的，同样都是扩大收集信息重要的一步。

### 1、域名同C段IP
***
一般来说，一个规模比较大的互联网企业会拥有比较多IP地址，这些IP地址的分配通常也是在一个C段当中。

比如当前企业主域名为www.test.com，其IP地址为222.222.222.222

可以推测222.222.222.1-255的IP地址都为该公司IP地址，最后的确定还要根据其他的信息进行判断。

### 2、服务器指纹
***
有些企业运维在维护自己的服务器时候，喜欢打上自己的标签，例如特殊的HTTP头。

这种的可以通过shodan来进行搜索拥有同样标签的服务器。

### 3、自治系统号码
****
自治系统：autonomous system。在互联网中，一个自治系统(AS)是一个有权自主地决定在本系统中应采用何种路由协议的小型单位。这个网络单位可以是一个简单的网络也可以是一个由一个或多个普通的网络管理员来控制的网络群体，它是一个单独的可管理的网络单元（例如一所大学，一个企业或者一个公司个体）。一个自治系统有时也被称为是一个路由选择域（routing domain）。一个自治系统将会分配一个全局的唯一的16位号码，有时我们把这个号码叫做自治系统号（ASN）。

利用AS号来寻找IP的方式：先安装Jwhois

    yum install -y jwhois
执行

    whois -h asn.shadowserver.org origin 1.1.1.1
可获得ip所在企业的AS号，继续执行：

    whois -h asn.shadowserver.org prefix AS号
即可获得该as号对应网段

注：一般只有大企业才会有as号，并且一个企业可能会有多个as号。

### 4、域名txt记录(spf记录)
***
spf就是Sender Policy Framework。SPF可以防止别人伪造你来发邮件，是一个反伪造性邮件的解决方案。当你定义了你的domain name的SPF记录之后，接收邮件方会根据你的SPF记录来确定连接过来的IP地址是否被包含在SPF记录里面，如果在，则认为是一封正确的邮件，否则则认为是一封伪造的邮件。那么通常spf记录都会添加自己的一些IP段作为白名单。 比如我们看看163.com：

    ➜  ~  nslookup
    > set type=txt
    > 163.com
    Server:		114.114.114.114
    Address:	114.114.114.114#53
    
    Non-authoritative answer:
    163.com	text = "v=spf1 include:spf.163.com -all"
    > spf.163.com
    Server:		114.114.114.114
    Address:	114.114.114.114#53
    
    Non-authoritative answer:
    spf.163.com	text = "v=spf1 include:a.spf.163.com include:b.spf.163.com include:c.spf.163.com include:d.spf.163.com -all"
    
    > a.spf.163.com
    Server:		114.114.114.114
    Address:	114.114.114.114#53
    
    Non-authoritative answer:
    a.spf.163.com	text = "v=spf1 ip4:220.181.12.0/22 ip4:220.181.31.0/24 ip4:123.125.50.0/24 ip4:220.181.72.0/24 ip4:123.58.178.0/24 ip4:123.58.177.0/24 ip4:113.108.225.0/24 ip4:218.107.63.0/24 ip4:123.58.189.128/25 -all"
最后这一部分就是163的ip段。

### 5、CDN使用记录
***
通过观察网页源码内是否调用了相关例如 res.wooyuncdn.org这类的域名下资源，如有调用，多为CDN专用域名。

如：

    >ping static.wooyuncdn.org

    正在 Ping 1st.dtwscatest007.glb0.lxdns.com [110.110.110.110] 具有 32 字节的数据:
    来自 110.110.110.110 的回复: 字节=32 时间=27ms TTL=57
    来自 110.110.110.110 的回复: 字节=32 时间=29ms TTL=57
    来自 110.110.110.110 的回复: 字节=32 时间=26ms TTL=57
    来自 110.110.110.110 的回复: 字节=32 时间=26ms TTL=57
    
    110.110.110.110 的 Ping 统计信息:
        数据包: 已发送 = 4，已接收 = 4，丢失 = 0 (0% 丢失)，
    往返行程的估计时间(以毫秒为单位):
        最短 = 26ms，最长 = 29ms，平均 = 27ms
根据相应返回值，判断调用res为哪个CDN厂商，如网宿、蓝汛、加速乐等。针对相应的服务进行信息收集。

##端口服务收集
在已经获取到企业对应的IP之后，便可以对其进行端口扫描查看对应开放的服务。

###1、扫描器
***
速度相对于直接搜素引擎查询速度慢，但是更全面。

可以自己使用扫描器进行扫描开发服务，最常见的是用nmap：

nmap常用组合

快速检测一个网段中的存活主机

    nmap -sP x.x.x.x/24
从文本中读取相关IP，进行端口扫描，同时识别服务

    nmap -p80,22 -sV -iL ip.txt
只显示开放该端口的主机

    nmap -p80 --open 1.1.1.0/24
不使用反向解析,扫描80端口开放的主机，同时保存为xml文件

    nmap -n -p80 -iL ip.txt -sV --open -oX 80.xml
识别一台主机的操作系统

    nmap -O 1.1.1.1
在不检测一个存活主机的情况下，进行全端口扫描，识别服务

    nmap -Pn -p1-65535 -A -sV 1.1.1.1
扫描mysql的空口令：

    nmap -p3306 --script=mysql-empty-password.nse 192.168.5.1
暴力破解mssql的账户密码

    nmap -p1433 --script=ms-sql-brute --script-args=userdb=/var/passwd,passdb=/var/passwd 192.168.5.1
具体原理性的东西可以参考以下的文章

[NMAP 基础教程](http://drops.wooyun.org/tips/2002)

[Nmap速查手册](http://drops.wooyun.org/tips/4333)

[nmap脚本使用总结](http://drops.wooyun.org/tips/2188)

[Nmap参考指南(Man Page)](http://nmap.org/man/zh/)

快速扫描某一个端口建议使用masscan：

github地址：https://github.com/robertdavidgraham/masscan

全网扫描：

    masscan 0.0.0.0/0 -p0-65535
扫描对应IP开放的对应端口：

    masscan -p80,8000-8100 10.0.0.0/8
把扫描的信息保存：

    masscan 0.0.0.0/0 -p0-65535 -oX scan.xml
###2、搜索引擎
***
这里使用搜索引擎就不是指Google、百度，而是shodan,zoomeye和fofa。

**2.1 shodan**

基础语法: City：用于寻找位于指定城市的设备。例：

    iis city:beijing
County：用于寻找位于指定国家的设备。例：

    iis country: China
os：用于查询指定系统

    Apache os:Linux
Net：用于寻找指定ip地址和子网掩码的设备。例：

    iis net:216.0.0.0/16
Hostname：用于搜索包含指定域名的主机。例

    #误报较高
    qq hostname:.com
exp搜索地址：

    https://exploits.shodan.io/welcome
测试的例子:

查找redis:

    port:6379
也可以直接搜索，会根据banner来匹配

    redis
网络摄像头:

    Android Webcam Server -Authenticate
查找openssl版本为1.0.0服务器

    openssl/1.0.0
[Shodan搜索引擎介绍](http://drops.wooyun.org/tips/2469)

由于Shodan搜索出来的数据是之前扫描存储的，而非实时扫描，所以搜索到的结果不一定100%准确。

2.2 zoomeye(钟馗之眼)

网址:

[zoomeye](http://www.zoomeye.org/)

常用语法 组件名称:

    #组件名
    app:"Apache httpd"
    #组件版本
    ver:"2.2.16"
端口：

    #ssh的22端口
    port:22
    
操作系统:
    
    #linux操作系统
    os:linux
服务:

    #公网摄像头
    service:webcam
IP地址：

    #google的DNS
    ip:8.8.8.8
子网搜索:

    cidr:8.8.8.8/24
网站域名:

    site:google.com
关键字：

    #<meta name="Keywords">定义的页面关键词
    keywords:Nginx
描述:

    #<meta name="description">定义的页面说明
    desc:Nginx
标题:

    #页面标题，在<title>
    title:Nginx
更完整的语法手册:

[官网手册](http://www.zoomeye.org/help/manual)

常见的一些搜索组合都列在这里:

[常见组合](http://www.zoomeye.org/search/dork)

**2.3 fofa**

网址：

[fofa](http://fofa.so/)

查询语法

标题中搜索:

    title=test
http头部中搜索:

    header=linux
从html中搜索:

    host=".gov.cn"
根据IP搜索:

    ip="1.1.1"
同时支持括号和&& || !=等等，可以灵活的自由组合

常用的组件识别列表：

[常用组件识别](http://fofa.so/info/library)

网站识别：

[网站识别](http://fofa.so/search/checkapp)

常见的可利用端口

    21           ftp文件传输协议
    22           SSH远程登录协议
    23           telnet终端仿真协议
    25           smtp
    110          Pop3
    1433         Microsoft SQL Server远程端口
    3306         MySQL远程端口
    3389         win远程登入
    7500-10000   常用的web后台端口

## WEB应用收集

WEB应用的收集是建立在IP、域名以及端口所收集到的数据之上的。

每一个IP及域名对外开放的端口都可能搭建了WEB服务。

除此之外，还有以下方式扩大针对WEB应用的收集：

### 1、目录及文件扫描
***
针对开放WEB服务的端口进行常见的敏感目录以及文件扫描，这些对以后的突破都可能产生至关重要的作用。

这些敏感的目录猪猪侠已经写过相关工具，工具介绍以及设计思想可以在社区中看到：动态多线程敏感信息泄露检测工具--weakfilescan.

### 2、网络搜索
***
可以在github上通过一些关键字搜索相关企业的代码，如果该企业在github上有放公开的代码，那么可以搜索到对其代码进行分析，有的甚至会存在一些敏感账号的用户名密码，例如邮箱，svn，ftp等。

可以看社区的讨论：如何从github上找漏洞。

还可以针对一些页面的历史信息信息收集：

如果一些页面已经被修改，Google与百度之前爬过该页面，那么可以通过Google与百度的缓存查看页面原来的样子。

同时[时光倒流机](http://archive.org/web)这个网站上会保存一个网站的很多历史页面，如果有记录的话，可以看到一个网站之前采用的WEB应用。

## 企业人员信息收集

对一个企业的人员信息进行收集，可以增加对整个公司的架构以及业务组成部分的了解，可为后期提供重要的数据。

###1、大数据密码
***
这里的大数据指的是互联网上已经泄漏过的用户数据组成的数据库，里面包含大量网民的账号与密码。

这种数据泄漏针对其他公司造成的影响正在持续中，很多公司的员工使用了企业的邮箱直接在外注册账号，而是用的邮箱密码又与公司邮箱的密码完全相同，就会导致很严重的问题，这种方式是最暴力最有效的方式。

这个案例可以看乌云主站：[汽车之家信息泄露所带来的多处高危安全风险](http://wooyun.org/bugs/wooyun-2010-065887)。

### 2、公司邮箱
***
公司邮箱的收集可以使用[theHarvester.py](https://github.com/laramies/theHarvester)，或者github上搜索，或者在大数据库里搜索，甚至在收集到邮箱之后观察邮箱的特点，自己建立字典规则生成邮箱，并且根据用户名信息弱口令生成密码的字典会有相当大的威力。

案例：[企业应用安全的软肋之唯品会内网漫游（DBA系统、项目管理系统等）](http://wooyun.org/bugs/wooyun-2010-094035)

### 3、互联网ID
***
通过weibo或者其他社交应用可以搜索某个公司的人员，比如：[58同城](http://s.weibo.com/user/&work=58%25E5%2590%258C%25E5%259F%258E&Refer=SUer_box)。这样便有很大的可能搜索到相关企业员工及其互联网ID，利用这些ID通过大数据便有可能有相关的用户名密码。

这些用户名密码也可能在一些云端如evernote、baidu网盘等，保存着企业的相关敏感数据，可对后期提供重要数据。

### 4、邮件钓鱼
***
邮件钓鱼在2014年的时候发现有人发送大量的钓鱼邮件，窃取企业内部相关人员的密码。

其分析可在之前知识库上的一个文章上看到：[一起针对国内企业OA系统精心策划的大规模钓鱼攻击事件](http://drops.wooyun.org/tips/2562)

## 企业外围信息收集

有时候剑走偏锋，将外围数据进行收集和整理往往会有意想不到的效果

### 1、在线协作平台
***
有的公司是采用内部协作平台，但多数是使用成熟的在线协作平台，在进行人员收集后，对各在线平台进行尝试大数据登陆。

列举一些常见的在线协作：

1.Tower [Tower](https://tower.im/)

2.EasyPm [EasyPm](https://easypm.cn/)

3.Worktile [Worktile](https://worktile.com/)

4.Team [Team](http://team.oschina.net/)

5.云之家 [云之家](http://www.yunzhijia.com/)

其他一些英文的暂缺，待补充。

其中例如tower等登陆会提示账号存在不存在，若存在，则进一步进行尝试，登陆后可能会有大量内部文件等。

### 2、群联系
***
QQ已经拥有数亿的活跃用户，国内公司联系一般途径中也包括了QQ，在QQ群搜索，比如 乌云网 则可以尝试搜索以下内容：

a.常规名字类 乌云 乌云网 wooyun wooyun.org（会搜索到包含title和群描述的群）

b.针对类名称 乌云dev 乌云开发 乌云研发 乌云运维（针对搜索运维和研发人员）

得到群联系后，一般对群主和管理员尝试进行社工和大数据，以及对比已收集公司信息。

并可以尝试：[QQ群关系查询](https://qqqun.org/)



 

