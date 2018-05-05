#逻辑漏洞
##用户体系

现在的互联网公司几乎都有自己的用户体系，而这套用户体系当中可能存在很多问题。

在此用乌云主站上已经报过的相关漏洞总结一下，这个体系当中出现的林林总总的问题：

**1、越权操作**

---
上面说过了只要对数据库进行增、删、改、查询的情况都可能存在越权。我们来看一般我们在web应用开发时操作数据库常会出现的一般语句：

增加：

	insert into tablename values(一些字段) where userid/username=12345/用户名 
参考例子：[爱拍越权漏洞及设计不合理漏洞大礼包（妹子哭了）](http://www.wooyun.org/bugs/wooyun-2010-033542)

删除：

	delete from tablename where id=123 
参考例子：[百度创意专家某功能平行权限漏洞（可删除他人素材）](http://www.wooyun.org/bugs/wooyun-2010-039358)

更改：

	update 一些字段 tablename set 一些字段 where userid/username=12345/用户名 
参考例子：[搜狐白社会任意用户信息修改漏洞](http://www.wooyun.org/bugs/wooyun-2010-036411)

查询：

	select * from tablename where id=12345 
参考例子：[Like团用户信息泄露+越权漏洞（可获取大量用户住址联系信息）](http://www.wooyun.org/bugs/wooyun-2010-033748)

大家可以看到，以上语句都涉及where，而后面的userid或username即是越权的突破口。在操作数据库时功能请求中往往会带着一些参数来用于辨别信息的唯一值。而这些参数就是我们越权时需要注意的。

在web开发中判断用户身份的字段往往是不会在客户端传递的。用户登录系统后，开发人员一般会创建一个session来保存用户名。当用户在查看、修改个人信息等需要判定用户身份时，就直接从session中获取，而不会在客户端传递，也就避免了篡改。但若出现从客户端传递的话，那么就必须要有一步权限验证的要求了。所以在测试越权时要用抓包工具截获请求，细览下可能存在辨别信息的唯一值，来进行测试。这里要说一点，传输的参数并不一定在请求参数中，也有可能存在链接等位置。如：

[虾米网送娃娃漏洞（平行权限漏洞）](http://www.wooyun.org/bugs/wooyun-2010-031826)

**2、cookie验证问题**

---
一些网站对于用户是否成功登录不是看用户名与密码是否与数据库里面的匹配，而是看cookies是否为空或session是否为true。这样的问题的假设就是开发者认为用户能够登录，那么cookies就不会为空或session就不会为false。但是逻辑缺陷很明显，那么只要能知道用户ID，然后构造一个cookies或让session值为true就可以绕过这样的认证了。

参考例子：WooYun: [益云广告平台任意帐号登录](http://www.wooyun.org/bugs/wooyun-2014-051424)

**3、密码重置流程**

---
密码找回逻辑测试一般流程

首先尝试正常密码找回流程，选择不同找回方式，记录所有数据包
分析数据包，找到敏感部分
分析后台找回机制所采用的验证手段
修改数据包验证推测
***3.1 用户凭证暴力破解***

四位或者六位的纯数字 例子

[当当网任意用户密码修改漏洞](http://www.wooyun.org/bugs/wooyun-2012-011833)

[微信任意用户密码修改漏洞](http://www.wooyun.org/bugs/wooyun-2012-011720)

***3.2 返回凭证***

url返回验证码及token 例子

[走秀网秀团任意密码修改缺陷](http://www.wooyun.org/bugs/wooyun-2012-05630)

[天天网任意账户密码重置（二）](http://www.wooyun.org/bugs/wooyun-2010-058210)

***3.3 密码找回凭证在页面中***

通过密保问题找回密码 例子

[sohu邮箱任意用户密码重置](http://www.wooyun.org/bugs/wooyun-2012-04728)

***3.4 返回短信验证码***

例子

[新浪某站任意用户密码修改（验证码与取回逻辑设计不当）](http://www.wooyun.org/bugs/wooyun-2010-085124)

***3.5 邮箱弱token***

时间戳的md5 例子

[奇虎360任意用户密码修改漏洞](http://www.wooyun.org/bugs/wooyun-2012-08333)

***3.6 用户名 & 服务器时间***

[中兴某网站任意用户密码重置漏洞（经典设计缺陷案例）](http://www.wooyun.org/bugs/wooyun-2015-090226)

***3.7 用户凭证有效性***

短信验证码 例子

[OPPO手机重置任意账户密码（3）](http://www.wooyun.org/bugs/wooyun-2010-053349)

[第二次重置OPPO手机官网任意账户密码（秒改）](http://www.wooyun.org/bugs/wooyun-2010-053079)

[OPPO修改任意帐号密码](http://www.wooyun.org/bugs/wooyun-2010-020032)

***3.8 邮箱token***

例子

[身份通任意密码修改-泄漏大量公民信息](http://www.wooyun.org/bugs/wooyun-2012-012572)

***3.9 重置密码token***

例子

[魅族的账号系统内存在漏洞可导致任意账户的密码重置](http://www.wooyun.org/bugs/wooyun-2010-078208)

***3.10 重新绑定***

手机绑定 例子

[网易邮箱可直接修改其他用户密码](http://www.wooyun.org/bugs/wooyun-2012-08307)

[12308可修改任意用户密码](http://www.wooyun.org/bugs/wooyun-2010-081467)

***3.11 邮箱绑定***

例子

[某彩票设计缺陷可修改任意用户密码](http://www.wooyun.org/bugs/wooyun-2015-092319)

[中国工控网任意用户密码重置漏洞](http://www.wooyun.org/bugs/wooyun-2010-086726)

***3.12 服务器验证***

最终提交步骤 例子

[携程旅行网任意老板密码修改(庆在wooyun第100洞)](http://www.wooyun.org/bugs/wooyun-2013-018263)

***3.13 服务器验证可控内容***

例子

[AA拼车网之任意密码找回2](http://www.wooyun.org/bugs/wooyun-2014-080278)

[四川我要去哪517旅行网重置任意账号密码漏洞](http://www.wooyun.org/bugs/wooyun-2010-082582)

***3.14 服务器验证验证逻辑为空***

例子

[某政企使用邮件系统疑似存在通用设计问题](http://www.wooyun.org/bugs/wooyun-2015-088927)

***3.15 用户身份验证***

账号与手机号码的绑定

[上海电信通行证任意密码重置](http://www.wooyun.org/bugs/wooyun-2014-075941)

***3.16 账号与邮箱账号的绑定***

例子

[魅族的账号系统内存在漏洞可导致任意账户的密码重置](http://www.wooyun.org/bugs/wooyun-2010-078208)

[和讯网修改任意用户密码漏洞](http://www.wooyun.org/bugs/wooyun-2015-091216)

***3.17 找回步骤***

跳过验证步骤、找回方式，直接到设置新密码页面 例子

[OPPO手机同步密码随意修改，短信通讯录随意查看](http://www.wooyun.org/bugs/wooyun-2010-042404)

[中国电信某IDC机房信息安全管理系统设计缺陷致使系统沦陷](http://www.wooyun.org/bugs/wooyun-2015-098765)

***3.18 本地验证***

在本地验证服务器的返回信息，确定是否执行重置密码，但是其返回信息是可控的内容，或者可以得到的内容 例子

[看我如何重置乐峰网供应商管理系统任意用户密码（管理员已被重置）](http://www.wooyun.org/bugs/wooyun-2010-083035)

[oppo重置任意用户密码漏洞(4)](http://www.wooyun.org/bugs/wooyun-2014-069987)

***3.19 发送短信等验证信息的动作在本地进行，可以通过修改返回包进行控制***

例子

[OPPO修改任意帐号密码-3](http://www.wooyun.org/bugs/wooyun-2010-020532)

[OPPO修改任意帐号密码-2](http://www.wooyun.org/bugs/wooyun-2010-020425)

***3.20 注入***

在找回密码处存在注入漏洞 例子

[用友人力资源管理软件（e-HR）另一处SQL注入漏洞（通杀所有版本）](http://www.wooyun.org/bugs/wooyun-2010-068060)

***3.21 Token生成***

token生成可控 例子

[天天网任意账号密码重置(非暴力温柔修改)](http://www.wooyun.org/bugs/wooyun-2015-094242)

[天天网再一次重置任意账号密码(依旧非暴力)](http://www.wooyun.org/bugs/wooyun-2015-095729)

***3.22 注册覆盖***

注册重复的用户名 例子

[中铁快运奇葩方式重置任意用户密码(admin用户演示)](http://www.wooyun.org/bugs/wooyun-2010-088708)

***3.23 session覆盖***

例子

[聚美优品任意修改用户密码(非爆破)](http://www.wooyun.org/bugs/wooyun-2014-085843)


##在线支付

**1、漏洞简介**

---
　　随着网民越来越习惯于网上购物，出现了越来越多的电商网站，在线交易平台等。 其中必然涉及在线支付的流程，而这里面存在很多的逻辑问题。 由于这里涉及到金钱，如果设计不当，很有可能产生诸如0元购买商品之类的严重漏洞。

**2、漏洞成因**

---
***支付过程中可直接修改数据包中的支付金额***

　　这种漏洞是支付漏洞中最常见的。 开发人员为了方便，直接在支付的关键步骤数据包中直接传递需要支付的金额。 而这种金额后端没有做校验，传递过程中也没有做签名，导致可以随意篡改金额提交。

***没有对购买数量进行限制***

　　产生的原因是开发人员没有对购买的数量参数进行严格的限制。 这种同样是数量的参数没有做签名，导致可随意修改，经典的修改方式就是改成负数。 当购买的数量是一个负数时，总额的算法仍然是“购买数量x单价=总价”。 所以这样就会导致有一个负数的需支付金额。 若支付成功，则可能导致购买到了一个负数数量的产品，并有可能返还相应的积分/金币到你的账户上。

也有将数量改成一个超大的数。结果可能导致商品数量或者支付的金额超过一定数值而归0。

***请求重放***

　　未对订单唯一性进行验证，导致购买商品成功后，重放其中请求，可以使购买商品一直增加。

***其他参数干扰***

　　由于对商品价格，数量等以外的其它会影响最终金额参数(如：运费)缺乏验证导致最终金额可被控制。

**3、漏洞检测及利用**

---
***检测方法***

无通用的检测方法

***利用***

突破限制超量购买限量商品。

　　低价、免费购买付费商品。部分漏洞甚至可在购买商品过程中获得金钱、积分等利益。

**4、实际案例**

---
***支付过程中可直接修改数据包中的支付金额***

[必胜客宅急送支付表单伪造金额](http://www.wooyun.org/bugs/wooyun-2012-05503)

[肯德基宅急送支付表单伪造金额](http://www.wooyun.org/bugs/wooyun-2012-05444)

[新浪微号存在支付绕过漏洞](http://www.wooyun.org/bugs/wooyun-2012-05316)

***没有对购买数量进行限制***

[115网盘存在支付绕过](http://www.wooyun.org/bugs/wooyun-2012-05353)

[国美网上商城支付漏洞1元订购Iphone 4S！](http://www.wooyun.org/bugs/wooyun-2012-07471)

[m1905电影网存在严重支付漏洞](http://www.wooyun.org/bugs/wooyun-2012-06708)

***请求重放***

[豆丁网购买豆元后可以将豆元倍增](http://www.wooyun.org/bugs/wooyun-2012-05173)

[阿里云0元订单，服务器随便买](http://www.wooyun.org/bugs/wooyun-2011-03009)

***私密泄漏***

[爱贷网高隐匿任意金额充值实战￥0成本从充值到提现全过程回放](http://www.wooyun.org/bugs/wooyun-2010-0104034)

***其他参数干扰***

[新东方逻辑支付漏洞](http://www.wooyun.org/bugs/wooyun-2013-019761)

**5、漏洞修复**

--
对传递的金钱，数量等对最后支付金额会产生影响的所有参数做签名。并且注意签名算法不可被猜测到。使被修改过的数据无法通过验证。
对重要的参数进行校检和有效性验证。
注意验证订单的唯一性，防止重放攻击。


##顺序执行

**1、概述**

---
  所谓的顺序执行 指的就是某一个逻辑流程中，按照第一步、第二步、第三步这种模式进行一步一步的验证，有顺序的执行逻辑的过程。 那么如果整个执行过程中的权限控制不够严格的话，就容易产生漏洞。下面说说常见的顺序执行漏洞。

**2、常见的顺序执行漏洞**

---
***2.1 密码找回的顺序执行***

这种漏洞还是比较常见的，具体流程是这样子。

	1 填写用户名进入下一步
	2 给指定的邮箱或者手机号发url或者短信进行校验
	3 根据邮箱的url或者手机短信进行验证后进入重置密码界面
	4 成功修改重置密码
  整个环节中，如果对4的前提过程中验证不够严格，就会导致执行1后直接跳过2和3来执行4这一步，从而导致任意用户密码重置漏洞！

实例：[http://wooyun.org/bugs/wooyun-2010-070708](http://wooyun.org/bugs/wooyun-2010-070708)

***2.2 支付环节的顺序执行***

一般支付环节的数序是这样子

	1 下单
	2 确定订单信息
	3 支付订单
	4 支付成功
  如果在1或者2过程中，对于正负数没有严格验证的话，那么就可以通过数量输入负数，或者修改价格实现低价购买或者刷钱，不过这种不在本次讨论范围，故这里跳过。 这里说的顺序执行，如果在4的这一步，没有对前面1、2和3验证严格的话，那么就可以直接跳过前面3步，直接进入4，然后成功支付。

实例：[http://wooyun.org/bugs/wooyun-2010-042370](http://wooyun.org/bugs/wooyun-2010-042370)

***3 登录验证的顺序执行***

  有的厂商的登录设计是这样，在登录的时候将页面验证码和用户名、密码分开进行了验证。如果验证码正确，进行第二个请求验证帐号和密码，如果验证码错误，直接对用户名和密码就不再进行验证。这种顺序逻辑，如果直接对用户名和密码验证的请求进行爆破，就可以实现扫号、暴力破解的目的。

实例：[http://wooyun.org/bugs/wooyun-2010-0115492](http://wooyun.org/bugs/wooyun-2010-0115492)

**3、漏洞检测方法**

---
  这种漏洞的检测方法很简单，就是直接对每一步都进行抓包，然后尝试是否可以跳过前面的验证，直接对结果请求进行成功请求即可。

**4、修补措施**

---
  对每一步的请求的验证，都要严格，而且要以上一步的结果为依据。可以给请求参数中加入一个随机的key，贯穿验证的始终。
  
  
  
##本地限制 抓包绕过

**1、背景介绍**

---
   出于各种原因，通常情况下我们需要对用户在网页中的各种操作及输入进行限制，以促使用户的输入符合预期。如限制用户输入邮箱地址，手机号码，限制用户上传的文件类型，要求用户输入正确的验证码等等。

为了实现这个目的，开发人员一般都会通过在网页中插入特殊的javascript脚本来达到限制用户的输入的作用。但是部分开发人员过分依赖和相信在前端插入javascript脚本的方法，忽视了在后端对用户输入的处理，导致漏洞。

**2、漏洞成因**

---
在服务器后端缺乏对于用户输入的处理和限制或者处理和限制不严格。

**3、漏洞扫描及利用**

---
漏洞扫描

无通用的扫描方法

漏洞利用

本地限制的绕过方法通常有以下几种:

	使用burpsuite等工具代理修改浏览器传输的数据包，或者使用wireshark等工具抓取浏览器的数据包再改包重放（最常见的方法）
	禁用浏览器的javascript使本地限制脚本失效
	使用浏览器的控制台修改网页和代码使本地限制失效
	使用浏览器插件对网页进行修改或者对数据包进行修改使限制失效

**4、漏洞危害**

---
本地限制不严多数情况下危害较小，但某些情况下影响重大：

文件上传限制不严可导致用户上传任意文件，如果带有恶意代码的可执行文件被上传到服务器上可以导致服务器被入侵。
验证码限制被绕过可以导致用户密码被爆破或者撞库，可以导致用户账户被盗取。

**5、实际案例**

---
***绕过文件上传限制***

[联想某分站文件上传绕过可获得root权限（可导致内部员工信息泄漏）](http://www.wooyun.org/bugs/wooyun-2010-027438)

[大地数字影院本地验证上传任意文件，已shell大量vip信息泄露](http://www.wooyun.org/bugs/wooyun-2010-020471)

[河北、天津、山西电信商务领航绕过javascript本地验证上传漏洞](http://www.wooyun.org/bugs/wooyun-2010-020471)

***验证码绕过***

[傲游游戏某接口设计不当可绕过验证码暴力破解用户可撞库#2（洗号神马的你懂得）](http://wooyun.org/bugs/wooyun-2010-095639)

[PPTV又又又一接口设计不当导致可暴力破解可撞库#4（账号主站通用+验证码绕过）](http://wooyun.org/bugs/wooyun-2010-092753)

**6、修复方案**

---
在服务器的后端对用户数输入进行严格限制并对用户权限进行验证。

##OAuth授权

**1、相关背景介绍**

---
OAuth（开放授权）是一个开放标准，允许用户让第三方应用访问该用户在某一网站上存储的私密的资源（如照片，视频，联系人列表），而无需将用户名和密码提供给第三方应用。

OAuth允许用户提供一个令牌，而不是用户名和密码来访问他们存放在特定服务提供者的数据。每一个令牌授权一个特定的网站（例如，视频编辑网站)在特定的时段（例如，接下来的2小时内）内访问特定的资源（例如仅仅是某一相册中的视频）。这样，OAuth让用户可以授权第三方网站访问他们存储在另外服务提供者的某些特定信息，而非所有内容。

**2、成因**

---
就OAuth协议本身而言是相对比较严谨的，目前常见的OAuth相关漏洞多为开发者在部署、使用OAuth时的疏忽或不规范所致。

**3、攻击方式及危害**
***授权方：***

认证服务器redirect_uri未校验

若认证服务器不对申请授权请求中的redirect_uri参数进行验证，攻击者则可以伪造一个redirect_uri为自己可控地址的请求，通过XSS或CSRF等手段让受害人访问，当获得授权后认证服务器将会带着授权码重定向到攻击者的地址，从而导致授权码泄露。

利用浏览器的一些特性绕过认证服务器对redirect_uri的校验

很多浏览器会将“`\`”转换成“`/`”，如攻击者将redirect_uri改为`www.b.com\.www.a.com`，认证服务器认为这个地址是`www.a.com`下的一个子域名，而浏览器经过转换后，实际跳转到的地址则是`www.b.com/.www.a.com`（即www.b.com下的一个地址），成功绕过了redirect_uri校验。相关漏洞如：[WooYun-2014-59403](http://www.wooyun.org/bugs/wooyun-2014-059403)。

safari浏览器会对url中的full width字符自动转化为常见的字符，攻击者通过将“`/`“等字符替换成full width字符后即可通过上述方法绕过redirect_uri校验。相关漏洞如：[WooYun-2014-59639](http://www.wooyun.org/bugs/wooyun-2014-059639)。

此外，还可以通过在URL中加入的“`@”`字符绕过redirect_uri校验。相关漏洞如：[WooYun-2014-59676](http://www.wooyun.org/bugs/wooyun-2014-059676)。

***应用方***：

***利用CSRF进行授权劫持***

因OAuth授权过程中的链接及参数都是已知的，所以攻击者可以预先构造相应链接诱导用户点击，点击后（已登录状态）的用户则在不知情的情况下对某一第三方应用进行了授权。

***利用URL跳转漏洞或引用外部图片等方式通过referer将code带到攻击者的域名***

如果应用方网站可以进行任意的URL跳转或引用的外部的图片等资源，攻击者则可利用跳转到自己网站或请求自己网站资源过程中的referer信息获取token。

**4、实际案例**

---
PiaCa：[WooYun-2012-05804：人人网Oauth 2.0授权可导致用户access_token泄露](http://www.wooyun.org/bugs/wooyun-2012-05804)

由于简化模式（implicit grant type）的授权请求仅需client_id和redirect_uri，人人网并没有对redirect_uri进行严格检查，导致攻击者可以利用redirect_uri域下的xss漏洞得到用户token。

p.z：[WooYun-2014-59403：腾讯OAuth平台redirect_uri过滤不严可能导致用户信息遭窃取](http://www.wooyun.org/bugs/wooyun-2014-059403)

由于绝大多数浏览器会将\转化为/，所以攻击者成功利用full width字符绕过redirect_uri校验。

p.z：[WooYun-2014-59639：腾讯OAuth平台redirect_uri过滤不严可能导致用户信息遭窃取（三）](http://www.wooyun.org/bugs/wooyun-2014-059639)

由于safari会对url中的full width字符自动转化为常见的字符，所以攻击者成功利用full width字符绕过redirect_uri校验。

**5、修复方案**

---
***授权方：***

对于OAuth回调污染问题，应严格校验redirect_uri，在某些情况下可以考虑通过字符串比对的方式进行校验。

***应用方：***

可利用state参数进行防跨站攻击，验证302跳转回来带code参数的这个请求是否是攻击者伪造的，防止攻击者伪造请求。

对于外链攻击，可在支持HTML5浏览器的环境下给所有外部链接加上`rel=noreferrer`属性；对于老版本IE的处理方案是利用一个HTTPS进行跳转达到抹去referer的效果。

**6、漏洞扫描与发现**

---
***授权方：***

排查对redirect_uri的域检测是否存在绕过。

***应用方：***

排查网站上是否存在URL跳转漏洞。

**7、相关其他安全问题**

---
通过OAuth从资源服务器获取数据的时候，应该注意进行相应过滤，防止从资源服务器引入危险代码导致SQLi、XSS等攻击。

**8、相关资源**

---
[OAuth 漏洞预警](http://zhuanlan.zhihu.com/wooyun/19745587)

[OAuth 2.0安全案例回顾](http://drops.wooyun.org/papers/598)

[OAuth 安全指南](http://drops.wooyun.org/papers/1989)

[解OAuth 2.0](http://www.ruanyifeng.com/blog/2014/05/oauth_2_0.html)