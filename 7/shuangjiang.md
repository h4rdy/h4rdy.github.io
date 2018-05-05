## DNS分析
### dnsdict6使用说明

**1、工具简介**
***
由gnucitizen.org开发，一款可以使用内置或指定字典的基于dnsmap的DNS枚举工具。

**2、使用方法**
***
终端直接输入“dnsdict6 -h”可以查看其相关参数用法：
    
    light@kali:~# dnsdict6 -h
    dnsdict6 v2.5 (c) 2013 by van Hauser / THC <vh@thc.org> www.thc.org
     
    Syntax: dnsdict6 [-d4] [-s|-m|-l|-x|-u] [-t THREADS] [-D] domain [dictionary-file]
     
    Enumerates a domain for DNS entries, it uses a dictionary file if supplied
    or a built-in list otherwise. This tool is based on dnsmap by gnucitizen.org.
     
    Options:
     -4      do also dump IPv4 addresses
     -t NO   specify the number of threads to use (default: 8, max: 32).
     -D      dump the selected built-in wordlist, no scanning.
     -d      display IPv6 information on NS and MX DNS domain information.
     -S      perform SRV service name guessing
     -[smlxu] choose the dictionary size by -s(mall=100), -m(edium=1419) (DEFAULT)
               -l(arge=2601), -x(treme=5886) or -u(ber=16724)
语法：dnsdict6 [-d46] [-s|-m|-l|-x] [-t THREADS] [-D] domain [dictionary-file]

参数解释：

* -4：显示ipv4
* -t：指定要使用的线程，默认线程为8，最大32
* -D：只显示字典不扫描
* -d：显示在DNS服务器上的NS、MX记录的ipv6信息
* －[smlx] 选择字典大小［内置的] -s 小型是50条 －m 中等是796条[默认] -l 大型1416条 －x 最大3211条
 
**3、使用示范**
***
查询1ight.co的DNS信息：

    light@kali:~# dnsdict6 -d46 -t 16 -d -m 1ight.co
    Starting DNS enumeration work on 1ight.co. ...
    Gathering NS and MX information...
    NS of 1ight.co. is f1g1ns1.dnspod.net. => 113.108.80.138
    NS of 1ight.co. is f1g1ns1.dnspod.net. => 111.30.132.180
    NS of 1ight.co. is f1g1ns1.dnspod.net. => 125.39.208.193
    NS of 1ight.co. is f1g1ns1.dnspod.net. => 180.153.9.189
    NS of 1ight.co. is f1g1ns1.dnspod.net. => 182.140.167.166
    NS of 1ight.co. is f1g1ns2.dnspod.net. => 115.236.137.40
    NS of 1ight.co. is f1g1ns2.dnspod.net. => 115.236.151.191
    NS of 1ight.co. is f1g1ns2.dnspod.net. => 112.90.82.194
    NS of 1ight.co. is f1g1ns2.dnspod.net. => 101.226.30.224
    NS of 1ight.co. is f1g1ns2.dnspod.net. => 182.140.167.188
    MX of 1ight.co. is mxbiz1.qq.com. => 183.60.15.245
    MX of 1ight.co. is mxbiz1.qq.com. => 183.57.48.34
    MX of 1ight.co. is mxbiz2.qq.com. => 183.60.15.245
    MX of 1ight.co. is mxbiz2.qq.com. => 183.57.48.34
     
    Starting enumerating 1ight.co. - creating 16 threads for 1419 words...
    Estimated time to completion: 1 to 1 minutes
    www.1ight.co. => 112.74.102.78
 
    Found 1 domain name and 1 unique ipv4 address for 1ight.co.
**4、相关资源**
***
[gnucitizen.org](http://www.gnucitizen.org/)

### dnsenum使用说明

**1、工具简介**
***
Dnsenum是一款非常强大的perl语言编写的多线程域名信息收集工具，它是由参与backtrack 开发项目的程序员所设计，设计者名叫Fillp (barbsie) Waeythens 。 dnsenum的目的是尽可能收集一个域的信息，它能够通过谷歌或者字典文件猜测可能存在的域名，以及对一个网段进行反向查询。它可以查询网站的主机地址信息、域名服务器、mx record（函件交换记录），在域名服务器上执行axfr请求，通过谷歌脚本得到扩展域名信息（google hacking），提取自域名并查询，计算C类地址并执行whois查询，执行反向查询，把地址段写入文件。

**2、使用方法**
***
终端直接输入“dnsenum -h”可以查看其相关参数用法：

        light@kali:~# dnsenum -h
        dnsenum.pl VERSION:1.2.3
        Usage: dnsenum.pl [Options] <domain> 
        [Options]:
        Note: the brute force -f switch is obligatory.
        GENERAL OPTIONS:
          --dnsserver 	<server>
        			Use this DNS server for A, NS and MX queries.
          --enum		Shortcut option equivalent to --threads 5 -s 15 -w.
          -h, --help		Print this help message.
          --noreverse		Skip the reverse lookup operations.
          --nocolor		Disable ANSIColor output.
          --private		Show and save private ips at the end of the file domain_ips.txt.
          --subfile <file>	Write all valid subdomains to this file.
          -t, --timeout <value>	The tcp and udp timeout values in seconds (default: 10s).
          --threads <value>	The number of threads that will perform different queries.
          -v, --verbose		Be verbose: show all the progress and all the error messages.
        GOOGLE SCRAPING OPTIONS:
          -p, --pages <value>	The number of google search pages to process when scraping names, 
        			the default is 5 pages, the -s switch must be specified.
          -s, --scrap <value>	The maximum number of subdomains that will be scraped from Google (default 15).
        BRUTE FORCE OPTIONS:
          -f, --file <file>	Read subdomains from this file to perform brute force.
          -u, --update	<a|g|r|z>
        			Update the file specified with the -f switch with valid subdomains.
        	a (all)		Update using all results.
        	g		Update using only google scraping results.
        	r		Update using only reverse lookup results.
        	z		Update using only zonetransfer results.
          -r, --recursion	Recursion on subdomains, brute force all discovred subdomains that have an NS record.
        WHOIS NETRANGE OPTIONS:
          -d, --delay <value>	The maximum value of seconds to wait between whois queries, the value is defined randomly, default: 3s.
          -w, --whois		Perform the whois queries on c class network ranges.
        			 **Warning**: this can generate very large netranges and it will take lot of time to performe reverse lookups.
        REVERSE LOOKUP OPTIONS:
          -e, --exclude	<regexp>
        			Exclude PTR records that match the regexp expression from reverse lookup results, useful on invalid hostnames.
        OUTPUT OPTIONS:
          -o --output <file>	Output in XML format. Can be imported in MagicTree (www.gremwell.com)
参数解释：

* -f dns.txt ：指定字典文件，可以换成 dns-big.txt 也可以自定义字典
* -dnsserver 8.8.8.8 ：指定dns服务器，一般可以直接使用目标dns服务器，（PS：8.8.8.8 是一个IP地址，是Google提供的免费dns服务器的IP地址，另一个是：8.8.4.4）
* -o output.txt ：结果在 output.txt文档里
**3、使用示范**
***
查询1ight.co的DNS信息：

    light@kali:~# dnsenum 1ight.co
    dnsenum.pl VERSION:1.2.3
     
    -----   1ight.co   -----
     
     
    Host's addresses:
    __________________
     
    1ight.co.                                5        IN    A        112.74.102.78
     
     
    Name Servers:
    ______________
     
    f1g1ns1.dnspod.net.                      5        IN    A        111.30.132.180
    f1g1ns1.dnspod.net.                      5        IN    A        125.39.208.193
    f1g1ns1.dnspod.net.                      5        IN    A        180.153.9.189
    f1g1ns1.dnspod.net.                      5        IN    A        182.140.167.166
    f1g1ns1.dnspod.net.                      5        IN    A        113.108.80.138
    f1g1ns2.dnspod.net.                      5        IN    A        182.140.167.188
    f1g1ns2.dnspod.net.                      5        IN    A        115.236.137.40
    f1g1ns2.dnspod.net.                      5        IN    A        115.236.151.191
    f1g1ns2.dnspod.net.                      5        IN    A        112.90.82.194
    f1g1ns2.dnspod.net.                      5        IN    A        101.226.30.224
     
     
    Mail (MX) Servers:
    ___________________
     
    mxbiz2.qq.com.                           5        IN    A        183.60.15.245
    mxbiz2.qq.com.                           5        IN    A        183.57.48.34
    mxbiz1.qq.com.                           5        IN    A        183.57.48.34
    mxbiz1.qq.com.                           5        IN    A        183.60.15.245
     
     
    Trying Zone Transfers and getting Bind Versions:
    _________________________________________________
     
     
    Trying Zone Transfer for 1ight.co on f1g1ns1.dnspod.net ... 
    AXFR record query failed: connection failed
     
    Trying Zone Transfer for 1ight.co on f1g1ns2.dnspod.net ... 
    AXFR record query failed: connection failed
     
    brute force file not specified, bay.
**4、相关资源**
***
[dnsenum git](https://github.com/fwaeytens/dnsenum)

### dnsmap使用说明

**1、工具简介**
***
Dnsmap也是一款搜集信息的工具，它和Dnsenum一样是用于获得子域名的强有力的工具。

**2、使用方法**
***
kali终端直接输入“dnsmap”可以查看其相关参数用法：

    light@kali:~# dnsmap
    dnsmap 0.30 - DNS Network Mapper by pagvac (gnucitizen.org)
     
    usage: dnsmap <target-domain> [options]
    options:
    -w <wordlist-file>
    -r <regular-results-file>
    -c <csv-results-file>
    -d <delay-millisecs>
    -i <ips-to-ignore> (useful if you're obtaining false positives)
     
    e.g.:
    dnsmap target-domain.foo
    dnsmap target-domain.foo -w yourwordlist.txt -r /tmp/domainbf_results.txt
    dnsmap target-fomain.foo -r /tmp/ -d 3000
    dnsmap target-fomain.foo -r ./domainbf_results.txt
参数解释：

* -w：wordlist_TLAs.txt 指定字典文件
* -c：cisco.csv 输出文件
**3、使用示范**
***
查询1ight.co的子域名信息：

    light@kali:~# dnsmap 1ight.co -c Desktop/result.csv
    dnsmap 0.30 - DNS Network Mapper by pagvac (gnucitizen.org)
     
    [+] searching (sub)domains for 1ight.co using built-in wordlist
    [+] using maximum random delay of 10 millisecond(s) between requests
    ....
**4、相关资源**
[dnsmap google code](https://code.google.com/p/dnsmap/)


### dnsrecon使用说明

**1、工具简介**
***
dnsrecon是一款DNS记录的工具，其中一个特色是通过Google查出站点的子域名与IP信息。与dnsmap暴力破解子域名是不一样的,因此速度比dnsmap快，缺点是返回结果不如dnsmap全面。

**2、使用方法**
***
kali终端直接输入“dnsrecon -h”可以查看其相关参数用法：

    light@kali:~# dnsrecon 
    Version: 0.8.8
    Usage: dnsrecon.py <options>
     
    Options:
       -h, --help                  Show this help message and exit
       -d, --domain      <domain>  Domain to Target for enumeration.
       -r, --range       <range>   IP Range for reverse look-up brute force in formats (first-last)
                                   or in (range/bitmask).
       -n, --name_server <name>    Domain server to use, if none is given the SOA of the
                                   target will be used
       -D, --dictionary  <file>    Dictionary file of sub-domain and hostnames to use for
                                   brute force.
       -f                          Filter out of Brute Force Domain lookup records that resolve to
                                   the wildcard defined IP Address when saving records.
       -t, --type        <types>   Specify the type of enumeration to perform:
                                   std      To Enumerate general record types, enumerates.
                                            SOA, NS, A, AAAA, MX and SRV if AXRF on the
                                            NS Servers fail.
     
                                   rvl      To Reverse Look Up a given CIDR IP range.
     
                                   brt      To Brute force Domains and Hosts using a given
                                            dictionary.
     
                                   srv      To Enumerate common SRV Records for a given 
     
                                            domain.
     
                                   axfr     Test all NS Servers in a domain for misconfigured
                                            zone transfers.
     
                                   goo      Perform Google search for sub-domains and hosts.
     
                                   snoop    To Perform a Cache Snooping against all NS 
                                            servers for a given domain, testing all with
                                            file containing the domains, file given with -D
                                            option.
     
                                   tld      Will remove the TLD of given domain and test against
                                            all TLD's registered in IANA
     
                                   zonewalk Will perform a DNSSEC Zone Walk using NSEC Records.
     
       -a                          Perform AXFR with the standard enumeration.
       -s                          Perform Reverse Look-up of ipv4 ranges in the SPF Record of the
                                   targeted domain with the standard enumeration.
       -g                          Perform Google enumeration with the standard enumeration.
       -w                          Do deep whois record analysis and reverse look-up of IP
                                   ranges found thru whois when doing standard query.
       -z                          Performs a DNSSEC Zone Walk with the standard enumeration.
       --threads          <number> Number of threads to use in Range Reverse Look-up, Forward
                                   Look-up Brute force and SRV Record Enumeration
       --lifetime         <number> Time to wait for a server to response to a query.
       --db               <file>   SQLite 3 file to save found records.
       --xml              <file>   XML File to save found records.
       --iw                        Continua bruteforcing a domain even if a wildcard record resolution is 
                                   discovered.
       -c, --csv          <file>   Comma separated value file.
       -j, --json         <file>   JSON file.
       -v                          Show attempts in the bruteforce modes.
参数解释：

* -d : 选项是指定域名
* -x –axfr: AXFR请求枚举
* -s –dospf: 反向查询SPF记录 * -g –google: 通过google枚举子域名与IP * -w –dowhois: 查whois
* –lifetime: 响应时间，这个选项是必须的
**3、使用示范**
查询1ight.co的DNS信息：

    root@kali:~# dnsrecon -d 1ight.co --lifetime 3
    [*] Performing General Enumeration of Domain: 1ight.co
    ....
**4、相关资源**
***
[dnsrecon git](https://github.com/darkoperator/dnsrecon)

###dnsrevenum6使用说明

**1、工具简介**
***
该工具可以执行一个快速反向DNS枚举。

**2、使用方法**
***
终端直接输入“dnsrevenum6 -h”可以查看其相关参数用法：

    light@kali:~# dnsrevenum6 -h
    dnsrevenum6 v2.5 (c) 2013 by van Hauser / THC <vh@thc.org> www.thc.org
     
    Syntax: dnsrevenum6 dns-server ipv6address
     
    Performs a fast reverse DNS enumeration and is able to cope with slow servers.
    Examples:
      dnsrevenum6 dns.test.com 2001:db8:42a8::/48
      dnsrevenum6 dns.test.com 8.a.2.4.8.b.d.0.1.0.0.2.ip6.arpa
### dnstracer 使用说明

**1、工具简介**
***
dnstracker可以追踪dns的解析过程。

**2、使用方法**
***
kali终端直接输入“dnstracer”可以查看其相关参数用法：

    light@kali:~# dnstracer 
    DNSTRACER version 1.8.1 - (c) Edwin Groothuis - http://www.mavetju.org
    Usage: dnstracer [options] [host]
    	-c: disable local caching, default enabled
    	-C: enable negative caching, default disabled
    	-o: enable overview of received answers, default disabled
    	-q <querytype>: query-type to use for the DNS requests, default A
    	-r <retries>: amount of retries for DNS requests, default 3
    	-s <server>: use this server for the initial request, default localhost
    	             If . is specified, A.ROOT-SERVERS.NET will be used.
    	-t <maximum timeout>: Limit time to wait per try
    	-v: verbose
    	-S <ip address>: use this source address.
    	-4: don't query IPv6 servers
**3、使用示范**
***
查询1ight.co的DNS解析过程：
    
    light@kali:~# dnstracer -o 1ight.co
    Tracing to 1ight.co[a] via 192.168.75.2, maximum of 3 retries
    192.168.75.2 (192.168.75.2) 
     |\___ F1G1NS1.DNSPOD.NET [1ight.co] (180.153.9.189) Got authoritative answer 
     |\___ F1G1NS1.DNSPOD.NET [1ight.co] (182.140.167.166) * Got authoritative answer 
     |\___ F1G1NS1.DNSPOD.NET [1ight.co] (113.108.80.138) Got authoritative answer 
     |\___ F1G1NS1.DNSPOD.NET [1ight.co] (111.30.132.180) * * * 
     |\___ F1G1NS1.DNSPOD.NET [1ight.co] (125.39.208.193) Got authoritative answer 
      \___ F1G1NS2.DNSPOD.NET [1ight.co] (112.90.82.194) Got authoritative answer 
      \___ F1G1NS2.DNSPOD.NET [1ight.co] (101.226.30.224) Got authoritative answer 
      \___ F1G1NS2.DNSPOD.NET [1ight.co] (182.140.167.188) * Got authoritative answer 
      \___ F1G1NS2.DNSPOD.NET [1ight.co] (115.236.137.40) Got authoritative answer 
      \___ F1G1NS2.DNSPOD.NET [1ight.co] (115.236.151.191) * Got authoritative answer 
     
    F1G1NS2.DNSPOD.NET (115.236.151.191)    1ight.co -> 112.74.102.78
    F1G1NS2.DNSPOD.NET (115.236.137.40)     1ight.co -> 112.74.102.78
    F1G1NS2.DNSPOD.NET (182.140.167.188)    1ight.co -> 112.74.102.78
    F1G1NS2.DNSPOD.NET (101.226.30.224)     1ight.co -> 112.74.102.78
    F1G1NS2.DNSPOD.NET (112.90.82.194)      1ight.co -> 112.74.102.78
    F1G1NS1.DNSPOD.NET (125.39.208.193)     1ight.co -> 112.74.102.78
    F1G1NS1.DNSPOD.NET (113.108.80.138)     1ight.co -> 112.74.102.78
    F1G1NS1.DNSPOD.NET (182.140.167.166)    1ight.co -> 112.74.102.78
    F1G1NS1.DNSPOD.NET (180.153.9.189)      1ight.co -> 112.74.102.78    
### Dnswalk使用说明

**1、工具简介**
***
有时候可能需要了解当前域名所对应的所有二级域名，DNSWALK就是利用DNS区域传输技术来获取DNS对应域名A记录的小工具。

**2、使用方法**
***
kali终端直接输入“dnswalk –help”可以查看其相关参数用法：

light@kali:~# dnswalk --help
     
    Usage: dnswalk [-OPTIONS [-MORE_OPTIONS]] [--] [PROGRAM_ARG1 ...]
     
    The following single-character options are accepted:
    	With arguments: -D
    	Boolean (without arguments): -r -f -i -a -d -m -F -l
     
    Options may be merged together.  -- stops processing of options.
    Space is not required between options and their arguments.
注意：域名后面有一个点

**3、使用示范**
***
查询1ight.co的域名A记录信息：
    
    light@kali:~# dnswalk 1ight.co.
    Checking 1ight.co.
    Getting zone transfer of 1ight.co. from f1g1ns1.dnspod.net...failed
    FAIL: Zone transfer of 1ight.co. from f1g1ns1.dnspod.net failed: connection failed
    Getting zone transfer of 1ight.co. from f1g1ns2.dnspod.net...
    ....
    

### fierce使用说明

**1、工具简介**
***
在得到主域名信息之后，如果能通过主域名得到所有子域名信息，在通过子域名查询其对应的主机IP，这样我们能得到一个较为完整的信息。 使用fierse工具，可以进行域名列表查询。

**2、使用方法**
***
终端直接输入“fierce -h”可以查看其相关参数用法：

    light@kali:~# fierce -h
    fierce.pl (C) Copywrite 2006,2007 - By RSnake at http://ha.ckers.org/fierce/
     
    	Usage: perl fierce.pl [-dns example.com] [OPTIONS]
 
    Overview:
    	Fierce is a semi-lightweight scanner that helps locate non-contiguous
    	IP space and hostnames against specified domains.  It's really meant
    	as a pre-cursor to nmap, unicornscan, nessus, nikto, etc, since all 
    	of those require that you already know what IP space you are looking 
    	for.  This does not perform exploitation and does not scan the whole 
    	internet indiscriminately.  It is meant specifically to locate likely 
    	targets both inside and outside a corporate network.  Because it uses 
    	DNS primarily you will often find mis-configured networks that leak 
    	internal address space. That's especially useful in targeted malware.
     
    Options:
    	-connect	Attempt to make http connections to any non RFC1918
    		(public) addresses.  This will output the return headers but
    		be warned, this could take a long time against a company with
    		many targets, depending on network/machine lag.  I wouldn't
    		recommend doing this unless it's a small company or you have a
    		lot of free time on your hands (could take hours-days).  
    		Inside the file specified the text "Host:\n" will be replaced
    		by the host specified. Usage:
     
    	perl fierce.pl -dns example.com -connect headers.txt
     
    	-delay		The number of seconds to wait between lookups.
    	-dns		The domain you would like scanned.
    	-dnsfile  	Use DNS servers provided by a file (one per line) for
                    reverse lookups (brute force).
    	-dnsserver	Use a particular DNS server for reverse lookups 
    		(probably should be the DNS server of the target).  Fierce
    		uses your DNS server for the initial SOA query and then uses
    		the target's DNS server for all additional queries by default.
    	-file		A file you would like to output to be logged to.
    	-fulloutput	When combined with -connect this will output everything
    		the webserver sends back, not just the HTTP headers.
    	-help		This screen.
    	-nopattern	Don't use a search pattern when looking for nearby
    		hosts.  Instead dump everything.  This is really noisy but
    		is useful for finding other domains that spammers might be
    		using.  It will also give you lots of false positives, 
    		especially on large domains.
    	-range		Scan an internal IP range (must be combined with 
    		-dnsserver).  Note, that this does not support a pattern
    		and will simply output anything it finds.  Usage:
     
    	perl fierce.pl -range 111.222.333.0-255 -dnsserver ns1.example.co
     
    	-search		Search list.  When fierce attempts to traverse up and
    		down ipspace it may encounter other servers within other
    		domains that may belong to the same company.  If you supply a 
    		comma delimited list to fierce it will report anything found.
    		This is especially useful if the corporate servers are named
    		different from the public facing website.  Usage:
     
    	perl fierce.pl -dns examplecompany.com -search corpcompany,blahcompany 
     
    		Note that using search could also greatly expand the number of
    		hosts found, as it will continue to traverse once it locates
    		servers that you specified in your search list.  The more the
    		better.
    	-suppress	Suppress all TTY output (when combined with -file).
    	-tcptimeout	Specify a different timeout (default 10 seconds).  You
    		may want to increase this if the DNS server you are querying
    		is slow or has a lot of network lag.
    	-threads  Specify how many threads to use while scanning (default
    	  is single threaded).
    	-traverse	Specify a number of IPs above and below whatever IP you
    		have found to look for nearby IPs.  Default is 5 above and 
    		below.  Traverse will not move into other C blocks.
    	-version	Output the version number.
    	-wide		Scan the entire class C after finding any matching
    		hostnames in that class C.  This generates a lot more traffic
    		but can uncover a lot more information.
    	-wordlist	Use a seperate wordlist (one word per line).  Usage:
     
    	perl fierce.pl -dns examplecompany.com -wordlist dictionary.txt

**3、使用示范**
***
查询1ight.co的域名列表信息：

    light@kali:~# fierce -dns 1ight.co
    DNS Servers for 1ight.co:
    	f1g1ns1.dnspod.net
    	f1g1ns2.dnspod.net
     
    Trying zone transfer first...
    	Testing f1g1ns1.dnspod.net
    		Request timed out or transfer not allowed.
    	Testing f1g1ns2.dnspod.net
    		Request timed out or transfer not allowed.
     
    Unsuccessful in zone transfer (it was worth a shot)
    Okay, trying the good old fashioned way... brute force
     
    Checking for wildcard DNS...
    Nope. Good.
    Now performing 2280 test(s)...
    ....
**4、相关资源**
***
[工具官方网站](http://ha.ckers.org/fierce/)

