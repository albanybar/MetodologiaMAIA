
Fase 1: Coleta de informação

Uso do netdiscover para identificação do IP a ser inspecionado no caso o 172.16.116.128

```jsx

root@kali:~# netdiscover -r 172.16.116.0/24

 Currently scanning: Finished!   |   Screen View: Unique Hosts                                                                                                                              
                                                                                                                                                                                            
 4 Captured ARP Req/Rep packets, from 4 hosts.   Total size: 240                                                                                                                            
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 172.16.116.1    00:50:56:c0:00:08      1      60  VMware, Inc.                                                                                                                             
 172.16.116.2    00:50:56:f9:18:06      1      60  VMware, Inc.                                                                                                                             
 172.16.116.128  00:0c:29:1a:79:bd      1      60  VMware, Inc.                                                                                                                             
 172.16.116.254  00:50:56:e4:11:09      1      60  VMware, Inc.                                                                                                                             


```

Uso do nmap para identificação das portas abertas e com a opção -A scripts de enumeração e com isso foi identificado a pasta .git


```jsx

──(root㉿kali)-[/home/kali]
└─# nmap -vvv -A 172.16.116.128   
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-20 18:45 EDT
NSE: Loaded 156 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:45
Completed NSE at 18:45, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:45
Completed NSE at 18:45, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:45
Completed NSE at 18:45, 0.00s elapsed
Initiating ARP Ping Scan at 18:45
Scanning 172.16.116.128 [1 port]
Completed ARP Ping Scan at 18:45, 0.10s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 18:45
Completed Parallel DNS resolution of 1 host. at 18:45, 0.00s elapsed
DNS resolution of 1 IPs took 0.00s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 18:45
Scanning 172.16.116.128 [1000 ports]
Discovered open port 22/tcp on 172.16.116.128
Discovered open port 80/tcp on 172.16.116.128
Completed SYN Stealth Scan at 18:45, 0.14s elapsed (1000 total ports)
Initiating Service scan at 18:45
Scanning 2 services on 172.16.116.128
Completed Service scan at 18:46, 6.03s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against 172.16.116.128
NSE: Script scanning 172.16.116.128.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:46
Completed NSE at 18:46, 0.36s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:46
Completed NSE at 18:46, 0.02s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:46
Completed NSE at 18:46, 0.00s elapsed
Nmap scan report for 172.16.116.128
Host is up, received arp-response (0.00095s latency).
Scanned at 2024-03-20 18:45:53 EDT for 8s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 64 OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 57:b1:f5:64:28:98:91:51:6d:70:76:6e:a5:52:43:5d (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC8frfKJoug6k4wCSqcsbT7meZVMAFhil7gpcyzdiiutx5GhiKXsiuW3S4+t1F4VmqfUDXeLEGb9KPLyEI4Lsa/OB5sV/D9zsSSdiDwY7XrjM8C4rnWL+oHeVOIhwwKAPfs8GhxRUXmaGvWrMIqWqZPm7tuEm+PEcTTuAHyMypZelGByd7MCm5vAS5Yq0uNAzyNAmepvkmONeN1OrvmVMmHduMtPurHBeBj0n8A5JPKsMu7k9FuHRGS4t5r02gFjWq7sj69QXazooEDoOQKQ8MPmO2+lAFc/aASzVLmR18GR+f9iGa6QPayK6JrSGEsnmJ2P//3Ag2UxuN+KmbSHMv3GxMUx6UGzXmPUTB/EpjFjwnP8WJoDx1Kz6dJhSa989yRm/QpwDVNF2fXtWTdlerSwK91O4c3oeYfIWGSQYibFUz0zSnTlVyYeQXrKIgVTi/LXL4CLx2RxBELLnpZpzb6bi2E1SbgN/O8Z0s9wGutN1lHlNXeAr/DtFHtbydH3mM=
|   256 cc:64:fd:7c:d8:5e:48:8a:28:98:91:b9:e4:1e:6d:a8 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOzep/j+gpuyw1FGbB2Xv/n9dxfX6dVxL1fq5kPo73VI7meVIOtHMfKJRR171UkOgjQcmdEDbacx/1gPYROEpOQ=
|   256 9e:77:08:a4:52:9f:33:8d:96:19:ba:75:71:27:bd:60 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJSt7LQLdRjZXyGAxifV2JJ37dTptXNSJNmSYLMi6ct5
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.41 ((Ubuntu))
| http-git: 
|   172.16.116.128:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: i changed login.php file for more secure 
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: DarkHole V2
MAC Address: 00:0C:29:1A:79:BD (VMware)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
TCP/IP fingerprint:
OS:SCAN(V=7.94SVN%E=4%D=3/20%OT=22%CT=1%CU=33014%PV=Y%DS=1%DC=D%G=Y%M=000C2
OS:9%TM=65FB6729%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=1%ISR=10E%TI=Z%CI=Z%I
OS:I=I%TS=A)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW
OS:7%O5=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88
OS:%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%
OS:S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%
OS:RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W
OS:=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
OS:U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%D
OS:FI=N%T=40%CD=S)

Uptime guess: 17.806 days (since Sat Mar  2 22:25:27 2024)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=256 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.95 ms 172.16.116.128

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 18:46
Completed NSE at 18:46, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 18:46
Completed NSE at 18:46, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 18:46
Completed NSE at 18:46, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.62 seconds
           Raw packets sent: 1023 (45.806KB) | Rcvd: 1015 (41.286KB)

```