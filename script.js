
// script.js
// Enhanced command database with more details
const commandDatabase = {
    basic: {
        title: "BASIC COMMANDS",
        icon: "fas fa-layer-group",
        color: "#00ff9d",
        commands: [
            {command: "ls", description: "list files", usage: "ls [options] [directory]", example: "ls -la /home/user"},
            {command: "ls -la", description: "detailed list with hidden files", usage: "ls -la", example: "ls -la"},
            {command: "cd", description: "change directory", usage: "cd [directory]", example: "cd /etc"},
            {command: "pwd", description: "print working directory", usage: "pwd", example: "pwd"},
            {command: "mkdir", description: "create directory", usage: "mkdir [directory]", example: "mkdir new_folder"},
            {command: "rmdir", description: "remove empty directory", usage: "rmdir [directory]", example: "rmdir old_folder"},
            {command: "rm", description: "remove file", usage: "rm [file]", example: "rm file.txt"},
            {command: "rm -rf", description: "force remove recursively", usage: "rm -rf [directory]", example: "rm -rf folder/", dangerous: true},
            {command: "cp", description: "copy files", usage: "cp [source] [destination]", example: "cp file.txt backup/"},
            {command: "mv", description: "move/rename files", usage: "mv [source] [destination]", example: "mv old.txt new.txt"},
            {command: "touch", description: "create empty file", usage: "touch [filename]", example: "touch newfile.txt"},
            {command: "cat", description: "view file content", usage: "cat [file]", example: "cat /etc/passwd"},
            {command: "less", description: "view file page by page", usage: "less [file]", example: "less largefile.log"},
            {command: "head", description: "show first lines", usage: "head -n [number] [file]", example: "head -20 access.log"},
            {command: "tail", description: "show last lines", usage: "tail -n [number] [file]", example: "tail -f logfile.log"},
            {command: "clear", description: "clear terminal", usage: "clear", example: "clear"},
            {command: "history", description: "show command history", usage: "history", example: "history | grep ssh"},
            {command: "echo", description: "print text", usage: "echo [text]", example: "echo 'Hello World'"},
            {command: "man", description: "manual pages", usage: "man [command]", example: "man ls"},
            {command: "uname -a", description: "system information", usage: "uname -a", example: "uname -a"},
            {command: "whoami", description: "current user", usage: "whoami", example: "whoami"},
            {command: "id", description: "user information", usage: "id", example: "id"},
            {command: "hostname", description: "system hostname", usage: "hostname", example: "hostname"},
            {command: "date", description: "show date and time", usage: "date", example: "date"},
            {command: "cal", description: "calendar", usage: "cal", example: "cal 2023"},
            {command: "uptime", description: "system running time", usage: "uptime", example: "uptime"},
            {command: "df -h", description: "disk usage human readable", usage: "df -h", example: "df -h"},
            {command: "du -h", description: "directory size", usage: "du -h [directory]", example: "du -h /home"},
            {command: "free -h", description: "memory usage", usage: "free -h", example: "free -h"},
            {command: "top", description: "process monitor", usage: "top", example: "top"},
            {command: "htop", description: "advanced process monitor", usage: "htop", example: "htop"},
            {command: "ps aux", description: "process list", usage: "ps aux", example: "ps aux | grep python"},
            {command: "kill", description: "terminate process", usage: "kill [PID]", example: "kill 1234"},
            {command: "reboot", description: "reboot system", usage: "reboot", example: "sudo reboot"},
            {command: "shutdown", description: "power off system", usage: "shutdown", example: "sudo shutdown now"},
            {command: "ip a", description: "network interfaces", usage: "ip a", example: "ip a"},
            {command: "ping", description: "test network connectivity", usage: "ping [host]", example: "ping google.com"},
            {command: "wget", description: "download files", usage: "wget [URL]", example: "wget https://example.com/file.zip"}
        ]
    },
    intermediate: {
        title: "INTERMEDIATE COMMANDS",
        icon: "fas fa-cogs",
        color: "#00ccff",
        commands: [
            {command: "chmod", description: "change permissions", usage: "chmod [permissions] [file]", example: "chmod 755 script.sh"},
            {command: "chown", description: "change ownership", usage: "chown [user]:[group] [file]", example: "chown root:root file"},
            {command: "sudo", description: "execute as root", usage: "sudo [command]", example: "sudo apt update"},
            {command: "su", description: "switch user", usage: "su [username]", example: "su -"},
            {command: "find", description: "search files", usage: "find [path] [expression]", example: "find / -name '*.conf'"},
            {command: "locate", description: "indexed file search", usage: "locate [pattern]", example: "locate *.log"},
            {command: "grep", description: "search text", usage: "grep [pattern] [file]", example: "grep 'error' /var/log/syslog"},
            {command: "awk", description: "text processing", usage: "awk '[pattern] {action}' [file]", example: "awk '{print $1}' file.txt"},
            {command: "sed", description: "stream editor", usage: "sed 's/find/replace/' [file]", example: "sed 's/old/new/g' file.txt"},
            {command: "xargs", description: "build arguments", usage: "[command] | xargs [command]", example: "find . -name '*.txt' | xargs rm"},
            {command: "tar", description: "archive files", usage: "tar [options] [archive] [files]", example: "tar -czvf archive.tar.gz folder/"},
            {command: "gzip", description: "compress files", usage: "gzip [file]", example: "gzip file.txt"},
            {command: "gunzip", description: "decompress files", usage: "gunzip [file.gz]", example: "gunzip file.txt.gz"},
            {command: "zip", description: "zip files", usage: "zip [archive.zip] [files]", example: "zip archive.zip file1 file2"},
            {command: "unzip", description: "unzip files", usage: "unzip [archive.zip]", example: "unzip archive.zip"},
            {command: "scp", description: "secure copy", usage: "scp [source] [user@host:dest]", example: "scp file.txt user@remote:/home/user"},
            {command: "rsync", description: "sync files", usage: "rsync [options] [source] [dest]", example: "rsync -avz folder/ user@remote:backup/"},
            {command: "mount", description: "mount filesystem", usage: "mount [device] [mountpoint]", example: "mount /dev/sdb1 /mnt"},
            {command: "umount", description: "unmount filesystem", usage: "umount [mountpoint]", example: "umount /mnt"},
            {command: "lsblk", description: "list block devices", usage: "lsblk", example: "lsblk"},
            {command: "fdisk", description: "disk partition", usage: "fdisk [device]", example: "sudo fdisk -l"},
            {command: "crontab", description: "scheduled tasks", usage: "crontab -e", example: "crontab -e"},
            {command: "watch", description: "repeat command", usage: "watch [command]", example: "watch -n 1 'ls -la'"},
            {command: "screen", description: "terminal session", usage: "screen", example: "screen -S session_name"},
            {command: "tmux", description: "terminal multiplexer", usage: "tmux", example: "tmux new -s session"},
            {command: "netstat", description: "network statistics", usage: "netstat [options]", example: "netstat -tulpn"},
            {command: "ss", description: "socket statistics", usage: "ss [options]", example: "ss -tulpn"},
            {command: "traceroute", description: "route tracking", usage: "traceroute [host]", example: "traceroute google.com"},
            {command: "arp -a", description: "ARP table", usage: "arp -a", example: "arp -a"},
            {command: "route", description: "routing table", usage: "route", example: "route -n"},
            {command: "nmap", description: "network scanner", usage: "nmap [options] [target]", example: "nmap -sP 192.168.1.0/24"},
            {command: "tcpdump", description: "packet capture", usage: "tcpdump [options]", example: "tcpdump -i eth0 port 80"},
            {command: "nc", description: "netcat tool", usage: "nc [options] [host] [port]", example: "nc -zv example.com 80"},
            {command: "curl", description: "HTTP requests", usage: "curl [options] [URL]", example: "curl -I https://example.com"},
            {command: "service", description: "manage services", usage: "service [service] [action]", example: "service apache2 restart"},
            {command: "systemctl", description: "system services", usage: "systemctl [action] [service]", example: "systemctl status ssh"},
            {command: "journalctl", description: "system logs", usage: "journalctl [options]", example: "journalctl -f"},
            {command: "dmesg", description: "kernel logs", usage: "dmesg", example: "dmesg | tail -20"}
        ]
    },
    advanced: {
        title: "ADVANCED COMMANDS",
        icon: "fas fa-shield-alt",
        color: "#bd00ff",
        commands: [
            {command: "nmap -A", description: "aggressive scan", usage: "nmap -A [target]", example: "nmap -A 192.168.1.1"},
            {command: "nmap -sV", description: "version detection", usage: "nmap -sV [target]", example: "nmap -sV 192.168.1.1"},
            {command: "nikto", description: "web vulnerability scanner", usage: "nikto -h [host]", example: "nikto -h http://target.com"},
            {command: "whatweb", description: "web fingerprinting", usage: "whatweb [URL]", example: "whatweb https://example.com"},
            {command: "dirb", description: "directory brute force", usage: "dirb [URL] [wordlist]", example: "dirb http://target.com /usr/share/wordlists/dirb/common.txt"},
            {command: "gobuster", description: "directory brute force", usage: "gobuster [mode] [options]", example: "gobuster dir -u http://target.com -w wordlist.txt"},
            {command: "dnsenum", description: "DNS enumeration", usage: "dnsenum [domain]", example: "dnsenum example.com"},
            {command: "fierce", description: "DNS reconnaissance", usage: "fierce [options] [domain]", example: "fierce -dns example.com"},
            {command: "enum4linux", description: "SMB enumeration", usage: "enum4linux [target]", example: "enum4linux 192.168.1.100"},
            {command: "smbclient", description: "SMB client", usage: "smbclient [options]", example: "smbclient -L //192.168.1.100"},
            {command: "rpcclient", description: "RPC enumeration", usage: "rpcclient [options] [target]", example: "rpcclient -U '' 192.168.1.100"},
            {command: "ftp", description: "FTP client", usage: "ftp [host]", example: "ftp 192.168.1.100"},
            {command: "hydra", description: "login brute force", usage: "hydra [options] [service]://[target]", example: "hydra -l admin -P pass.txt ssh://192.168.1.1"},
            {command: "medusa", description: "brute force tool", usage: "medusa [options]", example: "medusa -h 192.168.1.1 -u admin -P pass.txt -M ssh"},
            {command: "hashcat", description: "hash cracking", usage: "hashcat [options] [hash] [wordlist]", example: "hashcat -m 0 hash.txt rockyou.txt"},
            {command: "john", description: "password cracking", usage: "john [options] [hashfile]", example: "john --wordlist=rockyou.txt hash.txt"},
            {command: "airmon-ng", description: "monitor mode", usage: "airmon-ng [interface]", example: "airmon-ng start wlan0"},
            {command: "airodump-ng", description: "wireless packet capture", usage: "airodump-ng [interface]", example: "airodump-ng wlan0mon"},
            {command: "aireplay-ng", description: "packet injection", usage: "aireplay-ng [options]", example: "aireplay-ng --deauth 10 -a BSSID wlan0mon"},
            {command: "aircrack-ng", description: "WiFi cracker", usage: "aircrack-ng [capture.cap]", example: "aircrack-ng capture-01.cap -w rockyou.txt"},
            {command: "reaver", description: "WPS attack tool", usage: "reaver [options]", example: "reaver -i wlan0mon -b BSSID -vv"},
            {command: "wash", description: "WPS scanner", usage: "wash [options]", example: "wash -i wlan0mon"},
            {command: "msfconsole", description: "Metasploit framework", usage: "msfconsole", example: "msfconsole"},
            {command: "searchsploit", description: "exploit search", usage: "searchsploit [term]", example: "searchsploit apache 2.4"},
            {command: "setoolkit", description: "social engineering toolkit", usage: "setoolkit", example: "setoolkit"},
            {command: "wpscan", description: "WordPress scanner", usage: "wpscan [options]", example: "wpscan --url http://target.com --enumerate"},
            {command: "sqlmap", description: "SQL injection tool", usage: "sqlmap [options]", example: "sqlmap -u 'http://target.com/page?id=1' --dbs"},
            {command: "xsser", description: "XSS testing", usage: "xsser [options]", example: "xsser -u 'http://target.com/search?q='"},
            {command: "nikto -Tuning", description: "deep scan with tuning", usage: "nikto -h [host] -Tuning [options]", example: "nikto -h http://target.com -Tuning 1,2,3,4,5,6,7"},
            {command: "sslscan", description: "SSL analysis", usage: "sslscan [host]", example: "sslscan example.com"},
            {command: "amass", description: "subdomain enumeration", usage: "amass enum [options]", example: "amass enum -d example.com"},
            {command: "theharvester", description: "OSINT gathering", usage: "theharvester [options]", example: "theharvester -d example.com -b all"},
            {command: "recon-ng", description: "recon framework", usage: "recon-ng", example: "recon-ng"},
            {command: "maltego", description: "link analysis", usage: "maltego", example: "Start with: maltego"},
            {command: "burpsuite", description: "web proxy", usage: "burpsuite", example: "burpsuite"},
            {command: "owasp-zap", description: "web testing", usage: "zap.sh", example: "zap.sh -daemon"}
        ]
    },
    expert: {
        title: "EXPERT COMMANDS",
        icon: "fas fa-user-ninja",
        color: "#ffcc00",
        commands: [
            {command: "msfvenom", description: "payload generator", usage: "msfvenom [options]", example: "msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.100 LPORT=4444 -f exe > payload.exe"},
            {command: "crackmapexec", description: "Active Directory testing", usage: "crackmapexec [protocol] [target] [options]", example: "crackmapexec smb 192.168.1.0/24 -u user -p password"},
            {command: "impacket-smbexec", description: "SMB execution", usage: "smbexec.py [domain]/[user]:[password]@[target]", example: "smbexec.py domain/user:password@192.168.1.100"},
            {command: "impacket-psexec", description: "remote execution", usage: "psexec.py [domain]/[user]:[password]@[target]", example: "psexec.py domain/user:password@192.168.1.100"},
            {command: "impacket-wmiexec", description: "WMI execution", usage: "wmiexec.py [domain]/[user]:[password]@[target]", example: "wmiexec.py domain/user:password@192.168.1.100"},
            {command: "mimikatz", description: "credential extraction", usage: "mimikatz.exe [command]", example: "mimikatz # sekurlsa::logonpasswords"},
            {command: "secretsdump.py", description: "dump password hashes", usage: "secretsdump.py [domain]/[user]:[password]@[target]", example: "secretsdump.py domain/user:password@192.168.1.100"},
            {command: "responder", description: "LLMNR/NBT-NS poisoning", usage: "responder -I [interface]", example: "responder -I eth0 -wrf"},
            {command: "bettercap", description: "MITM framework", usage: "bettercap [options]", example: "bettercap -iface eth0"},
            {command: "mitmproxy", description: "traffic interception", usage: "mitmproxy [options]", example: "mitmproxy -T --host"},
            {command: "proxychains", description: "route traffic through proxy", usage: "proxychains [command]", example: "proxychains nmap -sT 192.168.1.1"},
            {command: "chisel", description: "tunneling tool", usage: "chisel [server|client] [options]", example: "chisel server -p 8080 --reverse"},
            {command: "sshuttle", description: "VPN over SSH", usage: "sshuttle [options]", example: "sshuttle -r user@server 0.0.0.0/0 -vv"},
            {command: "linpeas.sh", description: "Linux privilege escalation", usage: "./linpeas.sh", example: "./linpeas.sh"},
            {command: "linenum.sh", description: "Linux enumeration", usage: "./linenum.sh", example: "./linenum.sh -t"},
            {command: "pspy", description: "process monitoring", usage: "./pspy [options]", example: "./pspy -p -i 1000"},
            {command: "winpeas.exe", description: "Windows privilege escalation", usage: "winpeas.exe", example: "winpeas.exe"},
            {command: "powershell-empire", description: "C2 framework", usage: "powershell-empire", example: "powershell-empire"},
            {command: "covenant", description: "C2 framework", usage: "dotnet run", example: "Start with: dotnet run"},
            {command: "sliver", description: "red team C2", usage: "sliver [command]", example: "sliver"},
            {command: "veil", description: "AV evasion", usage: "veil", example: "veil"},
            {command: "obfuscator", description: "payload obfuscation", usage: "obfuscator [options]", example: "obfuscator -f payload.exe -o obfuscated.exe"},
            {command: "volatility", description: "memory forensics", usage: "volatility -f [memory.dmp] [plugin]", example: "volatility -f memory.dmp imageinfo"},
            {command: "rekall", description: "memory analysis", usage: "rekall [options]", example: "rekall -f memory.dmp pslist"},
            {command: "autopsy", description: "disk forensics", usage: "autopsy", example: "autopsy"},
            {command: "foremost", description: "file carving", usage: "foremost [options] [image]", example: "foremost -i disk.img -o output"},
            {command: "binwalk", description: "firmware analysis", usage: "binwalk [options] [file]", example: "binwalk -e firmware.bin"},
            {command: "radare2", description: "reverse engineering", usage: "r2 [file]", example: "r2 -A binary.exe"},
            {command: "ghidra", description: "reverse engineering", usage: "ghidra", example: "Start with: ghidra"},
            {command: "strace", description: "system call trace", usage: "strace [command]", example: "strace ls -la"},
            {command: "ltrace", description: "library call trace", usage: "ltrace [command]", example: "ltrace ls -la"},
            {command: "perf", description: "performance analysis", usage: "perf [command]", example: "perf stat ls -la"},
            {command: "auditctl", description: "audit control", usage: "auditctl [options]", example: "auditctl -w /etc/passwd -p rwxa"},
            {command: "tcpflow", description: "TCP stream capture", usage: "tcpflow [options]", example: "tcpflow -c -i eth0 port 80"},
            {command: "yara", description: "malware rules", usage: "yara [rules] [file]", example: "yara rules.yar suspicious.exe"},
            {command: "clamav", description: "malware scan", usage: "clamscan [file]", example: "clamscan -r /home/user"}
        ]
    },
    destruction: {
        title: "DATA DESTRUCTION",
        icon: "fas fa-skull-crossbones",
        color: "#ff003c",
        commands: [
            {command: "rm -rf /", description: "remove entire filesystem", usage: "rm -rf /", dangerous: true, warning: "THIS WILL DESTROY YOUR SYSTEM! Never run this unless you want to delete everything."},
            {command: "rm -rf *", description: "delete all files in current directory", usage: "rm -rf *", dangerous: true, warning: "Deletes all files in current directory recursively. Use with extreme caution."},
            {command: "dd", description: "raw disk write/overwrite", usage: "dd if=[input] of=[output]", example: "dd if=/dev/zero of=/dev/sda", dangerous: true},
            {command: "mkfs", description: "create filesystem (destroys data)", usage: "mkfs [options] [device]", example: "mkfs.ext4 /dev/sdb1", dangerous: true},
            {command: "mkfs.ext4", description: "format disk as ext4", usage: "mkfs.ext4 [device]", example: "mkfs.ext4 /dev/sdb1", dangerous: true},
            {command: "fdisk", description: "disk partitioning", usage: "fdisk [device]", example: "fdisk /dev/sdb", dangerous: true},
            {command: "parted", description: "advanced partitioning", usage: "parted [device]", example: "parted /dev/sdb", dangerous: true},
            {command: "wipefs", description: "wipe filesystem signatures", usage: "wipefs [options] [device]", example: "wipefs -a /dev/sdb1", dangerous: true}
        ]
    },
    control: {
        title: "SYSTEM CONTROL",
        icon: "fas fa-network-wired",
        color: "#ff00aa",
        commands: [
            {command: "reboot", description: "reboot system", usage: "reboot", example: "sudo reboot"},
            {command: "shutdown", description: "power off system", usage: "shutdown [time]", example: "sudo shutdown now"},
            {command: "shutdown -h now", description: "immediate shutdown", usage: "shutdown -h now", example: "sudo shutdown -h now"},
            {command: "shutdown -r now", description: "immediate reboot", usage: "shutdown -r now", example: "sudo shutdown -r now"},
            {command: "init 0", description: "shutdown (System V)", usage: "init 0", example: "sudo init 0"},
            {command: "init 6", description: "reboot (System V)", usage: "init 6", example: "sudo init 6"},
            {command: "poweroff", description: "power off", usage: "poweroff", example: "sudo poweroff"},
            {command: "halt", description: "stop system", usage: "halt", example: "sudo halt"},
            {command: "chmod -R", description: "recursive permissions", usage: "chmod -R [permissions] [directory]", example: "chmod -R 755 /var/www"},
            {command: "chmod 777", description: "unsafe full permissions", usage: "chmod 777 [file]", example: "chmod 777 script.sh", warning: "Gives full read/write/execute to everyone. Security risk!"},
            {command: "chown -R", description: "recursive ownership", usage: "chown -R [user]:[group] [directory]", example: "chown -R www-data:www-data /var/www"},
            {command: "setfacl", description: "set ACL permissions", usage: "setfacl [options]", example: "setfacl -m u:user:rwx file.txt"},
            {command: "getfacl", description: "view ACLs", usage: "getfacl [file]", example: "getfacl /etc/shadow"},
            {command: "sudo", description: "execute as root", usage: "sudo [command]", example: "sudo visudo"},
            {command: "su -", description: "login as root", usage: "su -", example: "su -"},
            {command: "passwd", description: "change password", usage: "passwd [username]", example: "passwd"},
            {command: "useradd", description: "create user", usage: "useradd [options] [username]", example: "sudo useradd -m -s /bin/bash newuser"},
            {command: "userdel", description: "delete user", usage: "userdel [username]", example: "sudo userdel -r olduser"},
            {command: "usermod", description: "modify user", usage: "usermod [options] [username]", example: "sudo usermod -aG sudo username"},
            {command: "visudo", description: "edit sudoers file", usage: "visudo", example: "sudo visudo"},
            {command: "kill -9", description: "force kill process", usage: "kill -9 [PID]", example: "kill -9 1234"},
            {command: "pkill", description: "kill by process name", usage: "pkill [process]", example: "pkill firefox"},
            {command: "killall", description: "kill all matching processes", usage: "killall [process]", example: "killall chrome"},
            {command: "nice", description: "change process priority", usage: "nice [command]", example: "nice -n 10 long_task"},
            {command: "renice", description: "modify running process priority", usage: "renice [priority] [PID]", example: "renice 5 1234"},
            {command: "tcpdump -i any", description: "capture on all interfaces", usage: "tcpdump -i any", example: "sudo tcpdump -i any port 80"},
            {command: "tcpflow", description: "extract TCP streams", usage: "tcpflow [options]", example: "tcpflow -c -i eth0 port 443"},
            {command: "wireshark", description: "packet analysis GUI", usage: "wireshark", example: "wireshark"},
            {command: "ettercap", description: "MITM attack tool", usage: "ettercap [options]", example: "ettercap -T -i eth0 -M arp // //"},
            {command: "bettercap", description: "MITM framework", usage: "bettercap [options]", example: "bettercap -iface eth0"},
            {command: "mitmproxy", description: "traffic interception", usage: "mitmproxy [options]", example: "mitmproxy -T --host"},
            {command: "nmap -sS", description: "SYN stealth scan", usage: "nmap -sS [target]", example: "nmap -sS 192.168.1.1"},
            {command: "ssh", description: "remote shell", usage: "ssh [user@host]", example: "ssh user@192.168.1.100"},
            {command: "systemctl stop", description: "stop service", usage: "systemctl stop [service]", example: "sudo systemctl stop apache2"},
            {command: "systemctl disable", description: "disable service at boot", usage: "systemctl disable [service]", example: "sudo systemctl disable apache2"},
            {command: "crontab -e", description: "edit cron jobs", usage: "crontab -e", example: "crontab -e"},
            {command: "at", description: "one-time job scheduling", usage: "at [time]", example: "echo 'reboot' | at 3:00 AM"}
        ]
    }
};

// Global variables
let searchActive = false;
let currentSearchResults = [];
let activeCategoryFilter = 'all';


// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    const isTerminalPage = window.location.pathname.includes('terminal.html') || 
                          document.querySelector('.terminal-page');
    
    if (!isTerminalPage) {
        // ===== MAIN PAGE (index.html) INITIALIZATION =====
        initMatrixEffect();
        renderCategoryFilters();
        renderCommandCards();
        updateStats();
        setupEventListeners();
        
        showNotification('CyberKali Hub Loaded', 'Ready to explore 200+ Kali Linux commands.', 'info');
    } else {
        initMatrixEffect();
    }
});
// Initialize matrix effect
function initMatrixEffect() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    const matrixBg = document.getElementById('matrixBg');
    
    if (!matrixBg) return;
    
    canvas.style.position = 'fixed';
    canvas.style.top = '0';
    canvas.style.left = '0';
    canvas.style.width = '100%';
    canvas.style.height = '100%';
    canvas.style.pointerEvents = 'none';
    canvas.style.zIndex = '-2';
    matrixBg.appendChild(canvas);
    
    function resizeCanvas() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }
    
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);
    
    const chars = "01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン";
    const fontSize = 18;
    const columns = Math.floor(canvas.width / fontSize);
    const drops = Array(columns).fill(1);
    
    function drawMatrix() {
        ctx.fillStyle = 'rgba(10, 10, 20, 0.05)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        
        ctx.fillStyle = '#00ff9d';
        ctx.font = `${fontSize}px monospace`;
        
        for (let i = 0; i < drops.length; i++) {
            const char = chars.charAt(Math.floor(Math.random() * chars.length));
            ctx.fillText(char, i * fontSize, drops[i] * fontSize);
            
            if (drops[i] * fontSize > canvas.height && Math.random() > 0.975) {
                drops[i] = 0;
            }
            
            drops[i]++;
        }
    }
    
    setInterval(drawMatrix, 70);
}

// Render category filters
function renderCategoryFilters() {
    const container = document.getElementById('categoryFilters');
    const categories = [
        {id: 'all', name: 'All Commands', icon: 'fas fa-globe'},
        {id: 'basic', name: 'Basic', icon: 'fas fa-layer-group'},
        {id: 'intermediate', name: 'Intermediate', icon: 'fas fa-cogs'},
        {id: 'advanced', name: 'Advanced', icon: 'fas fa-shield-alt'},
        {id: 'expert', name: 'Expert', icon: 'fas fa-user-ninja'},
        {id: 'destruction', name: 'Destruction', icon: 'fas fa-skull-crossbones'},
        {id: 'control', name: 'Control', icon: 'fas fa-network-wired'}
    ];
    
    categories.forEach(cat => {
        const filter = document.createElement('div');
        filter.className = `category-filter ${cat.id === 'all' ? 'active' : ''}`;
        filter.innerHTML = `<i class="${cat.icon}"></i> ${cat.name}`;
        filter.dataset.category = cat.id;
        filter.addEventListener('click', () => toggleCategoryFilter(cat.id));
        container.appendChild(filter);
    });
}

// Render command cards
function renderCommandCards() {
    const container = document.getElementById('commandCategories');
    container.innerHTML = '';
    
    for (const [categoryId, categoryData] of Object.entries(commandDatabase)) {
        const card = document.createElement('div');
        card.className = `category-card ${categoryId}`;
        
        const commandsHTML = categoryData.commands.map(cmd => {
            const dangerousClass = cmd.dangerous ? 'dangerous' : '';
            return `
                <div class="command-item ${dangerousClass}" data-command="${cmd.command}" data-category="${categoryId}" data-description="${cmd.description}">
                    <div class="command-text">${cmd.command}</div>
                    <div class="command-desc">${cmd.description}</div>
                </div>
            `;
        }).join('');
        
        card.innerHTML = `
            <div class="card-header">
                <div class="card-icon" style="border-color: ${categoryData.color}; color: ${categoryData.color}">
                    <i class="${categoryData.icon}"></i>
                </div>
                <div>
                    <div class="card-title">${categoryData.title}</div>
                    <span class="command-count">${categoryData.commands.length} commands</span>
                </div>
            </div>
            <div class="command-list">
                ${commandsHTML}
            </div>
        `;
        
        container.appendChild(card);
    }
    
    document.querySelectorAll('.command-item').forEach(item => {
        item.addEventListener('click', function(e) {
            if (e.target.classList.contains('command-item') || 
                e.target.closest('.command-item')) {
                const command = this.dataset.command;
                const category = this.dataset.category;
                const description = this.dataset.description;
                
                copyToClipboard(command);
                
                showCommandDetails(command, category, description);
            }
        });
    });
}

// Toggle category filter
function toggleCategoryFilter(categoryId) {
    activeCategoryFilter = categoryId;
    
    document.querySelectorAll('.category-filter').forEach(filter => {
        filter.classList.toggle('active', filter.dataset.category === categoryId);
    });
    
    if (searchActive) {
        performSearch(document.getElementById('searchInput').value, categoryId);
    } else {
        document.querySelectorAll('.category-card').forEach(card => {
            if (categoryId === 'all' || card.classList.contains(categoryId)) {
                card.style.display = 'block';
            } else {
                card.style.display = 'none';
            }
        });
    }
}

function setupEventListeners() {
    const searchInput = document.getElementById('searchInput');
    const searchButton = document.getElementById('searchButton');
    const clearSearch = document.getElementById('clearSearch');
    
    searchInput.addEventListener('keyup', function(e) {
        if (e.key === 'Enter') {
            performSearch(this.value, activeCategoryFilter);
        }
    });
    
    searchButton.addEventListener('click', () => {
        performSearch(searchInput.value, activeCategoryFilter);
    });
    
    clearSearch.addEventListener('click', () => {
        clearSearchResults();
    });
    
    document.getElementById('showAll').addEventListener('click', () => {
        showAllCommands();
    });
    
    document.getElementById('showDangerous').addEventListener('click', () => {
        showDangerousCommands();
    });
    
    document.getElementById('showCommon').addEventListener('click', () => {
        showCommonCommands();
    });
    
    document.getElementById('copyAll').addEventListener('click', () => {
        exportAllCommands();
    });
    

    document.getElementById('openTerminal')?.addEventListener('click', () => {
        window.location.href = 'terminal.html';
    });

    document.getElementById('notificationClose').addEventListener('click', () => {
        hideNotification();
    });
    
    document.getElementById('usageClose').addEventListener('click', () => {
        hideUsagePanel();
    });
    
    document.getElementById('overlay').addEventListener('click', () => {
        hideUsagePanel();
    });
    
    document.getElementById('aboutLink').addEventListener('click', (e) => {
        e.preventDefault();
        showNotification('About CyberKali Hub', 'Interactive interface for Kali Linux commands. Designed for educational purposes only.', 'info');
    });
    
    document.getElementById('printLink').addEventListener('click', (e) => {
        e.preventDefault();
        window.print();
    });
    
}

// Perform search
function performSearch(query, categoryFilter = 'all') {
    if (!query.trim()) {
        clearSearchResults();
        return;
    }
    
    const startTime = performance.now();
    const searchTerm = query.toLowerCase().trim();
    
    // Show results section
    const resultsSection = document.getElementById('resultsSection');
    resultsSection.style.display = 'block';
    searchActive = true;
    
    // Hide category cards
    document.getElementById('commandCategories').style.display = 'none';
    
    // Filter commands
    const results = [];
    
    for (const [categoryId, categoryData] of Object.entries(commandDatabase)) {
        if (categoryFilter !== 'all' && categoryFilter !== categoryId) {
            continue;
        }
        
        categoryData.commands.forEach(cmd => {
            const commandText = cmd.command.toLowerCase();
            const descriptionText = cmd.description.toLowerCase();
            
            if (commandText.includes(searchTerm) || 
                descriptionText.includes(searchTerm) ||
                (cmd.usage && cmd.usage.toLowerCase().includes(searchTerm))) {
                results.push({
                    ...cmd,
                    category: categoryId,
                    categoryTitle: categoryData.title,
                    categoryColor: categoryData.color
                });
            }
        });
    }
    
    currentSearchResults = results;
    
    // Update UI
    updateSearchResults(results);
    
    const endTime = performance.now();
    const searchTime = (endTime - startTime).toFixed(2);
    
    document.getElementById('searchTime').textContent = `Search time: ${searchTime}ms`;
    document.getElementById('resultsCount').textContent = `${results.length} results found for "${query}"`;
    
    // Scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// Update search results display
function updateSearchResults(results) {
    const container = document.getElementById('resultsGrid');
    
    if (results.length === 0) {
        container.innerHTML = `
            <div style="text-align: center; padding: 40px; grid-column: 1 / -1;">
                <i class="fas fa-search" style="font-size: 3rem; color: #666; margin-bottom: 20px;"></i>
                <h3 style="color: #aaa;">No commands found</h3>
                <p style="color: #777;">Try different keywords or browse the categories below</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = results.map(result => {
        const dangerousClass = result.dangerous ? 'dangerous' : '';
        return `
            <div class="command-item ${dangerousClass}" 
                 data-command="${result.command}" 
                 data-category="${result.category}"
                 data-description="${result.description}"
                 style="border-left-color: ${result.categoryColor}">
                <div>
                    <div class="command-text">${result.command}</div>
                    <div style="color: ${result.categoryColor}; font-size: 0.9rem; margin-top: 5px;">
                        <i class="fas fa-tag"></i> ${result.categoryTitle}
                    </div>
                </div>
                <div class="command-desc">${result.description}</div>
            </div>
        `;
    }).join('');
    
    container.querySelectorAll('.command-item').forEach(item => {
        item.addEventListener('click', function() {
            const command = this.dataset.command;
            const category = this.dataset.category;
            const description = this.dataset.description;
            
            copyToClipboard(command);
            showCommandDetails(command, category, description);
        });
    });
}

// Clear search results
function clearSearchResults() {
    searchActive = false;
    currentSearchResults = [];
    
    document.getElementById('searchInput').value = '';
    document.getElementById('resultsSection').style.display = 'none';
    document.getElementById('commandCategories').style.display = 'grid';
    document.getElementById('searchTime').textContent = 'Ready';
    
    // Reset category filter
    toggleCategoryFilter('all');
}

// Show all commands
function showAllCommands() {
    document.getElementById('searchInput').value = '';
    clearSearchResults();
    showNotification('All Commands', 'Showing all 200+ commands across 6 categories.', 'info');
}

// Show dangerous commands
function showDangerousCommands() {
    const dangerousCommands = [];
    
    for (const [categoryId, categoryData] of Object.entries(commandDatabase)) {
        categoryData.commands.forEach(cmd => {
            if (cmd.dangerous) {
                dangerousCommands.push({
                    ...cmd,
                    category: categoryId,
                    categoryTitle: categoryData.title,
                    categoryColor: categoryData.color
                });
            }
        });
    }
    
    // Update UI for dangerous commands view
    const resultsSection = document.getElementById('resultsSection');
    resultsSection.style.display = 'block';
    searchActive = true;
    
    document.getElementById('commandCategories').style.display = 'none';
    document.getElementById('searchInput').value = 'dangerous';
    
    updateSearchResults(dangerousCommands);
    document.getElementById('resultsCount').textContent = `${dangerousCommands.length} dangerous commands`;
    
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    
    showNotification('Warning', 'These commands can cause data loss or system damage. Use with extreme caution!', 'warning');
}

// Show common commands
function showCommonCommands() {
    const commonCommands = [
        ...commandDatabase.basic.commands.slice(0, 10),
        ...commandDatabase.intermediate.commands.slice(0, 8),
        ...commandDatabase.advanced.commands.slice(0, 6)
    ].map(cmd => ({
        ...cmd,
        category: 'basic',
        categoryTitle: 'Common Commands',
        categoryColor: '#00ff9d'
    }));
    
    // Update UI for common commands view
    const resultsSection = document.getElementById('resultsSection');
    resultsSection.style.display = 'block';
    searchActive = true;
    
    document.getElementById('commandCategories').style.display = 'none';
    document.getElementById('searchInput').value = 'common';
    
    updateSearchResults(commonCommands);
    document.getElementById('resultsCount').textContent = `${commonCommands.length} most used commands`;
    
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    
    showNotification('Common Commands', 'These are the most frequently used Kali Linux commands.', 'info');
}

// Export all commands
function exportAllCommands() {
    let exportText = "KALI LINUX COMMANDS REFERENCE\n";
    exportText += "Generated from CyberKali Hub\n";
    exportText += "=".repeat(50) + "\n\n";
    
    for (const [categoryId, categoryData] of Object.entries(commandDatabase)) {
        exportText += `${categoryData.title}\n`;
        exportText += "-".repeat(30) + "\n";
        
        categoryData.commands.forEach(cmd => {
            exportText += `${cmd.command.padEnd(25)} - ${cmd.description}\n`;
        });
        
        exportText += "\n";
    }
    
    copyToClipboard(exportText);
    showNotification('Export Complete', 'All commands copied to clipboard in text format.', 'success');
}

// Show command details in panel
function showCommandDetails(command, category, description) {
    // Find command in database
    let cmdData = null;
    for (const [catId, catData] of Object.entries(commandDatabase)) {
        const foundCmd = catData.commands.find(cmd => cmd.command === command);
        if (foundCmd) {
            cmdData = { ...foundCmd, category: catId, categoryTitle: catData.title };
            break;
        }
    }
    
    if (!cmdData) return;
    
    // Update usage panel
    document.getElementById('usageCommand').textContent = command;
    
    let content = `<p><strong>Description:</strong> ${cmdData.description}</p>`;
    
    if (cmdData.usage) {
        content += `<p><strong>Usage:</strong> <code>${cmdData.usage}</code></p>`;
    }
    
    if (cmdData.example) {
        content += `<div class="usage-example"><strong>Example:</strong><br><code>${cmdData.example}</code></div>`;
    }
    
    if (cmdData.warning) {
        content += `<div class="usage-warning"><strong>⚠ WARNING:</strong><br>${cmdData.warning}</div>`;
    }
    
    content += `<p><strong>Category:</strong> ${cmdData.categoryTitle}</p>`;
    
    document.getElementById('usageContent').innerHTML = content;
    
    // Show panel
    document.getElementById('usagePanel').style.display = 'block';
    document.getElementById('overlay').style.display = 'block';
    
    // Show notification
    showNotification('Command Copied', `"${command}" copied to clipboard.`, 'success');
}

// Hide usage panel
function hideUsagePanel() {
    document.getElementById('usagePanel').style.display = 'none';
    document.getElementById('overlay').style.display = 'none';
}

// Show notification
function showNotification(title, message, type = 'info') {
    const notification = document.getElementById('notification');
    const notificationTitle = document.getElementById('notificationTitle');
    const notificationBody = document.getElementById('notificationBody');
    
    // Set colors based on type
    let borderColor = '#00ff9d';
    if (type === 'warning') borderColor = '#ffcc00';
    if (type === 'danger') borderColor = '#ff003c';
    if (type === 'success') borderColor = '#00ccff';
    
    notification.style.borderColor = borderColor;
    notificationTitle.textContent = title;
    notificationBody.textContent = message;
    notification.style.display = 'block';
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        if (notification.style.display === 'block') {
            hideNotification();
        }
    }, 5000);
}

// Hide notification
function hideNotification() {
    document.getElementById('notification').style.display = 'none';
}

// Copy to clipboard
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        console.log(`Copied: ${text}`);
    }).catch(err => {
        console.error('Failed to copy:', err);
        // Fallback
        const textArea = document.createElement('textarea');
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
    });
}

// Update statistics
function updateStats() {
    let totalCommands = 0;
    let dangerousCount = 0;
    
    for (const categoryData of Object.values(commandDatabase)) {
        totalCommands += categoryData.commands.length;
        dangerousCount += categoryData.commands.filter(cmd => cmd.dangerous).length;
    }
    
    document.getElementById('totalCommands').textContent = `Total Commands: ${totalCommands}`;
    document.getElementById('totalCommandsStat').textContent = `${totalCommands}+`;
    document.getElementById('dangerousCommands').textContent = dangerousCount;
}

// ===== LIVE TERMINAL SIMULATOR =====
class TerminalSimulator {
    constructor() {
        this.history = [];
        this.historyIndex = -1;
        this.currentDirectory = '/home/kali';
        this.user = 'kali';
        this.hostname = 'cyberhub';
        this.commands = this.buildCommandDatabase();
        this.init();
    }
    
    buildCommandDatabase() {
        // Combine all commands from our database
        const allCommands = {};
        
        for (const [category, categoryData] of Object.entries(commandDatabase)) {
            categoryData.commands.forEach(cmd => {
                allCommands[cmd.command.split(' ')[0]] = {
                    ...cmd,
                    category: category,
                    baseCommand: cmd.command.split(' ')[0],
                    args: cmd.command.split(' ').slice(1).join(' ')
                };
            });
        }
        
        // special terminal commands
        return {
            ...allCommands,
            'help': {
                command: 'help',
                description: 'Show available commands',
                usage: 'help [command]',
                category: 'terminal'
            },
            'clear': {
                command: 'clear',
                description: 'Clear terminal screen',
                usage: 'clear',
                category: 'terminal'
            },
            'history': {
                command: 'history',
                description: 'Show command history',
                usage: 'history',
                category: 'terminal'
            },
            'pwd': {
                command: 'pwd',
                description: 'Print working directory',
                usage: 'pwd',
                category: 'basic',
                simulate: () => this.currentDirectory
            },
            'whoami': {
                command: 'whoami',
                description: 'Print current user',
                usage: 'whoami',
                category: 'basic',
                simulate: () => this.user
            },
            'hostname': {
                command: 'hostname',
                description: 'Print system hostname',
                usage: 'hostname',
                category: 'basic',
                simulate: () => this.hostname
            },
            'ls': {
                command: 'ls',
                description: 'List directory contents',
                usage: 'ls [options] [directory]',
                category: 'basic',
                simulate: (args) => this.simulateLs(args)
            },
            'cd': {
                command: 'cd',
                description: 'Change directory',
                usage: 'cd [directory]',
                category: 'basic',
                simulate: (args) => this.simulateCd(args)
            },
            'echo': {
                command: 'echo',
                description: 'Print text',
                usage: 'echo [text]',
                category: 'basic',
                simulate: (args) => args
            },
            'date': {
                command: 'date',
                description: 'Print current date and time',
                usage: 'date',
                category: 'basic',
                simulate: () => new Date().toString()
            }
        };
    }
    
    init() {
        this.terminalInput = document.getElementById('terminalInput');
        this.terminalOutput = document.getElementById('terminalOutput');
        this.autocomplete = document.getElementById('autocompleteSuggestions');
        this.terminalBody = document.getElementById('terminalBody');
        
        this.setupEventListeners();
        this.showWelcomeMessage();
    }

    setupEventListeners() {
        // Terminal input
        this.terminalInput.addEventListener('keydown', (e) => this.handleKeyDown(e));
        this.terminalInput.addEventListener('input', () => this.handleAutocomplete());
        
        // Control buttons
        document.getElementById('terminalClear').addEventListener('click', () => this.clearTerminal());
        document.getElementById('terminalReset').addEventListener('click', () => this.resetTerminal());
        document.getElementById('terminalHelp').addEventListener('click', () => this.executeCommand('help'));
        
        // Click outside to close autocomplete
        document.addEventListener('click', (e) => {
            if (!e.target.closest('.terminal-input-area') && !e.target.closest('.autocomplete-suggestions')) {
                this.autocomplete.style.display = 'none';
            }
        });
    }
    
    showWelcomeMessage() {
        const welcome = `
    <span class="terminal-prompt">=== KALI LINUX TERMINAL SIMULATOR ===</span>
    <span class="terminal-output-text">
    Welcome to the dedicated terminal practice environment!

    This is a <span class="terminal-success">safe simulation</span> where you can practice:
    • Linux command syntax
    • Command-line navigation
    • File system operations
    • Common Kali Linux tools

    <b>Key Features:</b>
    • <span class="terminal-command">Tab completion</span> - Press Tab for suggestions
    • <span class="terminal-command">Command history</span> - Use ↑↓ arrows
    • <span class="terminal-command">Safe environment</span> - No real commands executed
    • <span class="terminal-command">200+ commands</span> - Full Kali Linux command reference

    Type <span class="terminal-command">help</span> to see available commands.
    Type <span class="terminal-command">ls</span> to explore the virtual filesystem.

    ────────────────────────────────────────────────────
    </span>
    <span class="terminal-prompt">${this.user}@${this.hostname}:~$</span> <span class="cursor"></span>
    `;
        
        this.terminalOutput.innerHTML = welcome;
    }

    handleKeyDown(e) {
        // Enter key
        if (e.key === 'Enter') {
            const command = this.terminalInput.value.trim();
            if (command) {
                this.executeCommand(command);
                this.terminalInput.value = '';
                this.autocomplete.style.display = 'none';
            }
            e.preventDefault();
            return;
        }
        
        // Tab key for autocomplete
        if (e.key === 'Tab') {
            e.preventDefault();
            this.completeCommand();
            return;
        }
        
        // Up/Down arrows for history
        if (e.key === 'ArrowUp') {
            e.preventDefault();
            this.navigateHistory(-1);
            return;
        }
        
        if (e.key === 'ArrowDown') {
            e.preventDefault();
            this.navigateHistory(1);
            return;
        }
    }
    
    executeCommand(input) {
        // history
        this.history.push(input);
        this.historyIndex = this.history.length;
        
        // Show command in terminal
        this.printLine(`<span class="terminal-prompt">${this.user}@${this.hostname}:${this.getPromptPath()}$</span> <span class="terminal-command">${input}</span>`);
        
        // Parse command
        const parts = input.split(' ');
        const baseCommand = parts[0].toLowerCase();
        const args = parts.slice(1).join(' ');
        
        // Execute
        setTimeout(() => {
            this.processCommand(baseCommand, args, input);
            // Scroll to bottom
            this.terminalBody.scrollTop = this.terminalBody.scrollHeight;
        }, 50);
    }
    
    processCommand(baseCommand, args, fullCommand) {
        const command = this.commands[baseCommand];
        
        if (!command) {
            this.printLine(`<span class="terminal-error">Command not found: ${baseCommand}. Type 'help' for available commands.</span>`);
            return;
        }
        
        // Special commands
        if (baseCommand === 'clear') {
            this.clearTerminal();
            return;
        }
        
        if (baseCommand === 'help') {
            this.showHelp(args);
            return;
        }
        
        if (baseCommand === 'history') {
            this.showHistory();
            return;
        }
        
        // Simulated commands
        if (command.simulate) {
            try {
                const result = command.simulate(args);
                if (result !== undefined) {
                    this.printLine(`<span class="terminal-output-text">${result}</span>`);
                }
            } catch (error) {
                this.printLine(`<span class="terminal-error">Error: ${error.message}</span>`);
            }
        } else {
            // Show command info for other commands
            this.printLine(`<span class="terminal-output-text">Command: ${command.command}</span>`);
            this.printLine(`<span class="terminal-output-text">Description: ${command.description}</span>`);
            if (command.usage) {
                this.printLine(`<span class="terminal-output-text">Usage: ${command.usage}</span>`);
            }
            if (command.example) {
                this.printLine(`<span class="terminal-output-text">Example: ${command.example}</span>`);
            }
            this.printLine(`<span class="terminal-success">✓ This is a simulated output. In real terminal, this would execute ${command.command}</span>`);
        }
        
        // Show prompt for next command
        this.printLine(`<span class="terminal-prompt">${this.user}@${this.hostname}:${this.getPromptPath()}$</span> <span class="cursor"></span>`);
    }
    
    simulateLs(args) {
        const files = [
            { name: 'Desktop', type: 'directory', permissions: 'drwxr-xr-x' },
            { name: 'Documents', type: 'directory', permissions: 'drwxr-xr-x' },
            { name: 'Downloads', type: 'directory', permissions: 'drwxr-xr-x' },
            { name: 'Pictures', type: 'directory', permissions: 'drwxr-xr-x' },
            { name: 'Music', type: 'directory', permissions: 'drwxr-xr-x' },
            { name: 'Videos', type: 'directory', permissions: 'drwxr-xr-x' },
            { name: 'Public', type: 'directory', permissions: 'drwxr-xr-x' },
            { name: 'Templates', type: 'directory', permissions: 'drwxr-xr-x' },
            { name: '.bashrc', type: 'file', permissions: '-rw-r--r--' },
            { name: '.profile', type: 'file', permissions: '-rw-r--r--' },
            { name: 'README.txt', type: 'file', permissions: '-rw-r--r--' },
            { name: 'hackthebox', type: 'directory', permissions: 'drwxr-xr-x' },
            { name: 'tools', type: 'directory', permissions: 'drwxr-xr-x' },
            { name: 'scripts', type: 'directory', permissions: 'drwxr-xr-x' }
        ];
        
        if (args.includes('-l') || args.includes('-la')) {
            let output = 'total 96\n';
            files.forEach(file => {
                if (!args.includes('-a') && file.name.startsWith('.')) return;
                const randomSize = Math.floor(Math.random() * 10000) + 100;
                const randomDate = new Date(Date.now() - Math.random() * 31536000000);
                const dateStr = randomDate.toLocaleDateString('en-US', { 
                    month: 'short', 
                    day: '2-digit',
                    hour: '2-digit',
                    minute: '2-digit'
                }).replace(',', '');
                
                output += `${file.permissions} 1 ${this.user} ${this.user} ${randomSize.toString().padStart(6)} ${dateStr} ${file.name}\n`;
            });
            return output;
        } else if (args.includes('-a')) {
            return files.map(f => f.name).join('  ');
        } else {
            return files.filter(f => !f.name.startsWith('.')).map(f => f.name).join('  ');
        }
    }
    
    simulateCd(args) {
        if (!args || args === '~') {
            this.currentDirectory = '/home/kali';
            return '';
        } else if (args === '..') {
            this.currentDirectory = this.currentDirectory.split('/').slice(0, -1).join('/') || '/';
            return '';
        } else if (args === '/') {
            this.currentDirectory = '/';
            return '';
        } else if (args.startsWith('/')) {
            this.currentDirectory = args;
            return '';
        } else {
            this.currentDirectory = this.currentDirectory.endsWith('/') 
                ? this.currentDirectory + args 
                : this.currentDirectory + '/' + args;
            return '';
        }
    }
    
    showHelp(args) {
        if (args) {
            const command = this.commands[args.toLowerCase()];
            if (command) {
                this.printLine(`<span class="terminal-output-text"><strong>${command.command}</strong> - ${command.description}</span>`);
                if (command.usage) {
                    this.printLine(`<span class="terminal-output-text">Usage: ${command.usage}</span>`);
                }
                if (command.example) {
                    this.printLine(`<span class="terminal-output-text">Example: ${command.example}</span>`);
                }
                if (command.warning) {
                    this.printLine(`<span class="terminal-error">Warning: ${command.warning}</span>`);
                }
            } else {
                this.printLine(`<span class="terminal-error">No help found for: ${args}</span>`);
            }
        } else {
            this.printLine(`<span class="terminal-output-text">Available commands:</span>`);
            this.printLine(`<span class="terminal-output-text">────────────────────────────────────────────</span>`);
            
            // Group commands by category
            const categories = {};
            Object.values(this.commands).forEach(cmd => {
                if (!categories[cmd.category]) categories[cmd.category] = [];
                categories[cmd.category].push(cmd);
            });
            
            for (const [category, commands] of Object.entries(categories)) {
                if (category === 'terminal') continue;
                
                this.printLine(`<span class="terminal-command">${category.toUpperCase()}:</span>`);
                commands.slice(0, 8).forEach(cmd => {
                    this.printLine(`  <span class="terminal-command">${cmd.command.padEnd(20)}</span> - ${cmd.description}`);
                });
                if (commands.length > 8) {
                    this.printLine(`  <span class="terminal-output-text">... and ${commands.length - 8} more</span>`);
                }
                this.printLine('');
            }
            
            this.printLine(`<span class="terminal-output-text">Type <span class="terminal-command">help [command]</span> for detailed help</span>`);
            this.printLine(`<span class="terminal-output-text">Type <span class="terminal-command">clear</span> to clear the terminal</span>`);
        }
    }
    
    showHistory() {
        if (this.history.length === 0) {
            this.printLine(`<span class="terminal-output-text">No command history</span>`);
            return;
        }
        
        this.printLine(`<span class="terminal-output-text">Command History:</span>`);
        this.history.forEach((cmd, index) => {
            this.printLine(`  <span class="terminal-output-text">${(index + 1).toString().padStart(3)}</span>  <span class="terminal-command">${cmd}</span>`);
        });
    }
    
    handleAutocomplete() {
        const input = this.terminalInput.value.trim();
        if (!input) {
            this.autocomplete.style.display = 'none';
            return;
        }
        
        const suggestions = this.getAutocompleteSuggestions(input);
        if (suggestions.length === 0) {
            this.autocomplete.style.display = 'none';
            return;
        }
        
        this.showAutocompleteSuggestions(suggestions);
    }
    
    getAutocompleteSuggestions(input) {
        const inputLower = input.toLowerCase();
        const suggestions = [];
        
        // Find matching commands
        for (const [cmdName, cmdData] of Object.entries(this.commands)) {
            if (cmdName.startsWith(inputLower)) {
                suggestions.push({
                    command: cmdName,
                    description: cmdData.description,
                    fullMatch: true
                });
            } else if (cmdName.includes(inputLower)) {
                suggestions.push({
                    command: cmdName,
                    description: cmdData.description,
                    fullMatch: false
                });
            }
        }
        
        // Sort: exact matches first, then alphabetical
        suggestions.sort((a, b) => {
            if (a.fullMatch && !b.fullMatch) return -1;
            if (!a.fullMatch && b.fullMatch) return 1;
            return a.command.localeCompare(b.command);
        });
        
        return suggestions.slice(0, 8); // Limit to 8 suggestions
    }
    
    showAutocompleteSuggestions(suggestions) {
        const inputRect = this.terminalInput.getBoundingClientRect();
        this.autocomplete.style.position = 'fixed';
        this.autocomplete.style.left = `${inputRect.left}px`;
        this.autocomplete.style.top = `${inputRect.bottom}px`;
        this.autocomplete.style.width = `${inputRect.width}px`;
        
        this.autocomplete.innerHTML = suggestions.map(suggestion => `
            <div class="autocomplete-item" data-command="${suggestion.command}">
                <span class="autocomplete-cmd">${suggestion.command}</span>
                <span class="autocomplete-desc">${suggestion.description}</span>
            </div>
        `).join('');
        
        this.autocomplete.style.display = 'block';
        
        // click handlers
        this.autocomplete.querySelectorAll('.autocomplete-item').forEach(item => {
            item.addEventListener('click', () => {
                this.terminalInput.value = item.dataset.command;
                this.autocomplete.style.display = 'none';
                this.terminalInput.focus();
            });
        });
    }
    
    completeCommand() {
        const input = this.terminalInput.value.trim();
        if (!input) return;
        
        const suggestions = this.getAutocompleteSuggestions(input);
        if (suggestions.length === 1) {
            // Complete with the only suggestion
            this.terminalInput.value = suggestions[0].command + ' ';
            this.autocomplete.style.display = 'none';
        } else if (suggestions.length > 1) {
            // Show suggestions
            this.handleAutocomplete();
        }
    }
    
    navigateHistory(direction) {
        if (this.history.length === 0) return;
        
        this.historyIndex += direction;
        
        // Bound the index
        if (this.historyIndex < 0) this.historyIndex = 0;
        if (this.historyIndex >= this.history.length) this.historyIndex = this.history.length - 1;
        
        if (this.historyIndex >= 0 && this.historyIndex < this.history.length) {
            this.terminalInput.value = this.history[this.historyIndex];
        }
    }
    
    clearTerminal() {
        this.terminalOutput.innerHTML = '';
        this.printLine(`<span class="terminal-prompt">${this.user}@${this.hostname}:${this.getPromptPath()}$</span> <span class="cursor"></span>`);
    }
    
    resetTerminal() {
        this.history = [];
        this.historyIndex = -1;
        this.currentDirectory = '/home/kali';
        this.showWelcomeMessage();
        this.terminalInput.value = '';
        this.autocomplete.style.display = 'none';
    }
    
    printLine(html) {
        const line = document.createElement('div');
        line.className = 'terminal-line';
        line.innerHTML = html;
        this.terminalOutput.appendChild(line);
    }
    
    getPromptPath() {
        if (this.currentDirectory === '/home/kali') return '~';
        if (this.currentDirectory.startsWith('/home/kali/')) {
            return '~' + this.currentDirectory.substring('/home/kali'.length);
        }
        return this.currentDirectory;
    }
}