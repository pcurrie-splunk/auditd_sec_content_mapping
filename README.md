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
| [Linux AWK Privilege Escalation[(#Linux-AWK-Privilege-Escalation) | d |
| [Linux Ruby Privilege Escalation](#Linux-Ruby-Privilege-Escalation) | d |
| [Linux pkexec Privilege Escalation](#Linux-pkexec-Privilege-Escalation) | d |
| [Linux Deleting Critical Directory Using RM Command](#Linux-Deleting-Critical-Directory-Using-RM-Command) | d |
| [Linux Find Privilege Escalation](#Linux-Find-Privilege-Escalation) | d |
| [Linux Add Files In Known Crontab Directories](#Linux-Add-Files-In-Known-Crontab-Directories) | d |
| [Linux Deletion of SSL Certificate](#Linux-Deletion-of-SSL-Certificate) | b |
| [Linux System Network Discovery](#Linux-System-Network-Discovery) | d |
| [Linux Obfuscated Files or Information Base64 Decode](#Linux-Obfuscated-Files-or-Information-Base64-Decode) | d |
| [Linux Deletion Of Cron Jobs](#Linux-Deletion-Of-Cron-Jobs) | d |
| [Linux Disable Services](#Linux-Disable-Services) | d |
| [Linux Install Kernel Module Using Modprobe Utility](#Linux-Install-Kernel-Module-Using-Modprobe-Utility) | d |
| Linux File Creation In Profile Directory(#Linux-File-Creation-In-Profile-Directory) | d |
| Linux Shred Overwrite Command |
| Linux Kernel Module Enumeration |
| Linux GDB Privilege Escalation |
| Linux APT Privilege Escalation |
| Linux Cpulimit Privilege Escalation |
| Linux apt-get Privilege Escalation |
| [Linux High Frequency Of File Deletion In Etc Folder](#Linux-High-Frequency-Of-File-Deletion-In-Etc-Folder) |
| Linux Octave Privilege Escalation |
| Linux Add User Account |
| Linux Possible Append Cronjob Entry on Existing Cronjob File |
| Linux Possible Access To Sudoers File |
| Linux PHP Privilege Escalation |
| Linux Service File Created In Systemd Directory |
| Linux Visudo Utility Execution |
| Linux Sudoers Tmp File Creation |
| [Linux Possible Append Command To At Allow Config File](#Linux-Possible-Append-Command-To-At-Allow-Config-File) |
| [Linux Busybox Privilege Escalation](#Linux-Busybox-Privilege-Escalation) |
| [Linux Preload Hijack Library Calls](#Linux-Preload-Hijack-Library-Calls) |
| [Linux RPM Privilege Escalation](#Linux-RPM-Privilege-Escalation) |
| Linux Puppet Privilege Escalation |
| Linux SSH Authorized Keys Modification |
| Linux Clipboard Data Copy |
| Linux Deletion Of Init Daemon Script |
| Linux Gem Privilege Escalation |
| Linux Ingress Tool Transfer with Curl |
| Linux High Frequency Of File Deletion In Boot Folder |
| Linux Common Process For Elevation Control |
| Linux GNU Awk Privilege Escalation |
| Linux Possible Access To Credential Files |
| Linux c99 Privilege Escalation |
| Linux Curl Upload File |
| Linux Java Spawning Shell |
| [Linux Deletion Of Services](#Linux-Deletion-Of-Services) |
| Linux Iptables Firewall Modification |
| Linux File Creation In Init Boot Directory |
| Linux Account Manipulation Of SSH Config and Keys |
| Linux At Application Execution |
| Linux Docker Privilege Escalation |
| Linux Service Started Or Enabled |
| Linux Insert Kernel Module Using Insmod Utility |
| [Linux Edit Cron Table Parameter](#Linux-Edit-Cron-Table-Parameter) |
| Linux Possible Cronjob Modification With Editor |
| Linux Setuid Using Chmod Utility |
| Linux Possible Append Command To Profile Config File |
| Linux Decode Base64 to Shell |
| Linux MySQL Privilege Escalation |
| Linux Emacs Privilege Escalation |
| Linux DD File Overwrite |
| Linux Kworker Process In Writable Process Path |
| Linux Ingress Tool Transfer Hunting |
| Linux Adding Crontab Using List Parameter |
| Linux Proxy Socks Curl |
| Linux Change File Owner To Root |
| [Linux Doas Conf File Creation](#Linux-Doas-Conf-File-Creation) |
| Linux Ngrok Reverse Proxy Usage |
| Linux Composer Privilege Escalation |
| Linux OpenVPN Privilege Escalation |
| Linux Csvtool Privilege Escalation |
| [Linux At Allow Config File Creation](#Linux-At-Allow-Config-File-Creation) |
| Linux Sqlite3 Privilege Escalation |
| Linux Persistence and Privilege Escalation Risk Behavior |
| Linux SSH Remote Services Script Execute |
| Linux Make Privilege Escalation |
| Linux Node Privilege Escalation |
| Linux Setuid Using Setcap Utility |
| Linux Sudo OR Su Execution | d |
| Linux Stop Services(#Linux-Stop-Services) | d |
| Linux Service Restarted(#Linux-Service-Restarted) | d |


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

### Linux At Allow Config File Creation

Auditd config: Yes.  ["-w /etc/at.allow -p wa -k atallow", "-w /etc/at.deny -p wa -k atdeny"]
CIM Mapping: file_path, dest, file_create_time, file_name, process_guid.  
Search: No change required.  
Limitations:  
Sample events:    

```
type=PATH msg=audit(02/03/2023 19:04:34.591:925) : item=3 name=/etc/at.deny inode=33563218 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:etc_t:s0 objtype=CREATE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
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

### Linux High Frequency Of File Deletion In Etc Folder

PROCESS & FILESYSYTEM

This is a ttp search - will require new search to be built

### Linux Deletion Of Services

PROCESS

Auditd config: ["-w /etc/systemd -p wa -k servicefiles", "-w /usr/lib/systemd -p wa -k systemdfiles", "-w /bin/systemctl -p x -k systemd"]
CIM Mapping: action, file_path, file_name, dest, process_guid
Search: No change required.  
Limitations:  
Sample events:    

```
zxcv

```





### Linux Busybox Privilege Escalation

PROCESS





### Linux Preload Hijack Library Calls

PROCESS

### Linux RPM Privilege Escalation

Auditd config: 
CIM Mapping: 
Search: No change required.  
Limitations: 
Sample events:    

```

```









### Linux Edit Cron Table Parameter



Auditd config:  
CIM Mapping: 
Search: No change required.  
Limitations: 
Sample events:    

```

```



END.
