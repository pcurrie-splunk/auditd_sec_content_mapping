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

| Search | 
| --- |
| [Linux Possible Ssh Key File Creation](#linux-possible-ssh-key-file-creation) |
| [Linux Possible Access Or Modification Of sshd Config File](#Linux-Possible-Access-Or-Modification-of-sshd-config-file) |
| [Linux File Created In Kernel Driver Directory](#Linux-File-created-In-Kernel-Driver-Directory) |
| [Linux NOPASSWD Entry In Sudoers File](#Linux-NOPASSWD-Entry-In-Sudoers-File) |
| [Linux c89 Privilege Escalation](#Linux-c89-Privilege-Escalation) |
| [Linux Doas Tool Execution](#Linux-Doas-Tool-Execution) |
| [Linux AWK Privilege Escalation[(#Linux-AWK-Privilege-Escalation) |
| [Linux Ruby Privilege Escalation](#Linux-Ruby-Privilege-Escalation) |
| [Linux pkexec Privilege Escalation](#Linux-pkexec-Privilege-Escalation) |
| [Linux Deleting Critical Directory Using RM Command](#Linux-Deleting-Critical-Directory-Using-RM-Command) |
| [Linux Find Privilege Escalation](#Linux-Find-Privilege-Escalation) |
| [Linux Add Files In Known Crontab Directories](#Linux-Add-Files-In-Known-Crontab-Directories) |
| [Linux Deletion of SSL Certificate](#Linux-Deletion-of-SSL-Certificate) |
| [Linux System Network Discovery](#Linux-System-Network-Discovery) |
| [Linux Obfuscated Files or Information Base64 Decode](#Linux-Obfuscated-Files-or-Information-Base64-Decode) |
| [Linux Deletion Of Cron Jobs](#Linux-Deletion-Of-Cron-Jobs) |
| [Linux Disable Services](#Linux-Disable-Services) |
| [Linux Install Kernel Module Using Modprobe Utility](#Linux-Install-Kernel-Module-Using-Modprobe-Utility) |
| Linux File Creation In Profile Directory |
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
| Linux Sudo OR Su Execution |
| Linux Stop Services |
| Linux Service Restarted |![image](https://user-images.githubusercontent.com/111749978/215733461-1d59b737-157e-458d-aef9-dab0f49c62af.png)



START:

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

PROCESS.  

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

### Linux Possible Access Or Modification Of sshd Config File

Process.  


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

PROCESS

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


```

### Linux AWK Privilege Escalation

PROCESS

### Linux Ruby Privilege Escalation

PROCESS

### Linux pkexec Privilege Escalation

PROCESS

### Linux Deleting Critical Directory Using RM Command

PROCESS

### Linux Find Privilege Escalation

PROCESS


### Linux Add Files In Known Crontab Directories

Auditd config: Y  
CIM Mapping: file_path, dest, file_create_time, file_name, process_guid
Search: No change required.  
Limitations: Known crontab config locations only.
Sample events:    

```
type=PATH msg=audit(02/15/2023 09:10:23.932:2535) : item=0 name=/etc/cron.d/ inode=67621834 dev=fd:00 mode=dir,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:system_cron_spool_t:s0 objtype=PARENT cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(02/15/2023 09:10:23.932:2535) : item=1 name=/etc/cron.d/.0hourly.swp inode=67495461 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=unconfined_u:object_r:system_cron_spool_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(02/15/2023 09:10:23.932:2534) : item=0 name=/etc/cron.d/ inode=67621834 dev=fd:00 mode=dir,755 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:system_cron_spool_t:s0 objtype=PARENT cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
type=PATH msg=audit(02/15/2023 09:10:23.932:2534) : item=1 name=/etc/cron.d/0hourly~ inode=67621833 dev=fd:00 mode=file,644 ouid=root ogid=root rdev=00:00 obj=system_u:object_r:system_cron_spool_t:s0 objtype=DELETE cap_fp=none cap_fi=none cap_fe=0 cap_fver=0 
```

### Linux Deletion of SSL Certificate

FILESYSTEM & PROCESS


### Linux System Network Discovery

Datamodel: Endpoint.Processes
Auditd config: Y  
CIM Mapping: Processes.process_name, Processes.process_id, Processes.parent_process_id, Processes.process_guid, Processes.process_name, Processes.dest, Processes.user
Search: 
Limitations: may capture normal event made by administrator during auditing or testing network connection of specific host or network to network
Sample events:    

```

```


### Linux Obfuscated Files or Information Base64 Decode

PROCESS

### Linux Busybox Privilege Escalation

PROCESS


### Linux Deletion Of Cron Jobs

FILESYSTEM & PROCESS

### Linux Disable Services

PROCESS

### Linux Install Kernel Module Using Modprobe Utility

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
