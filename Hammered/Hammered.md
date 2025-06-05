## [Hammered](https://cyberdefenders.org/blueteam-ctf-challenges/hammered/) Lab Scenario:
This challenge takes you into virtual systems and confusing log data. In this challenge, as a SOC Analyst figure out what happened to this webserver honeypot using the logs from a possibly compromised server.


## The Logs provided

![](attachments/Screenshot%202025-06-03%20at%204.12.51%20PM%201.png)
## Question 1:
- Which service did the attackers use to gain access to the system?

**Answer: ssh**

We have the `auth.log` file containing successful and failed authentication attempts, especially for the `ssh` service, going through that we see a flood of failed authentication attempts against the root user.
## Question 2:
- What is the operating system version of the targeted system?

**Answer: `4.2.4-1ubuntu3`**


The [kernel ring buffer/dmesg](https://unix.stackexchange.com/a/198185) log records kernel and system messages, including details about the operating system version during boot
## Question 3:
- What is the name of the compromised account?

**Answer: root**

Searched for all successful ssh logins, and narrowed the list to only two usernames that have 4 characters, which gave us `fido` and `root`, `fido` has `uid=0` *(as per the hints given to us)* but it doesn't have as that many failed login attempts as the `root` user.
![](attachments/Screenshot%202025-06-04%20at%201.23.19%20PM.png)
- ##### The question's hints![](attachments/Screenshot%202025-06-04%20at%201.28.50%20PM.png)
## Question 4:
- How many attackers, represented by unique IP addresses, were able to successfully access the system after initial failed attempts?

**Answer: 6** 

To find that, i first listed all *`IP Addresses`* associated with successful login attempts then a run a simple bash script to find the frequency of failed login attempts each `IP Address` had. 

![](attachments/Screenshot%202025-06-04%20at%209.28.43%20PM.png)
#### Here is the script:

[failed_logins.sh](attachments/failed_logins.sh)
## Question 5:
- Which attacker's IP address successfully logged into the system the most number of times?

**Answer: 219.150.161.20**

Run a script that basically filters out successful logins for the root user for each `IP Address` and count it.

![](attachments/Screenshot%202025-06-04%20at%209.50.20%20PM.png)

#### Here is the script:

[successful_logins.sh](attachments/successful_logins.sh)

## Question 6:
- How many requests were sent to the Apache Server?

**Answer: 365**

Did a quick `wc -l` on the apache's access log.

![](attachments/Screenshot%202025-06-04%20at%2010.02.10%20PM.png)
## Question 7:
- How many rules have been added to the firewall?

**Answer: 6**

In the `auth.log` file, we can see `sudo` commands being executed, along them the `iptables` command.

![](attachments/Screenshot%202025-06-04%20at%2010.08.23%20PM.png)

## Question 8:
- One of the downloaded files on the target system is a scanning tool. What is the name of the tool?

**Answer: nmap**

Going through the given log files, we have two log files related for package managers:
`dpkg.log`
`apt/term.log`

and both of contain entries for the tool `nmap`
## Question 9:
- When was the last login from the attacker with IP 219.150.161.20? Format: MM/DD/YYYY HH:MM:SS AM

**Answer: 2010-04-19 05:56**

Simply `grep`'d for successful login attempts for that IP Address and check the date.

## Question 10:
- The database showed two warning messages. Please provide the most critical and potentially dangerous one.

**Answer: `mysql.user contains 2 root accounts without password!`**

the `daemon.log` file contains log entries for services aka `daemons`, and filtering out for mysql service warnings yields the answer.
![](attachments/Screenshot%202025-06-05%20at%2012.54.06%20PM.png)

## Question 11:
- Multiple accounts were created on the target system. Which account was created on **April 26** at **04:43:15**?

**Answer: wind3str0y**

`grep`'ing for `useradd` events in the `auth.log` file with the specified date yields the answer.

![](attachments/Screenshot%202025-06-05%20at%2012.58.49%20PM.png)

## Question 12:
- Few attackers were using a proxy to run their scans. What is the corresponding user-agent used by this proxy?

**Answer: `pxyscand/2.1`**

I guess the question is not well formed, but basically `grep`'ing through the apache's access log file, I found [pxyscand](https://gitlab.chathispano.com/historico/pxysh) (a proxy scanner) User-Agent, with a [`CONNECT`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods/CONNECT) method to the web server, allegedly i guess the attacker trying to see whether the apache server can be used as an http proxy. 

![](attachments/Screenshot%202025-06-05%20at%202.15.52%20PM.png)