## Question 1:

- To effectively trace the attacker's activities within our network, can you identify the IP address of the machine from which the attacker initially gained access?

==Answer: 10.0.0.130==

Going to ==Statistics -> Endpoints -> IPs==, We have 6 unique ip address possibly from the same subnet:

![[Screenshot 2025-05-29 at 3.48.30 PM.png]]

And looking through the *network captures*, we see host `10.0.0.130` connecting to a `SMB` Server `10.0.0.133`:

![[Screenshot 2025-05-29 at 3.56.52 PM.png]]

## Question 2:

- To fully understand the extent of the breach, can you determine the machine's hostname to which the attacker first pivoted?

 ==Answer : SALES-PC== 

As we know now the first compromised machine is `10.0.0.130` and the machine the attacker is trying to pivot to is `10.0.0.133`, and with that in mind i started looking for `DNS` or `DHCP` packets related to `10.0.0.133`, but nothing was apparent, thus i went for the hints below:

![[Screenshot 2025-05-30 at 11.27.56 AM.png]]

Here, they are instructing us to go look for `SMB's`  ==`Session Setup Response`== Packets that contain a ==`NTLMSSP Challenge`== Message so the target machine can authenticate the client, and with this packet we can extract the target machine's hostname as can be seen below:

![[Screenshot 2025-05-30 at 11.36.59 AM.png]] 

## Question 3:

- Knowing the username of the account the attacker used for authentication will give us insights into the extent of the breach. What is the username utilized by the attacker for authentication?

 ==Answer : ssales 

As noted from the previous question, we saw authentication packets being exchanged, and looking through the packets from the client's side aka the `SMB's` ==`Session Setup Request`== packets, we find the username the client is trying to authenticate with as show below:


![[Screenshot 2025-05-30 at 11.47.10 AM.png]]

The question's hints just for the record:

![[Screenshot 2025-05-30 at 11.56.48 AM.png]]


## Question 4:

- After figuring out how the attacker moved within our network, we need to know what they did on the target machine. What's the name of the service executable the attacker set up on the target?

==Answer: PSEXESVC==

After `10.0.0.130`'s network traffic of file uploading on `10.0.0.133`'s `SMB` share, we notice `MS-RPC` traffic from `10.0.0.130` to `10.0.0.133`, and it seems about managing a service:


![[Screenshot 2025-05-30 at 12.34.13 PM.png]]


Scrolling below that we a see a file upload of a file named `PSEXESVC`:


![[Screenshot 2025-05-30 at 12.41.13 PM.png]]

Here is the Question's hints as an explanation:

![[Screenshot 2025-05-30 at 12.47.27 PM.png]]

## Question 5 && Question 6:

- We need to know how the attacker installed the service on the compromised machine to understand the attacker's lateral movement tactics. This can help identify other affected systems. Which network share was used by PsExec to install the service on the target machine?

- We must identify the network share used to communicate between the two machines. Which network share did PsExec use for communication?

==Answer 5: ADMIN$==

==Answer 6: IPC$==

At the beginning of the network capture, we see a request for two `SMB`'s shares:

![[Screenshot 2025-05-30 at 12.58.19 PM.png]]

And we can see the ==`ADMIN$`== share used for the file upload:

![[Screenshot 2025-05-30 at 1.01.31 PM.png]]

Scrolling down much more reveals a pattern of read and creation requests of what seems like input/output/error output files on the ==`IPC$`== share:

![[Screenshot 2025-05-30 at 1.03.18 PM.png]]![[Screenshot 2025-05-30 at 1.04.17 PM.png]]

The questions's hints explain this behavior:

![[Screenshot 2025-05-30 at 1.07.34 PM.png]]
![[Screenshot 2025-05-30 at 1.08.01 PM.png]]

## Question 7:

- Now that we have a clearer picture of the attacker's activities on the compromised machine, it's important to identify any further lateral movement. What is the hostname of the second machine the attacker targeted to pivot within our network?

Applying the following filter:

`ip.addr == 10.0.0.130 and smb2 and ip.addr != 10.0.0.133`

we filter out the first pivoted machine's ip, thus we find the compromised  machine `10.0.0.130`
trying to pivot to `10.0.0.131`

![[Screenshot 2025-05-30 at 1.38.28 PM.png]]