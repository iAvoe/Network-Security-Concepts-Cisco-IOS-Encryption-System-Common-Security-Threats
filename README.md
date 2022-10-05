### Network Security Concepts

 - **Security breaches can**:
    - disrupt e-commerce
    - loss business data
    - threaten privacy
    - compromise information integrity
    - lost revenue for corporations
    - lost of user-customer's trust for stakeholders
    - theft of intellectual property lawsuits
    - threat public safety

 - A secure network ensures safety of users, protects commercial interests

 - Network security requires vigilance on org. professional who:
    - constantly be aware of new & evolving threats and attacks, vulnerabilities of devices & apps

<br>

### Risk Management in biz.

 - based on specific principles and concepts related to:
   - asset protection
   - security management

<br>

 - **Security terms**:
   - **Asset**
     - Governmental class
     - Private sector class
     - Classification criteria
     - Classification roles
     - **Traffic light protocol (TLP-RAGW)**
       - RED:      high impact; No disclosure; only available for participants
       - AMBER: mid-impact; Limit disclosure; available for participants' org.
       - GREEN: low-impact; Limit disclosure, available for community
       - WHITE: none

   - **Vulnerability**
     - Human factors
     - Policy/protocol flaws
     - Malicious software/code
     - Soft/Hardware vulnerabilities
     - Design errors/bad configuration
     - Physical access to network resources

   - **Threat**
   - **Risk**
   - **Countermeasure**
     - Admin policies, procedures, guidelines, standards, e.g.,  security policy
     - Physical infrastructure, soft/hardware setup
     - Technical / Logical controls, acct management, VPN tunnels, Intrusion Prevension Systems

 - **Confidientiality · Integrity · Authentication (CIA)**
   - A triad model for all organizations

   - Confidientiality implementations are:
     - Data encryption
       - Authentication  = Private Key (Encrypt) + Public Key (Decrypt)
       - Confidentiality  = Public Key (Decrypt) + Private Key (Encrypt)
     - User IDs and passwords 
     - Two-factor authentication is becoming the norm. 
     - Biometric verification
     - Security tokens
     - Key fobs
     - Soft tokens

   - Extreme confidientiality implementations are:
     - Air gapped server
     - Unplugged storage
     - Hard-copy-only documentation
     - Classified via data importance

   - Integrity implementations are:
     - Hashing / ECC Memory
     - Server room with air conditioning, backup power

   - **Availibility implementations are**:
     - Maintaining all hardware, including necessary upgrades
     - Maintaining a healthy, software conflict-free OS
     - Adequate data bandwidth, prevent transmission bottlenecks
     - Redundancy / RAID / High-availability clusters (HA Clusters)
     - Railover

<br>

 - **Security Information Event Mgmt. (SIEM)**
    - Real-time event reporting solution
    - Comprised from **Security Info Mgmt. (SIM)** & **Security Event Mgmt. (SEM)**
    - Example: Cisco Identity Services Engine (ISE) 
    - **SIEM provides**:
      - Forensic analysis: automatically interpret event logs
      - Correlation: co-relate multiple systems & apps (device, user, posture info), which makes reaction fast
      - Aggregation: help network security engineers to assess the significance of security events

<br>

 - **IoT Privacy**
   - Devices that could communicate automatically over Internet via their UID
   - A single device usually doesn't cause security issue
   - Analyzing fragmented data from multiple sources could yield sensitive info
   - IoT nodes could be unpatched forever, set with weak passwords, e.g. WiFi light bulb leaked WiFi password
   - In 2013, over 100,000 hacked appliances formed a botnet and created thousands of spam emails

<br>

 - **Vector of Attacks (VoA)**
   - paths available for attackers to gain access to network
   - Inside & outside
 - **Vector of Data Loss (VoDL)**
   - Pathes that attackers to take data away
     - Email
     - Unprotected cloud storage
     - Lost hard copy
     - Bad access control
     - Lost & unencrypted laptop
     - Lost removable storage

<br>

 - **Data Center Networks**:
   - Typically housed in an off-site facility
   - Interconnected to corporate site via VPN with ASA devices
   - Stores vast amount ot sensitive, business critical info
   - Physical security is critical
   - Armed with:
     - fire alarms & sprinklers
     - seismically-braced server racks
     - redundant heating, ventilation, and air conditioning (HVAC)
     - UPS systems
     - Mantrap door system
     - Network closets
     - **Outside perimeter security**:
       - officers
       - fences & gates
       - video surveillcance
     - **Inside perimeter security**:
       - motion detectors
       - security traps
       - biometric access
       - video surveillcance

<br>

 - **Clouds & Virtual Networks**:
   - Data storage & computing (application) services
   - No longer prone to VM-Specific threats e.g.,:
     - **Hyperjacking**: when attacker hijack VM hypervisor to launch attack on DC network
     - **Instant on activation**: an old VM with outdated security policies could be compromised
     - **Antivirus storms**: when all VMs tries to download virus database at the same time

<br>

 - **Bring your own device (BYOD)** policy:
   - Company to cut cost and allow employees to use their phone and laptop to work
     - Reduce training & device cost
     - Increase security problem
   - Cisco has developed **Borderless Network*** to allow access to resources on many types of endpoints, via various of connection methods
     - Cisco **Mobile Device Management (MDM)**
     - Features secure, monitor and management of mobile devices

<br>

 - **Cisco MDM Features**:
   - Data Encryption: e.g., bitlocker, makes PIN bypass impossible
   - PIN Enforcement: force PIN locking of mobile devices to prevent loss or device
   - Data Wipe: remotely wipe lost devices
   - Data Loss Prevention (DLP): Prevents accidental or malicious deletion of critical data
   - Jailbreak/Root Detaction: restrict devices that could bypass MDM features

<br>

 - **Hackers**
   - **Black hat**: malicious, unethical criminals who earn from breaking corporate networks and steal data
   - **White hat**: ethical hackers who earns from network penetration testing
   - **Gery hat**: compromises a network without permission and then discloses the vulnerability publicly, however not earning from stealing data
   - **Cybercriminicals**: black hat hackers who are often financed by org., also operates an underground market for *attack toolkits, zero day exploit codes, banking trojans*
   - **Hacktivists**: people who hack for attention
   - **State-sponsored Hackers**: usually a group of hacker who work for a country

<br>

 - **Penetration testing tools**
   - Password Crackers
   - Wireless Hacking Tools
   - Network Scanning and Hacking Tools
   - Packet Crafting Tools
   - Packet Sniffers
   - Rootkit Detectors
   - Fuzzers to search Vulnerabilities
   - Forensic Tools
   - Debuggers
   - Hacking Operating Systems
   - Encryption Tools
   - Vulnerability Exploitation Tools
   - Vulnerability Scanners

<br>

### Cisco IOS Encryption System

**Block cipher** converts a block of text at a time
**Stream cipher** converts 1 byte at a time

<br>

 - ***Data Encryption Standard (DES)**
   - Now considered to be insecure due to the 56-bit key size being small
   - Suspected with NSA backdoor
 - **Advanced Encryption Standard AES**
   - NSA has approved 128bit AES for up to SECRET level
   - NSA has approved 192bit AES for up to TOP SECRET level
   - Supports up to 256bit key size
   - Based on Rijndael algorithm
 - **3DES**
   - 256x stronger than DES
   - Takes a 64-bit block of data & performs 3DES operations in sequence:
   - Encrypts, decrypts, and encrypts. 
 - **Software-optimized Encryption Algorithm SEAL**
   - Designed in 1993
   - Supports 160bit key size
   - **Pros**: stream cipher, secure and much faster than block
   - **Cons**: longer initialization phase

<br>

 - **Ronald Rivest (RC) Algorithms**
   - Widely deployed in networking apps
     - **Pros**: Speed & Variable key size
   - Variations include:
     - RC2: Designed as a "drop-in" replacement of DES
     - RC4: Most used stream cipher for file & comms enc., e.g., SSL (https)
     - RC5: A fast block cipher with variable block size & key size
     - RC6: Was an AES finalist but lost, supports 128/256bit block cipher

<br>

**Symmetric keys**: also called private-key algorithms, one key for enc & dec

**Symmetric key algorithms**: 
 - MD5: 128bit
 - DES: 56bit
 - AES: 128, 192, 256bit
 - 3DES: 112, 168bit
 - SEAL: 160bit
 - RC2: 40, 64bit
 - RC4: 1~256bit
 - RC5: 0~2040bit
 - RC6: 128, 192, 256bit

**Asymmetric keys**: also called public-key algorithms, diff key for enc & dec
 - Internet Key Exchange (IKE)
 - Secure Socket Layer (SSL)
 - Secure Shell (SSH)
 - Pretty Good Privacy (PGP)

**Asymmetric key algorithms**:
 - Diffie-Hellman (DH): 512, 1024, 2048bit
 - Digital Signature Standard (DSS), DSA incorporated: 512~1024bit
 - RSA: 512~2048bit
 - ElGamal: 512~1024bit
 - Elliptical curve cryptography (ECC): 160bit

<br>

 - **Bulk data encryption - symmetric keys**
     - Best method is AES
     - 2nd best is 3DES, SEAL, RC6

<br>

 - **Creating Hash**
   - **Message Digest 5 (MD5)**
     - An internet standard (RFC 1321)
     - Typically expressed as a 32char hex
     - Design flaw was found in 1996, cryptographers switched to SHA
   - **SHA1**
     - Designed by NSA with SHA-2
     - MD5 takes 64 steps, SHA-1 involves 80
     - Employed in TLS and SSL, PGP, SSH, S/MIME, and IPSec
   - **SHA224, SHA256, SHA384, SHA512**
     - Collectively referred as SHA-2
     - Algorithmically similar to SHA-1
   - **SHA-3**
     - Competition accounced in Federal Register on Nov 2, 2007
       - Winner was Keccak algorithm created by Guido Bertoni, Joan Daemen, Gilles Van Assche, Michaël Peeters

<br>

 - **Data Intrgrity**
   - **Hashing Message Auth. Code (HMAC, KHMAC)**
     - Output of hash function depends on input data, & secret key
     - Guaranteed authenticity because only sender andreceiver knows secret key
     - Without secret key, HMAC function cannot be solved by man-in-mid attack
     - HMAC-MD5; HMAC-SHA-1

<br>

 - **Key management system (KMS)**
   - The most difficult part of cyptosystem
   - Many cryptosystems failed because of bad key management
   - Modern cryptoalgorithms require key management procedures
   - Most attacks on cryptosystems are aimed at key management
   - **Key Generation (Keygen)**
     - key Size/Length/Space
       - e.g., 256bit key is 2x key size than 128bit
   - **Key Verification**
   - **Key Exchange**
   - **Key Storage**
   - **Key Lifetime**
   - **Key Revoke-Destruction**

<br>

 - **Diffie-Hellman Asymmetric Key Exchange**
   1. Each side of the comms generates a private key, a public key
   2. Both side exchange the public key
   3. Diffie-Hellman protocol have a Certificate that confirms the public key is indeed coming from the right source
   4. A crypto key is generated by each side
   5. For every comms, both sides computes an identical value via DH-Math, which is not exchanged and works as the secret key
   6. The secret keys are never shared, which makes the process asymmetric

<br>

 - **Digital Signature Security Services**
   - Provides a unique proof of data source
   - Authenticate a user by private key
   - Provide nonrepudiation using a secure timestamp, and trusted time source
   - Each party has a unique, secret signature key, making nonrepudiation possible
   - **Authenticity of digitally signature**: proving that a certain party has seen and signed a document
   - **Integrity of digitally signed data**: guarantee that the data has not changed since document was signed
   - **Nonrepudiation of the transaction**: 3rd partry accepts digitical signature that data exchange was taken place, signing party cannot repudiate that it has signed the data

<br>

 - **RSA Encryption**
   - By Ron Rivest, Adi Shamir, and Leonard Adleman at MIT in 1977
   - Encryption of factoring very large numbers
   - Fhe 1st algorithm known to be suitable for signing
   - Widely used in Electronic Commerce Protocols
   - 10~40x faster than DSS-DSA
   - Doesn't make huge encrypted message unlike ElGamal

<br>

**Certitication Authority (CA)**: The source entity that issues the cert

 - **Digital Certificate File**
   - **Subject-Name**
     - Provides non-repudiation, authenticity, intergrity
   - Subject-Public-key
   - **CA-Info**
     - Issue date
     - Valid peroid
     - CA identity
   - **CA-Private-key**
     - Used for {Subect-Name} to generate digital signature
   - **CA-Digital-Signature**
     - Provides non-repudiation, authenticity (of CA), intergrity

   - **CA-Public-key**
     - The public key owner can use to verify that this digital cert is valid

<br>

 - **Public key (PKI) Structure / Framework**:
   - The technical, organizational, and legal components for a large scale used system to provide authenticity, confidentiality, integrity, and nonrepudiation
   - Consists of the hardware, software, people, policies, and procedures
   - Creates, manage, store, distribute, revoke certificates
 - **PKI Certificates**
   - Used for various purposes
   - Contain the binding between names and public keys
   - Published in a centralized directory for easy user access
 - **PKI Certificate Authority (CA)**:
   - A trusted 3rd party entity that issues certificates
   - Every CA also has a certificate containing its public key, signed by itself
     - A self-signed CA certificate

<br>

### Network Attacks

 - **Reconnaissance attacks / Info gathering attack**
   1. Query of information - find target network
   2. Initiate a ping sweep - determine active IP addresses
   3. Port Scanning------- determine available ports & services
   4. Vulnerbility scaning -- query identified ports to learn version of app, OS to seek vulnerbilities
   5. Exploit ------------- discover exploits via vulnerbilities
 - **Access attacks / Common vulnerabilities attack**
   - To retrieve data, gain access & escalate access priviledges on:
     - Auth services
     - FTP services
     - Web services
   - Password attack
   - IP, MAC, DHCP spoofing
   - Buffer overflow
   - MITM
   - Port redirect
   - Trust exploit
   - Covert Channel
   - Code Exec
   - Botnets
   - Brute Force / Rainbow table
   - **Social Engineering**
     - Pretexting
     - Phishing
     - Spear Phishing
     - SPAM
     - Tailgating
     - Something for Something (Quid pro quo)
     - Baiting
 - **DoS attacks**
   - **Maliciously Formatted Packets attack (MFP)**
     - A packet that contain errors for apps to identify
     - A improperly formatted packet
     - Causes receiving devices to slow down or crash
   - **Overwhelming traffic**
     - Eats server hardware resources by sending overwhelming queries
     - Considers as a major risk, because it is very easy to conduct and cause significate loss
     - **TCP SYN Flood attack**
       - A hacker sends many TCP SYN session
       - Target replies with TCP SYN-ACK and waits for TCP ACK
       - Hacker does not respond TCP ACK, server gets stuck with overwhelmed TCP half-open connections
     - **DDoS attack**
       - Sloworis - send adquate amount of TCP queries depend of server tables, makes the attack hard to detect
       - **Collision hashing**
         - Send http server with report that there is a hash fault
         - HTTP server will recompute all the hashes for it's clients
         - High vulnerbilities for servers that uses strong encryption

<br>

### End Device Attacks

 - **Viruses**
   - Malicious code that is attached to executable files 
   - Usually require end user activation
   - Can be harmless or distructive
   - Now spread by removable storages & emails
 - **Worms**
   - Self replicatating code exploiting vulnerabilities in end devices in network
   - Always run by themselves
   - Responsible for some of the most devastating attacks on internet
 - **Trojan Horse**
   - Hide malicious code inside
   - Difficult to detect
   - **Flexible concept**:
    - Security software disabler Trojan
    - Remote-access Trojan
    - Data-sending Trojan
    - Destructive Trojan
    - Proxy Trojan
    - DoS Trojan
    - FTP Trojan
 - **Malwares**
   - **Rootkits**: gain root priviledge for hacker and hide it's intrusion
   - **Phishing**: Attempts to convince people to divulge sensitive inforamtion
   - **Scareware**: creating the perception of a threat to scam
   - **Adware**: displays annoying ad pop-ups, may tracking the websites visited
   - **Spyware**: gather info about a user and send to another entity
   - **Ransomware**: denies access to the infected computer, then demands payment

<br>

### Network Security Domains

 - There are 12 network security domains specified by ISO/IEC 27002
   1. **Risk Assessment**
     - Quantity and quality value of risk related to risk situations
   2. **Security Policy**
     - Document that addresses the constraints and behaviors of members
     - How data can be accessible, & by whom
   3. **Org. of Information Security**
     - Governance model for info security
   4. **Asset Mgmt.**
     - Inventory of & classification scheme for info assets
   5. **Human Resources (HR) Security**
     - Security procedures relating to employees joining, leaving org.
   6. **Physical & Environmental Security**
     - Protection of computer facilities
   7. **Comms & Operations Mgmt.**
     - Mgmt. on technical security controls in systems, networks
   8. **Information System Acquisition, Development & Maintenance**
     - Integration of security info apps
   9. **Access Control**
     - Clear definition of user ristriction
   10. **Information Security Incident Mgmt.**
     - How to anticipate and respond to inforamtion security breaches
   11. **Business Continuity Mgmt.**
     - protection, maintenance and recovery of critical systems
   12. **Compliance**
     - process of ensuring conformance with security policies, standards

<br>

 - **Best Practices**
   - Develop a written security policy for the company.
   - Educate employees about the risks of social engineering, and develop strategies to validate identities over the phone, via email, or in person.
   - Control physical access to systems.
   - Use strong passwords and change them often.
   - Encrypt and password-protect sensitive data.
   - Implement security hardware and software such as firewalls, IPSs, virtual private network (VPN) devices, antivirus software, and content filtering.
   - Perform backups and test the backed up files on a regular basis.
   - Shut down unnecessary services and ports.
   - Keep patches up-to-date by installing them weekly or daily, if possible, to prevent buffer overflow and privilege escalation attacks.
   - Perform security audits to test the network

<br>

 - **Mitigating Malware**
   - Deploy Antivirus software
   - Keep antivirussoftware updated
     - Note: antivirus are host-based, they do not prevent viruses from entering network

<br>

 - **Mitigating Worms**
   - Inoculation: runs parallel to or subsequent to the containment, patch uninfected systems
   - Containment: compartmentalization, segmentation of the network to slow down or stop the worm 
   - Containment --> Quarantine: track down, identify infected machines, disconnect them from network
   - Treatment: actively disinfecting infected systems

<br>

 - **Mitigating Reconnaissance Attacks**
  - Use proper authentication
  - Use encryption to stop packet sniffer
  - Use anti-sniffer tools to detect packet sniffer attacks
  - Implement a switched infrastructure
  - Use firewall & IPS

<br>

 - **Mitigating Access Attacks**
  - Use strong passwords
  - Disable account after a few unsuccessful login attempts
  - Design network security policy with minimum trust
  - Use encrypted or hashed auth protocols
  - Review logs

<br>

  - **Mitigating DoS Attacks**
  - 24x7 Monitor network utilization
  - Notice first signs: a large number of user complaint about unavailability
  - Entire geographical regions of Internet connectivity could be compromised
  - Antispoofing technologies on routers & switches:
     - Port security
     - Dynamic Host Configuration Protocol (DHCP) snooping
     - IP Source Guard
     - Dynamic Address Resolution Protocol (ARP) Inspection
     - Access control lists (ACLs).

<br>

**Network Foundation Protection (NFP)**
 - systematically breaking down the infrastructure into smaller components
 - systematically focusing on how to secure each component
 - 3 major criteria:
   - **Management Plane**
     - Allow admins to communicate with device, receive reports/log messages
       - SSH, CCP, Syslog, SNMP
     - Methods:
       - Encrypt management protocls
       - Authentication, authorization, and accounting (AAA)
       - Login restrictions and login timeouts
       - Role based access control (RBAC)
       - Secure NTP
   - **Control Plane**
     - Device or user requests
       - Routing protocol updates/keepalives
       - Traffic directed to the IP address of the router
     - Methods:
       - Authenticate routing protocols
       - Control Plane Policing & Protection Features
   - **Data Plane**
     - Transit packets from one end device to another
     - Methods:
       - ACLs
       - STP safeguards
       - Port Security
       - firewalls
       - IDS/IPS
       - zone-based firewalls
 - NFP is not just a single feature on a network, but rather a combination

<br>

## Examination
### Question 1
 Which two components does HMAC use to determine the authenticity and integrity of a message? (Choose two.)

 - The password
 - The key
 - The hash
 - The transform set
 
<br>

### Question 2
Which security term refers to a person, property, or data of value to a company?

 - Asset
 - Risk
 - Threat prevention
 - Mitigation technique
 
<br>

### Question 3
Which example is of a function intended for cryptographic hashing?

 - SHA-135
 - MD65
 - XR12
 - MD5
 
<br>

### Question 4
Which of the following are two methods are used by hackers? (Choose two.)

 - Social engineering attack
 - Trojan horse attack
 - buffer Unicode attack
 - front door attacks
 
<br>

### Question 5
What does the key length represent?

 - Hash block size
 - Cipher block size
 - Stream block size
 - Number of permutations
 
<br>

### Question 6
Which encryption method uses more overhead and is typically reserved for low-volume cryptographic mechanisms?

 - Asymmetric
 - Advance encryption
 - Symmetric
 - Simple encryption
 
<br>

### Question 7
For the following statements, which one is the strongest symmetrical encryption algorithm?

 - 3DES
 - DES
 - AES
 - MD5
 - SHA-1
 
<br>

### Question 8
Which description about asymmetric encryption algorithms is correct?

 - They use different keys for decryption but the same key for encryption of data.
 - They use the same key for encryption and decryption of data.
 - They use different keys for encryption and decryption of data.
 - They use the same key for decryption but different keys for encryption of data.
 
<br>

### Question 9
What is the MD5 algorithm used for?

 - takes a variable-length message and produces a 168-bit message digest
 - takes a fixed-length message and produces a 128-bit message digest
 - takes a variable-length message and produces a 128-bit message digest
 - takes a message less than 2^64 bits as input and produces a 160-bit message digest
 
<br>

### Question 10
What mechanism does asymmetric cryptography use to secure data?

 - a public/private key pair
 - shared secret keys
 - an RSA nonce
 - an MD5 hash
 
<br>

### Question 11
Which component of CIA triad relate to safe data which is in transit?

 - Integrity
 - Confidentiality
 - Availability
 - Scalability
 
<br>

### Question 12
Which statement provides the best definition of malware?

 - Malware is unwanted software that is harmful or destructive.
 - Malware is software used by nation states to commit cyber crimes.
 - Malware is a collection of worms, viruses, and Trojan horses that is distributed as a single package.
 - Malware is tools and applications that remove unwanted programs.
 
<br>

### Question 13
Which option ensures that data is not modified in transit?

 - Authentication
 - Integrity
 - Authorization
 - Confidentiality
 
<br>

### Question 14
Hardware locks, keypads on entry doors, badge readers, and biometric readers are all examples of which of the following security types?

 - Physical
 - Logical
 - Software
 - Authentication
 
<br>

### Question 15
Why is UDP the "protocol of choice" for reflected DDoS attacks?

 - UDP requires a three way handshake to establish a connection.
 - There are more application choices when using UDP.
 - UDP is much more easily spoofed.
 - TCP cannot be used in DDoS attacks.
 
<br>

### Question 16
In which stage of an attack does the attacker discover devices on a target network?

 - Reconnaissance
 - Covering tracks
 - Gaining access
 - Maintaining access
 
<br>

### Question 17
SYN flood attack is a form of ?

 - Reconnaissance attack
 - Denial of Service attack
 - Spoofing attack
 - Man in the middle attack
 
<br>

### Question 18
If an attacker in a SYN flood attack uses someone else’s valid host address as the source address, the system under attack will send a large number of Synchronize/Acknowledge (SYN/ACK) packets to the

 - default gateway.
 - attacker’s address.
 - local interface being attacked.
 - specified source address.
 
<br>

### Question 19
Which of these characteristics is a feature of AES?

 - It is not supported by hardware accelerators but runs very fast in software
 - It provides strong encryption and authentication
 - It has a variable key length
 - It should be used with key lengths greater than 1024 bits
 
<br>

### Question 20
Which tool can an attacker use to attempt a DDoS attack?

 - Botnet
 - Trojan horse
 - Adware
 - Virus
 
<br>

### Question 21
Which of these is the best way to provide sender non-repudiation?

 - secure hash
 - SSL
 - pre-shared key
 - RSA signature
 
<br>

### Question 22
You need to create an access list that will prevent hosts in the network range of 192.168.160.0 to 192.168.191.0. Which of the following lists will you use?

 - access-list 10 deny 192.168.160.0 255.255.224.0
 - access-list 10 deny 192.168.160.0 0.0.191.255
 - access-list 10 deny 192.168.160.0 0.0.31.255
 - access-list 10 deny 192.168.0.0 0.0.31.255
 
<br>

### Question 23
What is the default behavior in an ACL when there is a match on a deny statement in an ACL?

 - The rest of the ACL is processed, in order, to run other permit statements.
 - The rest of the ACL is processed, in order, to run other deny statements.
 -The implicit permit overrides the explicit deny in the matched entry.
 - No other processing of the ACL, for the packet being considered, is performed.
 
<br>

### Question 24
Will the following ACL configuration prevent 192.168.1.80 from using Telnet to reach the router at 15.2.41.1?

 > access-list 1 deny 192.168.1.80 0.0.0.0 access-list 1 permit any
 > 
 > 
 > 
 > line vty 0 4
 > 
 > ip access-group 1 in

 - Yes, the configuration is perfect.
 - No, the ACL is wrong.
 - No, the destination is not specified.
 - No, the ACL is correct but the command to apply the ACL is wrong.
 - Yes, but the ACL must be extended to properly block Telnet.
 
<br>

### Question 25
Which statement is a guideline to be followed when designing access control lists?

 - Since ACL tests are executed in order, they should be organized from the most general conditions to the most specific.
 - Since ACL tests are executed in order, they should be organized from the most specific condition to the most general.
 - Since all statements in an ACL are evaluated before they are executed, an explicit deny any statement must be written in order for an ACL to function properly.
 - Since all statements in an ACL are evaluated before they are executed, an explicit permit any statement must be written in order for an ACL to function properly.
 
<br>

### Question 26
Use the ____ command to remove the application of the list.

 > no accessgroup [ip][list #][direction]
 > 
 > no ip [accessgroup][list #][direction]
 > 
 > no ip access-list [list #][direction]
 > 
 > no ip access-group [list #][direction]
 
<br>

### Question 27
What command would can you enter to verify that an access list has been applied on your interface?

 - show ip interface brief
 - show access-list
 - show ip access-list
 - show ip interface
 
<br>

### Question 28
You have created a named access list called Blocksales. Which of the following is a valid command for applying this to packets trying to enter interface Fa0/0 of your router?

 - (config)#ip access-group 110 in
 - (config-if)#ip access-group 110 in
 - (config-if)#ip access-group Blocksales in
 - (config-if)#Blocksales ip access-list in
 
<br>

### Question 29
Which of the following commands matches all IP packets that are sourced from subnet 172.16.32.0/22, destined to subnet 172.16.48.0/23?

access-list 101 permit ip 172.16.32.0 0.0.3.63 172.16.48.0 0.0.1.127

 > access-list 101 permit ip 172.16.32.0 0.0.3.0 172.16.48.0 0.0.1.0
 > 
 > access-list 101 permit ip 172.16.32.0 0.0.3.255 172.16.48.0 0.0.1.255
 > 
 > access-list 101 permit ip 172.16.32.0 0.0.3.255 172.16.48.0 0.0.3.255
 
<br>

### Question 30
Regarding extended IP access lists, the ____ keyword is short for a wildcard mask of 0.0.0.0.

 - host
 - any
 - none
 - all
 
<br>

### Question 31
You are the network administrator for the Widgets Company.  You configure a Web server on the network using the IP address 64.12.13.15. 

You want to allow users outside the network to access this Web site.  You want to configure an access list on the router connecting the network to the Internet.

Which access list should you configure to accomplish this task?

 - access-list 101 permit ip any host 64.12.13.15
 - access-list 1 permit ip any host 64.12.13.15
 - access-list 1 permit ip host 64.12.13.15 any
 - access-list 101 permit ip host 64.12.13.15 any
 
<br>

### Question 32
Unauthorized users have used Telnet to gain access to a company router. The network administrator wants to configure and apply an access list to allow Telnet access to the router, but only from the network administrator’s computer.

Which group of commands would be the best choice to allow only the IP address 172.16.3.3 to have Telnet access to the router?

 > access-list 101 permit tcp any host 172.16.3.3 eq telnet
 > 
 > interface s0/0
 > 
 > ip access-group 101 in
 > 
 > 
 > 
 > access-list 3 permit host 172.16.3.3
 > 
 > line vty 0 4
 > 
 > access-class 3 in
 > 
 > 
 > 
 > access-list 101 permit tcp any host 172.16.3.3 eq telnet
 > 
 > access-list 101 permit ip any any
 > 
 > interface s0/0
 > 
 > ip access-group 101 in
 > 
 > 
 > 
 > access-list 3 permit host 172.16.3.3
 > 
 > line vty 0 4
 > 
 > ip access-group 3 in
 
<br>

### Question 33
You are the network administrator for the Widgets Company.  As a part of improving network security, you are configuring ACLs on the routers in the network.

You wnat only host with IP addresses 172.16.20.4 through 172.16.20.7 and the host with IP address 172.16.22.4 to be able to telnet into Router A.  You configure the following on Router A:

 > access-list 1 permit 172.16.20.4 0.0.0.7
 > 
 > access-list 1 permit 172.16.22.4
 > 
 > line vty 0 4
 > 
 > access-class 1 in

You discover during testing that a host with an IP address of 172.16.20.3 is able to telnet into the router. What would you do to correct this problem?

 - Add access-list 1 deny 172.16.20.3 to the end of the ACL
 - Change access-list 1 permit 172.16.20.4 0.0.0.7 to access-list 1 permit 172.16.20.4 0.0.0.4
 - Change access-list 1 permit 172.16.20.4 0.0.0.7 to access-list 1 permit 172.16.20.4 0.0.0.3
 - Change access-list 1 permit 172.16.20.4 0.0.0.7 to access-list deny 172.16.20.4 0.0.0.3
 - Delete access-list 1 permit 172.16.20.4 from the end of the ACL
 
<br>

### Question 34
ACL 1 has three statements, in the following order, with address and wildcard mask values as follows:

 > 1.0.0.0 0.255.255.255
 > 1.1.0.0 0.0.255.255
 > 1.1.1.0 0.0.0.255

If a router tried to match a packet sourced from IP address 1.1.1.1 using this ACL, which ACL statement does a router consider the packet to have matched?

 - First
 - Second
 - Third
 - Implied deny at the end of the ACL
 
<br>

### Question 35
Which characteristic of the TACACS+ protocol is true?

 - Uses UDP ports 1645 or 1812
 - Offers extensive accounting capabilities
 - Is an open RFC standard protocol
 - Separates AAA functions
 
<br>

### Question 36
Which option is a characteristic of the RADIUS protocol?

 - Uses TCP
 - Offers multiprotocol support
 - Combines authentication and authorization in one process
 - Supports bi-directional challenge

<br>

### Question 37
What is the objective of the aaa authentication login console-in local command?

 - It specifies the login authorization method list named console-in using the local RADIUS username-password database.
 - It specifies the login authorization method list named console-in using the local username-password database on the router.
 - It specifies the login authentication method list named console-in using the local user database on the router.
 - It specifies the login authentication list named console-in using the local username- password database on the router.
 
<br>

### Question 38
Which two of the following are features that match with TACACS+? (choose two)

 - Transport protocol is TCP and it uses bidirectional CHAP
 - Transport protocol is UDP and is uses unidirectional CHAP
 - Encrypts the entire packet and supports NetBEUI
 - Encrypts the password only and has extensive accounting support
