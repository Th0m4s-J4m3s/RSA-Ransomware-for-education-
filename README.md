# RSA-Ransomware(for-education)
_The RSA virus was originally discovered by virus analyst Michael Gillespie, and belongs to the Cring ransomware family. This ransomware encrypts all user’s data on the PC (photos, documents, excel tables, music, videos, etc), adds its specific extension to every file, and creates the !!!!deReadMe!!!.txt files in every folder which contains encrypted files.

 _RSA adds its specific “.RSA” extension to the name of every file. For example, your photo named as “1.jpg” will be transformed into “1.jpg.RSA“, report in Excel tables named “report.xlsx” – to “report.xlsx.RSA“, and so on.

!!!!deReadMe!!!.txt file, which can be found in every folder that contains the encrypted files, is a ransom money note. Inside of it, you can find information about ways of contacting Rsa ransomware developers, and some other info. Inside of the ransom note, there is usually an instruction saying about purchasing the decryption tool. This decryption tool is created by ransomware developers, and can be obtained through the email, contacting poolhackers@tutanota.com, eternalnightmare@tutanota.com .

Source: https://howtofix.guide/rsa-virus/

# What's a Ransomware?

A ransomware is a type of malware that prevents legitimate users from accessing their device or data and asks for a payment in exchange for the stolen functionality. They have been used for mass extortion in various forms, but the most successful one seems to be encrypting ransomware: most of the user data are encrypted and the key can be obtained paying the attacker. To be widely successful a ransomware must fulfill three properties:

Property 1: The hostile binary code must not contain any secret (e.g. deciphering keys). At least not in an easily retrievable form, indeed white box cryptography can be applied to ransomware.

Property 2: Only the author of the attack should be able to decrypt the infected device.

Property 3: Decrypting one device can not provide any useful information for other infected devices, in particular the key must not be shared among them.

# How is Ransomware distributed?

From the first widely-distributed attacks using a floppy disk, to the use of botnets in the mid to late 2000s, ransomware distribution methods have evolved over the years. The most recent ransomware families and their associated variants most frequently employ the following techniques:

Phishing: Emails containing malicious links or attachments are one of the most common delivery techniques for ransomware payloads. According to Proofpoint’s State of Phish report, 47% of successful phishing campaigns resulted in some form of ransomware infection. (Source)

    Ryuk, a ransomware developed by Russian hacking group WIZARD SPIDER, is primarily delivered as a second-stage infection after initial Trickbot infection via malicious email attachments.

Automated Recon Scans: This method employs open internet scans, using services such as Shodan, to identify internet facing systems with open ports (ex: TCP/3389-Remote Desktop Protocol) or running unpatched exploitable versions of software.

    CloP, a now defunct ransomware group, was able to exploit two zero-days, CVE-2021-27102 and CVE-2021-27104, which allowed for remote code execution within unpatched Accellion FTA instances

Ransomware-as-a-Service (RaaS): A newer method of distribution, RaaS outsources the initial compromise of corporate systems (some will even outsource all actions up to ransom collection), with some form of subscription or profit splitting. While there are multiple revenue models for RaaS, some of the larger ransomware families like DopplePaymer, Maze, and Netwalker are operating under the Affiliate model. In the Affiliate model, a ransomware provider will develop/maintain the malware’s code in addition to setting up the associated infrastructure (payment portals, unique IDs, troubleshooting support, data leak sites). These groups will then recruit “affiliates” to deliver the ransomware payload to targeted victims. Once profits have been paid, the ransom group and the affiliates will split the profits.

# What Are the Stages of a Ransomware Infection?

Once a target has been identified, the ransomware lifecycle can be observed through the following stages:

    1.Initial Access/Distribution. This is the beginning of a ransomware attack. In addition to the previously detailed methods of distribution, ransomware can infect victims via most well-known malware delivery mechanisms such as drive-by-downloads, mishandling of malicious data, third-party compromise, or as a secondary stage of previously downloaded malware. Due to the wide range of compromise vectors being like other types of malware, it is difficult to categorize an attack as solely ransomware during this stage.

 

   2.Infection. Now that the dropper file is on the victim machine, a malicious executable (or another file) containing the ransomware payload is downloaded. This can be completed by making a call to a hardcoded URL or as an automated second stage of the initial infection vector. At this point you may see network traffic to suspicious IPs or domains that hold the malicious files. Once downloaded, the executable is typically placed in a local Windows %temp% directory (may also end up in the root or a subdirectory of C:\ such as C:\Windows), the original dropper file is removed, and the downloaded malicious file is executed.

 

   3.Payload Staging. At this point, the ransomware begins to set itself up for successful execution. The main goal of this stage is to ensure completion of ransomware attack and persistence through system shutdowns. Some actions the ransomware may take during this stage include but are not limited to:
        Running checks to see if ransomware has previously been deployed on the system
        Checking, adding, and modifying Registry values
        Discovering user accounts and their associated privileges
        Attempting privilege escalation
        Identifying mapped network shares
        Deleting system backups
        Disabling recovery tools
        Compiling encryption/decryption keys
        Adjusting system boot settings (some variants reboot victims in ‘Safe Mode’)
        Depending on the malware variant, C2 communication may be established.

 

   4.Scanning. Once the ransomware payload has completed staging the environment, it begins identifying files to encrypt. This can be completed by using hardcoded list of files to target or avoid. In certain human operated ransomware campaigns, adversaries may manually identify highly valuable data to encrypt. In other cases, ransomware will encrypt an entire drive (Petya). Using the network mapping data gathered during “Payload Staging”, ransomware can remotely identify systems/drives/files to target as well. Some recent ransomware variants will also look to encrypt data on any connected cloud storage providers.

 

   5.Data Encryption. With the target data identified, ransomware will begin encrypting. Files will be encrypted in one of two ways:
        Encrypted data will be written over the original data and data will be renamed
        A copy of original data will be encrypted, and the original will be deleted

Different ransomware families may prefer specific encryption algorithms or a combination of many. An example of this is in the Kaseya Supply Chain attack, in which REvil ransomware used a combination of Curve25519 (asymmetric) and Salsa20 (symmetric) encryption algorithms to encrypt target files. At some point either immediately prior, during, or after, encrypted files will be renamed and appended with a ransomware identifying hardcoded or dynamically generated file extension.

 

   6.Ransom Demand. For any systems impacted by data encryption, a ransom note will be generated. This can be thought of as a “calling card” for the adversary. Notes can be dropped into a single directory, every directory that holds encrypted files, or as a “lock screen” on victim desktops. Typically, these notes will include characteristics (ransom note title, specific language, or direct mention of group) that informs the victim who attacked them. Ransom notes for specific ransomware families tend to be the same across many variants. Ransom notes will include the monetary demand in some form of crypto currency, how to access the payment portal, and a point of contact. Once paid, a private key is provided to the victim, however, there is no guarantee that the key will properly decrypt the targeted data. According to Sophos, “92% of victims lost at least some data, and more than 50% of them lost at least a third of their precious files, despite paying.”
 

# Legal Warning

While this may be helpful for some, there are significant risks. hidden tear may be used only for Educational Purposes. Do not use it as a ransomware! You could go to jail on obstruction of justice charges just for running hidden tear, even though you are innocent.

# Download Removal Tool.

You can download GridinSoft Anti-Malware by clicking the button below:
Download GridinSoft Anti-Malware

Source: https://howtofix.guide/download/
