# Shields Up
CISA Shields Up Review and Next Steps

Summary: The Cybersecurity and Infrastructure Security Agency [CISA](https://www.cisa.gov/about-cisa "CISA") leads the national effort to understand, manage, and reduce risk to our cyber and physical infrastructure. In response to the Russian Invasion of Ukraine, CISA has been closely monitoring the increased malicious cyber activity and has developed strategies to help mitigate the risk to organizations.

This analysis has been titled [Shields Up](https://www.cisa.gov/shields-up "Shields Up") and is being continuously updated, so please subscribe to their updates  [here](https://public.govdelivery.com/accounts/USDHSCISA/subscriber/new?topic_id=USDHSCISA_138 "here").

## Review Checklist 

The following policy reviews and exercises should be completed annually, at a minimum.

| Name     | Date of Last Review | 
|----------|----------|
| Business Continuity Policy |   |
| Business Continuity Exercise |   | 
| IT Disaster Recovery Policy |   |
| IT Disaster Recovery Exercise |   |
|IT and Security Policy|   |


The following technical reviews should be completed annually, at a minimum, and if any major network changes occur.

| Name     | Date of Last Review | 
|----------|----------|
| EDR Security Policy Review |   |
| Network Segmentation Review |   | 


In an effort to reduce the risk of a successful cyber attack, CISA recommends the following scans and services:

| Cyber Hygiene    | Response| 
|----------|----------|
| Vulnerability Scan |   |
| Web Application Scan |   | 
| Phishing Campaign Assessment |   |
| External Penetration Testing |   | 



| CISA recommends the following steps for organizations to strengthen their cloud security practices.  | Response| 
|----------|----------|
| Implement conditional access (CA) policies based upon your organization's needs. |   |
| Establish a baseline for normal network activity within your environment. |   | 
| Routinely review both Active Directory sign-in logs and unified audit logs for anomalous activity. |   |
| Enforce MFA. |   | 
| Routinely review user-created email forwarding rules and alerts, or restrict forwarding. |   |
| Have a mitigation plan or procedures in place; understand when, how, and why to reset passwords and to revoke session tokens. |   | 
| [Follow recommend guidance on securing privileged access](https://media.defense.gov/2020/Dec/17/2002554125/-1/-1/0/AUTHENTICATION_MECHANISMS_CSA_U_OO_198854_20.PDF "Follow recommend guidance on securing privileged access")  |   |
| Consider a policy that does not allow employees to use personal devices for work. At a minimum, use a trusted mobile device management solution. |   |
|Resolve client site requests internal to your network.|   |
| Consider restricting users from forwarding emails to accounts outside of your domain.|   |
| Allow users to consent only to app integrations that have been pre-approved by an administrator. |   | 
| Audit email rules with enforceable alerts via the Security and Compliance Center or other tools that use the Graph API to warn administrators to abnormal activity. |   |
| Implement MFA for all users, without exception. |   |
| [Conditional access should be understood and implemented with a zero-trust mindset](https://www.microsoft.com/security/blog/2020/04/30/zero-trust-deployment-guide-azure-active-directory/ "Conditional access should be understood and implemented with a zero-trust mindset") |   |
| Ensure user access logging is enabled. Forward logs to a security information and event management appliance for aggregation and monitoring so as to not lose visibility on logs outside of logging periods. |   |
| Use a CA policy to block legacy authentication protocols. |   | 
| Verify that all cloud-based virtual machine instances with a public IP do not have open Remote Desktop Protocol (RDP) ports. Place any system with an open RDP port behind a firewall and require users to use a VPN to access it through the firewall. |   |
| Focus on awareness and training. Make employees aware of the threats—such as phishing scams—and how they are delivered. Additionally, provide users training on information security principles and techniques as well as overall emerging cybersecurity risks and vulnerabilities. |   |
|Establish blame-free employee reporting and ensure that employees know who to contact when they see suspicious activity or when they believe they have been a victim of a cyberattack. This will ensure that the proper established mitigation strategy can be employed quickly and efficiently.|   |
| Ensure existing built-in filtering and detection products (e.g., those for spam, phishing, malware, and safe attachments and links are enabled. |   |

| Organizations using M365 should also consider the following steps.| Response  | 
|----------|----------|
| Assign a few (one to three) trusted users as electronic discovery (or eDiscovery) managers to conduct forensic content searches across the entire M365 environment (Mailboxes, Teams, SharePoint, and OneDrive) for evidence of malicious activity. |   |
| Disable PowerShell remoting to Exchange Online for regular M365 users. Disabling for non-administrative users will lower the likelihood of a compromised user account being used to programmatically access tenant configurations for reconnaissance. |   |
|Do not allow an unlimited amount of unsuccessful login attempts. To configure these settings, see password smart lockout configuration and sign-in activity reports.|   |
| Consider using a tool such as Sparrow or Hawk—open-source PowerShell-based tools used to gather information related to M365—to investigate and audit intrusions and potential breaches. |   |

## IoC and File Bans

Indicators of compromise (IOCs) are “pieces of forensic data, such as data found in system log entries or files, that identify potentially malicious activity on a system or network.” Indicators of compromise aid information security and IT professionals in detecting data breaches, malware infections, or other threat activity. By monitoring for indicators of compromise, organizations can detect attacks and act quickly to prevent breaches from occurring or limit damages by stopping attacks in earlier stages.

CISA has identified many vulnerabilities or attacks and compiled a list of the associated file hashes.  It is important to review CISA's list and add file bans to keep the malicious files off the network.  With any new file approval requests, always check sites like [Virus Total](https://www.virustotal.com/gui/home/upload "Virus Total") to research the validity/hygiene of a file.

 IOCs associated with WhisperGate
 
 | File Name   | Hash| 
|----------|----------|
| WhisperGate | a196c6b8ffcb97ffb276d04f354696e2391311db3841ae16c8c9f56f36a38e92  |
| WhisperGate | dcbbae5a1c61dbbbb7dcd6dc5dd1eb1169f5329958d38b58c3fd9384081c9b78 |


IOCs associated with HermeticWiper

| File Name   | Hash| 
|----------|----------|
| Win32/KillDisk.NCV | 912342F1C840A42F6B74132F8A7C4FFE7D40FB77   |
| Win32/KillDisk.NCV | 61B25D11392172E587D8DA3045812A66C3385451 |
| HermeticWiper |  	912342f1c840a42f6b74132f8a7c4ffe7d40fb77 | 
| HermeticWiper | 61b25d11392172e587d8da3045812a66c3385451  |
| RCDATA_DRV_X64 | 	a952e288a1ead66490b3275a807f52e5  | 
| RCDATA_DRV_X86 | 231b3385ac17e41c5bb1b1fcb59599c4  |
| RCDATA_DRV_XP_X64 | 095a1678021b034903c85dd5acb447ad | 
| RCDATA_DRV_XP_X8 | eb845b7a16ed82bd248e395d9852f467 |
| Trojan.Killdisk| 1bc44eef75779e3ca1eefb8ff5a64807dbc942b1e4a2672d77b9f6928d292591  | 
| Trojan.Killdisk | 0385eeab00e946a302b24a91dea4187c1210597b8e17cd9e2230450f5ece21da  |
| Trojan.Killdisk |  a64c3e0522fad787b95bfb6a30c3aed1b5786e69e88e023c062ec7e5cebf4d3e | 
| Ransomware |  4dc13bb83a16d4ff9865a51b3e4d24112327c526c1392e14d56f20d6f4eaf382 |


 IOCs associated with CaddyWiper
 
 | File Name   | Hash| 
|----------|----------|
| caddy.exe | a294620543334a721a2ae8eaaf9680a0786f4b9a216d75b55cfd28f39e9430ea  |


 IOCs associated with BlackMatter
 
 | File Name   | Hash| 
|----------|----------|
| BlackMatter | 22D7D67C3AF10B1A37F277EBABE2D1EB4FD25AFBD6437D4377400E148BCC08D6  |


 IOCs associated with BlackCat/ALPHV
 
BlackCat/ALPHV: Powershell Scripts
| File Name   | Hash| 
|----------|----------|
| amd - Copy.ps1| 861738dd15eb7fb50568f0e39a69e107  |
| ipscan.ps1  |  9f60dd752e7692a2f5c758de4eab3e6f |
| Run1.ps1| 09bc47d7bc5e40d40d9729cec5e39d73  | 

BlackCat/ALPHV: Batch Scripts
| File Name   | Hash| 
|----------|----------|
| CheckVuln.bat| f5ef5142f044b94ac5010fd883c09aa7 |
| Create-share-RunAsAdmin.bat |  84e3b5fe3863d25bb72e25b10760e861 |
| LPE-Exploit-RunAsUser.bat | 9f2309285e8a8471fce7330fcade8619 | 
| RCE-Exploit-RunAsUser.bat  |  6c6c46bdac6713c94debbd454d34efd9 |
| est.bat   |  e7ee8ea6fb7530d1d904cdb2d9745899 |
| runav.bat  |  815bb1b0c5f0f35f064c55a1b640fca5 |

BlackCat/ALPHV: Executables and DLLs
| File Name   | Hash| 
|----------|----------|
| http_x64.exe  | 6c2874169fdfb30846fe7ffe34635bdb  |
| spider.dll  | 20855475d20d252dda21287264a6d860  |
| spider_32.dll   | 82db4c04f5dcda3bfcd75357adf98228  |
| powershell.dll   |  fcf3a6eeb9f836315954dae03459716d |
|  rpcdump.exe |  91625f7f5d590534949ebe08cc728380 |

BlackCat/ALPHV:  SHA256 Hashes
| File Name   | Hash| 
|----------|----------|
| BlackCat  | 731adcf2d7fb61a8335e23dbee2436249e5d5753977ec465754c6b699e9bf161 |
|  BlackCat |  f837f1cd60e9941aa60f7be50a8f2aaaac380f560db8ee001408f35c1b7a97cb |
|  BlackCat | 731adcf2d7fb61a8335e23dbee2436249e5d5753977ec465754c6b699e9bf161  |
| BlackCat  |  80dd44226f60ba5403745ba9d18490eb8ca12dbc9be0a317dd2b692ec041da28 |




