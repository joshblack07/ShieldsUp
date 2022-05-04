# Shields Up
CISA Shields Up Review and Next Steps

Summary: The Cybersecurity and Infrastructure Security Agency [CISA](https://www.cisa.gov/about-cisa "CISA") leads the national effort to understand, manage, and reduce risk to our cyber and physical infrastructure. In response to the Russian Invasion of Ukraine, CISA has been closely monitoring the increased malicious cyber activity and has developed strategies to help mitigate the risk to organizations.

This analysis has been titled [Shields Up](https://www.cisa.gov/shields-up "Shields Up")

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
