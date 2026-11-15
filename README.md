# Active Directory Tiered Password Policy Hardening Using Fine-Grained Password Policies (FGPP)

**Windows Server 2022 | Active Directory Domain Services | Identity & Access Management | CIS Benchmark | NIST SP 800-53 Rev. 5 | PowerShell**

## Contents

- [1. Project Overview](#1-project-overview)
- [2. Business Scenario](#2-business-scenario)
- [3. Lab Environment](#3-lab-environment)
- [4. Initial Security Assessment](#4-initial-security-assessment)
- [5. Implementation](#5-implementation)
- [6. Policy Verification](#6-policy-verification)
- [7. Functional Security Testing](#7-functional-security-testing)
- [8. Results Summary](#8-results-summary)
- [9. Security Framework Alignment](#9-security-framework-alignment)
- [10. Security Considerations and Limitations](#10-security-considerations-and-limitations)
- [11. Project Evidence](#11-project-evidence)
- [12. Key Lessons Learned](#12-key-lessons-learned)
- [13. Conclusion](#13-conclusion)
- [Author](#author)

## 1. Project Overview

This project demonstrates the implementation of risk-based password security in a Windows Server 2022 Active Directory environment using Fine-Grained Password Policies (FGPPs).

The project is based on a realistic organizational security requirement: standard domain users must maintain passwords with a minimum length of 14 characters, while privileged administrator accounts require a stronger minimum of 20 characters due to their elevated permissions and the potential impact of account compromise.

Rather than modifying the existing domain-wide password policy, I configured a separate Fine-Grained Password Policy and assigned it to a dedicated Active Directory security group.

The configuration was implemented and tested using a nonprivileged lab account to simulate privileged-account password requirements.

**Project objectives:**

- Assess the existing Active Directory password policy against selected CIS Windows Server 2022 Benchmark recommendations.
- Understand the limitations of traditional domain password policy configuration.
- Implement stronger password requirements for a selected group of accounts.
- Preserve the existing domain-wide password baseline.
- Validate the effective password policy using PowerShell.
- Test password enforcement and document supporting evidence.
- Demonstrate practical identity security and configuration management skills.

---

## 2. Business Scenario

An organization maintains two categories of Active Directory accounts:

| Account Classification | Minimum Password Length | Security Requirement |
|---|---|---|
| Standard domain accounts | 14 characters | Organization-wide password baseline |
| Privileged administrator accounts | 20 characters | Enhanced protection for elevated access |

Privileged administrator accounts can perform sensitive operations, such as modifying system configurations, managing user identities, and accessing critical infrastructure.

Because these accounts present greater security risk if compromised, the organization requires stronger password controls.

### The Technical Challenge

In an Active Directory domain, the default domain password policy establishes password requirements for ordinary domain accounts.

Linking different password-policy Group Policy Objects (GPOs) to separate organizational units does not provide separate password policies for different sets of domain users.

To implement different password requirements within the same domain, Active Directory supports **Fine-Grained Password Policies**, which can be assigned directly to user accounts or global security groups.

### Proposed Solution

Retain the existing 14-character domain-wide password policy and implement an FGPP with a minimum password length of 20 characters for a dedicated security group representing higher-risk accounts.

For safe testing, this project uses an isolated test group and a nonprivileged user account rather than modifying actual privileged administrator accounts.

---

## 3. Lab Environment

| Component | Technology |
|---|---|
| Virtualization | Microsoft Hyper-V |
| Domain Controller | Windows Server 2022 |
| Directory Services | Active Directory Domain Services (AD DS) |
| Identity Administration | Active Directory Users and Computers (ADUC) |
| Password Policy Management | Active Directory Administrative Center (ADAC) |
| Policy Validation | Windows PowerShell |
| Security Reference | CIS Microsoft Windows Server 2022 Benchmark v5.1.0 |
| Control Framework | NIST SP 800-53 Rev. 5 |

### Lab Architecture

```text
                  WINDOWS SERVER 2022
                 ACTIVE DIRECTORY DOMAIN
                            |
             +--------------+--------------+
             |                             |
    DEFAULT DOMAIN POLICY          FINE-GRAINED PASSWORD
             |                            POLICY
             |                             |
     Standard Domain Users       Dedicated Security Group
             |                             |
      Minimum Length: 14           Minimum Length: 20
      Complexity: Enabled          Complexity: Enabled
      Password History: 24         Password History: 24
                                           |
                                    CIS-TestUser
                                 (Nonprivileged Lab User)
```

The stronger policy is assigned through an Active Directory global security group, not by linking a password-policy GPO to an organizational unit.

---

## 4. Initial Security Assessment

Before implementing any changes, I reviewed the default domain password policy using PowerShell.

### PowerShell Command

```powershell
Get-ADDefaultDomainPasswordPolicy | Format-List
```

### Observed Baseline

| Password Setting | Existing Configuration |
|---|---|
| Minimum password length | 14 characters |
| Password complexity | Enabled |
| Password history | 24 |
| Maximum password age | 42 days |
| Minimum password age | 1 day |
| Account lockout threshold | 5 attempts |
| Account lockout duration | 15 minutes |
| Reset account lockout counter | 15 minutes |
| Reversible password encryption | Disabled |

The existing domain password settings met the selected CIS benchmark requirements reviewed for this project.

The purpose of the FGPP implementation was therefore not to correct an identified failure in the default password baseline. Instead, it was to demonstrate enhanced, risk-based protection for a higher-risk category of accounts.

This assessment was limited to selected password-related settings and does not establish full CIS Benchmark compliance.

---

## 5. Implementation

### Step 1: Create a Dedicated Lab Organizational Unit

Using Active Directory Users and Computers, I created an isolated organizational unit:

```text
CIS-Password-Lab
```

The OU was used to organize the lab objects and avoid changes to existing accounts.

### Step 2: Create a Global Security Group

I created the following group:

```text
Group Name: CIS-Password-Test
Group Scope: Global
Group Type: Security
```

This group was designated as the target for the enhanced password policy.

### Step 3: Create a Test User

I created a nonprivileged Active Directory account:

```text
Account Name: CIS-TestUser
```

I added the account to the `CIS-Password-Test` global security group.

### Step 4: Verify Group Membership

Using PowerShell:

```powershell
Get-ADGroupMember "CIS-Password-Test" |
    Select-Object Name,SamAccountName
```

The command confirmed that the test account was a member of the designated security group.

### Step 5: Create the Fine-Grained Password Policy

Using Active Directory Administrative Center:

```text
Active Directory Administrative Center
    > Domain
    > System
    > Password Settings Container
    > New
    > Password Settings
```

I created a Password Settings Object with the following configuration:

| Configuration | Value |
|---|---|
| Policy name | CIS-Privileged-Password-Policy |
| Policy precedence | 10 |
| Minimum password length | 20 characters |
| Enforce password complexity | Enabled |
| Password history | 24 |
| Minimum password age | 1 day |
| Maximum password age | 42 days |
| Account lockout threshold | 5 attempts |
| Reset failed logon counter | 15 minutes |
| Account lockout duration | 15 minutes |
| Reversible encryption | Disabled |
| Assigned security group | CIS-Password-Test |

The 20-character requirement was a deliberate scenario-specific enhancement rather than a claim that the CIS Benchmark mandates 20 characters for privileged accounts.

---

## 6. Policy Verification

After creating the FGPP, I verified that Active Directory selected the intended policy for the test account.

### Verify the Fine-Grained Password Policy

```powershell
Get-ADFineGrainedPasswordPolicy `
    -Identity "CIS-Privileged-Password-Policy" |
    Format-List Name,Precedence,MinPasswordLength,ComplexityEnabled,PasswordHistoryCount,AppliesTo
```

### Verify the Resultant Password Policy

```powershell
Get-ADUserResultantPasswordPolicy `
    -Identity "CIS-TestUser" |
    Format-List Name,MinPasswordLength,Precedence
```

### Observed Result

```text
Name              : CIS-Privileged-Password-Policy
MinPasswordLength : 20
Precedence        : 10
```

This confirmed that Active Directory selected the intended FGPP for the test account.

---

## 7. Functional Security Testing

To validate the implementation, I performed controlled password-reset tests against the isolated test account.

### Test 1: Noncompliant Password

I attempted to reset the test account password using a password that did not meet the new 20-character minimum.

**Observed result:** Active Directory rejected the password reset and displayed a password-policy requirements error.

The Windows error message is generic and can also occur due to complexity, password history, or other password requirements. Therefore, the error message alone cannot independently establish which specific policy setting caused the rejection.

### Test 2: Compliant Password

I performed another password reset using a unique, complex password containing at least 20 characters.

**Observed result:** Active Directory accepted the password change.

### Test 3: Verify the Default Domain Policy Remained Unchanged

After implementing and testing the FGPP, I ran:

```powershell
Get-ADDefaultDomainPasswordPolicy |
    Select-Object MinPasswordLength,ComplexityEnabled,PasswordHistoryCount
```

**Observed result:**

```text
MinPasswordLength : 14
ComplexityEnabled : True
PasswordHistoryCount : 24
```

The existing domain password baseline remained unchanged.

### Test 4: Reconfirm the Resultant Policy

Finally, I executed:

```powershell
Get-ADUserResultantPasswordPolicy CIS-TestUser |
    Select-Object Name,MinPasswordLength,Precedence
```

The resulting policy continued to show a 20-character minimum and precedence of 10.

---

## 8. Results Summary

| Validation Objective | Actual Result | Status |
|---|---|---|
| Assess existing domain policy | 14-character minimum identified | Passed |
| Create isolated test group | Global security group created | Passed |
| Add test account to group | Membership verified | Passed |
| Configure targeted FGPP | 20-character policy configured | Passed |
| Verify resultant FGPP | Intended policy selected | Passed |
| Reject noncompliant password | Reset rejected | Passed |
| Accept compliant password | Reset accepted | Passed |
| Preserve existing domain password policy | 14-character baseline unchanged | Passed |

The lab demonstrated the ability to implement a differentiated password security configuration and validate its behavior without modifying the existing domain-wide password requirements.

---

## 9. Security Framework Alignment

### CIS Microsoft Windows Server 2022 Benchmark v5.1.0

The CIS Benchmark was used to review selected settings within the existing domain password baseline, including:

- Password history
- Maximum password age
- Minimum password age
- Minimum password length
- Password complexity
- Reversible password encryption
- Account lockout settings

The 20-character FGPP was an additional risk-based hardening decision specific to the simulated organization.

### NIST SP 800-53 Rev. 5

**IA-5 — Authenticator Management**

Relevant to establishing and managing authentication requirements, including password-related controls.

**AC-2 — Account Management**

Relevant to managing accounts, including determining appropriate security requirements for different account types.

These controls provide a useful framework for discussing the project's security objectives. The lab was not a comprehensive assessment of either control.

---

## 10. Security Considerations and Limitations

Fine-Grained Password Policies provide more granular password controls, but stronger passwords alone do not eliminate privileged account risk.

In a production environment, additional safeguards should include:

- Multi-factor authentication where supported.
- Separate standard-user and administrator accounts.
- Least-privilege access assignments.
- Privileged access monitoring.
- Secure account provisioning and deprovisioning.
- Periodic access reviews.
- Additional privileged access management controls where appropriate.

This project simulated a privileged-account password requirement using a nonprivileged test account.

No actual Domain Admin accounts or production privileged identities were modified.

The project demonstrates configuration and validation of a targeted password policy, not complete privileged access management or full regulatory compliance.

---

## 11. Project Evidence

The following screenshots document implementation and testing in the educational lab. The author confirmed that the visible domain names, hostnames, account names, and infrastructure identifiers are fictional lab data and authorized publication of the original screenshots without redaction. The images are stored unchanged in [`evidence/`](evidence/).

| Evidence File | Description |
|---|---|
| [01_Domain_Password_Policy_Before.png](evidence/01_Domain_Password_Policy_Before.png) | Original domain password baseline |
| [05_CIS_Group_Membership.png](evidence/05_CIS_Group_Membership.png) | Test account group membership |
| [06_FGPP_Created.png](evidence/06_FGPP_Created.png) | FGPP configuration in ADAC |
| [08_FGPP_Resultant_Policy.png](evidence/08_FGPP_Resultant_Policy.png) | Resultant FGPP verification |
| [09_Domain_Policy_Unchanged.png](evidence/09_Domain_Policy_Unchanged.png) | Domain-wide policy remains unchanged |
| [10_Short_Password_Rejected.png](evidence/10_Short_Password_Rejected.png) | Noncompliant password rejected |
| [11_Compliant_Password_Accepted.png](evidence/11_Compliant_Password_Accepted.png) | Compliant password accepted |
| [12_Resultant_Policy_After_Test.png](evidence/12_Resultant_Policy_After_Test.png) | Final resultant policy verification |
| [02_CIS_Test_OU.png](evidence/02_CIS_Test_OU.png) | Lab organizational unit visible in ADUC |
| [03_CIS_Test_Group.png](evidence/03_CIS_Test_Group.png) | Global security group creation settings |
| [04_CIS_Test_User.png](evidence/04_CIS_Test_User.png) | Test user creation summary |
| [Screenshot 2026-11-14 200945.png](evidence/Screenshot%202026-11-14%20200945.png) | Additional group membership verification |

These screenshots show lab configuration and observed messages; they do not establish full CIS or NIST compliance. The password rejection message does not identify the specific setting responsible, and the successful reset message does not independently establish password length or complexity. No passwords, GPO backups, or copyrighted CIS Benchmark PDF are included.

---

## 12. Key Lessons Learned

This project strengthened my practical understanding of Active Directory identity and password security.

Key takeaways included:

1. **Domain-wide password policies and Fine-Grained Password Policies serve different purposes.** FGPPs allow selected accounts to receive different password requirements without changing the default domain baseline.

2. **Security policy implementation should be based on organizational risk.** Higher-risk accounts may warrant additional protection.

3. **Policy configuration and policy enforcement are not the same thing.** The resultant policy must be verified, and controlled testing provides additional evidence.

4. **A successful security change should avoid unintended effects.** The stronger lab policy was introduced without modifying the existing domain password requirements.

5. **Technical evidence improves audit readiness.** PowerShell output, configuration screenshots, and validation results help document the work performed.

---

## 13. Conclusion

This project demonstrates a practical implementation of tiered password security in Windows Server 2022 Active Directory.

By assessing the existing domain policy, configuring a Fine-Grained Password Policy, verifying its assignment, and testing password behavior, I demonstrated how an organization can apply stronger password requirements to selected higher-risk accounts while maintaining a standard policy for ordinary domain users.

The lab reinforced core Information Assurance and Governance, Risk, and Compliance practices, including security baseline assessment, identity management, risk-based control implementation, validation, and evidence collection.

---

## Author

**Musah Issah**

Cybersecurity | Information Assurance | GRC | Windows Security Hardening

**GitHub:** [MusahIssah](https://github.com/MusahIssah)

**Project Repository:** [active-directory-tiered-password-hardening](https://github.com/MusahIssah/active-directory-tiered-password-hardening)

*Disclaimer: This project was performed in a controlled educational lab. It is not a production implementation, and the findings should not be interpreted as a complete CIS Benchmark or NIST compliance assessment.*
