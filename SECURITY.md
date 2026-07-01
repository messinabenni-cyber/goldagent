# Security Policy

## Overview

This document sets out the security policy, responsible disclosure guidelines, and acceptable use requirements for goldagent. It is intended for enterprise security teams, penetration testers, and security researchers operating within authorised engagements.

---

## Authorisation Requirement

**This tool MUST only be used on systems, networks, and infrastructure that you own or for which you hold explicit, written authorisation from the system owner prior to commencing any testing activity.**

Unauthorised use of this tool against systems you do not own or have not been explicitly permitted to test is a criminal offence in most jurisdictions, including but not limited to:

- **United Kingdom** — Computer Misuse Act 1990 (as amended by the Police and Justice Act 2006 and the Serious Crime Act 2015), carrying penalties of up to ten years imprisonment.
- **United States** — Computer Fraud and Abuse Act 18 U.S.C. § 1030, carrying penalties including substantial fines and imprisonment.
- **European Union** — Directive 2013/40/EU on attacks against information systems, as transposed into member state law.
- **Australia** — Criminal Code Act 1995, Part 10.7 (Computer Offences).
- **Canada** — Criminal Code s. 342.1 (Unauthorized use of computer).

The above list is not exhaustive. You are solely responsible for ensuring that your use of this tool complies with all applicable laws and regulations in your jurisdiction and in the jurisdiction of any target system.

**Authorisation must be:**
- Obtained in writing before testing commences.
- Signed by an individual with legal authority to grant it (e.g., the system owner, a duly authorised officer of the organisation, or a client under a formal statement of work).
- Specific in scope — it must identify the target systems, IP ranges, domains, or services included.
- Retained for the duration of the engagement and for a reasonable period thereafter for audit purposes.

---

## Responsible Use Guidelines

Security professionals using this tool are expected to adhere to the following standards throughout any engagement:

1. **Obtain written authorisation before testing.** Do not rely on verbal permission. A signed rules of engagement (RoE) document, statement of work, or equivalent is required.

2. **Respect the agreed scope.** Testing must be confined to the systems, services, and targets explicitly listed in your authorisation. Out-of-scope activity — even if technically accessible — is not permitted.

3. **Do not place calls to real PSTN, VoIP, or telecommunications numbers** without explicit authorisation from the relevant network operator or carrier, in addition to the system owner. Unsolicited calls may constitute harassment or telecommunications fraud under applicable law.

4. **Minimise impact.** Prefer non-destructive testing techniques. Avoid actions that could cause denial of service, data loss, or disruption to production systems unless specifically authorised and appropriate safeguards are in place.

5. **Handle cracked credentials and recovered secrets responsibly.** Store any credentials, password hashes, API keys, or other sensitive material recovered during testing in an encrypted, access-controlled manner. Credentials must be disclosed to the system owner as part of engagement findings and securely deleted or returned at engagement close.

6. **Disclose findings promptly.** Report discovered vulnerabilities, misconfigurations, and recovered credentials to the system owner as soon as reasonably practicable, in accordance with the agreed reporting timeline in your engagement documentation.

7. **Do not retain data beyond the engagement.** Scan results, captured traffic, recovered hashes, credentials, and other artefacts collected during testing must not be retained beyond the period required for reporting, unless explicitly agreed in writing with the system owner.

8. **Do not share or sell engagement data.** Data collected during an authorised engagement is confidential to that engagement. It must not be disclosed to third parties, shared publicly, or used for any purpose outside the scope of the engagement.

---

## What This Tool Will Not Do

goldagent includes the following built-in controls to prevent misuse:

- **No internet-wide scanning.** The tool will not initiate unsolicited scans of arbitrary internet-facing hosts or IP ranges without explicit target specification by the operator.
- **No automatic destructive actions.** Actions with destructive potential (e.g., account lockout, data modification, service termination) require explicit operator confirmation and are not executed automatically.
- **No exfiltration of data to external infrastructure.** The tool does not transmit captured credentials, hashes, scan results, or any other collected data to external servers operated by the tool's developers or any third party.
- **No persistence mechanisms.** The tool does not install backdoors, persistent agents, or scheduled tasks on target or operator systems as part of its normal operation.
- **No bypass of operator-configured scope restrictions.** Target scope restrictions configured by the operator are enforced and cannot be silently overridden.

These controls are provided as a reasonable safeguard. They do not substitute for operator responsibility to obtain proper authorisation and operate within legal boundaries.

---

## Reporting Security Issues in goldagent Itself

If you discover a security vulnerability in goldagent itself — including bugs that could allow scope bypass, credential leakage, privilege escalation, or any other unintended security-relevant behaviour — please report it responsibly.

**How to report:**

1. **Do not open a public GitHub issue** for security vulnerabilities. Public disclosure before a fix is available may put users at risk.
2. Send a report by email to: **benvoleo@yahoo.co.uk**
   - Use the subject line: `[SECURITY] goldagent vulnerability report`
   - Encrypt your report using PGP if possible (public key available on request).
3. Include in your report:
   - A clear description of the vulnerability.
   - Steps to reproduce, including any proof-of-concept code or commands.
   - The potential impact and affected versions.
   - Your preferred contact details for follow-up.
4. You will receive an acknowledgement within **5 business days** and a substantive response within **14 calendar days** where possible.
5. Please allow reasonable time (typically 90 days) for a fix to be developed and released before any public disclosure, in accordance with coordinated vulnerability disclosure norms.

We do not currently operate a bug bounty programme, but responsible reporters will be credited in release notes if they wish.

---

## Scope of Authorised Use

The following constitutes authorised use of this tool:

- **Penetration testing** of systems, networks, or applications under a signed engagement with the system owner.
- **Red team exercises** conducted under a formal statement of work with an authorising client.
- **Internal security assessments** by security teams operating on infrastructure owned or operated by their employer, within the scope of their role.
- **Capture-the-flag (CTF) competitions** and training environments explicitly designated for security practice.
- **Security research** on systems you own or on dedicated, isolated lab environments with no production data.

The following does not constitute authorised use and is strictly prohibited:

- Testing any system, network, or service without prior written authorisation from its owner.
- Targeting public infrastructure, shared hosting environments, or third-party services outside the scope of a signed engagement.
- Use against former employers, ex-clients, or any organisation with whom you do not have a current, valid authorisation.
- Providing access to this tool to individuals who have not agreed to this policy.

---

## Data Handling

All data collected during use of this tool — including but not limited to scan results, discovered credentials, captured authentication hashes, network traffic, and configuration information — must be handled in accordance with the following requirements:

| Data Type | Storage Requirement | Retention | Disposal |
|---|---|---|---|
| Cracked or recovered credentials | Encrypted at rest (AES-256 or equivalent); access-controlled | Engagement duration plus reporting period only | Secure deletion (overwrite or cryptographic erasure) at engagement close or as directed by the system owner |
| Captured password hashes | Encrypted at rest; access-controlled | Engagement duration plus reporting period only | Secure deletion at engagement close |
| Scan results and reports | Encrypted in transit and at rest; shared only with authorised recipients | As specified in the engagement agreement | Secure deletion per engagement agreement |
| Network traffic captures | Encrypted at rest; access-controlled | Minimum necessary for reporting | Secure deletion at engagement close |
| Personally identifiable information (PII) | Must not be collected beyond what is incidental and necessary; encrypted at rest | Minimum necessary; notify system owner of any PII discovered | Secure deletion; notify system owner |

**Additional data handling requirements:**

- Do not store engagement data on personal, unmanaged, or shared devices without explicit written approval from the system owner.
- Do not upload engagement data to cloud storage, collaboration platforms, or any third-party service not explicitly approved by the system owner.
- In the event of a data breach or unauthorised access to collected engagement data, notify the system owner immediately and no later than within 24 hours of discovery.
- Comply with all applicable data protection legislation governing the data you handle, including the UK GDPR and Data Protection Act 2018, EU GDPR, and equivalent frameworks as applicable.

---

## Acknowledgement

By using goldagent, you confirm that you have read, understood, and agree to comply with this security policy in its entirety. If you are using this tool on behalf of an organisation, you confirm that you have the authority to bind that organisation to these terms.

---

*Last updated: 2026-07-01*
