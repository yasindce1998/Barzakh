# Security Policy

## Overview

The Barzakh project is an academic research initiative focused on defensive security. This document outlines our security policies, vulnerability disclosure procedures, and incident response protocols.

## Scope

This security policy applies to:

- All source code in this repository
- Build and deployment scripts
- Documentation and configuration files
- Development and testing infrastructure
- Audit and logging systems

## Security Principles

**Implementation status:** policy statements below describe intended operational
controls, not a certification that each deployment enforces them. Current scan
outcomes, server safeguards, CI/release attestations, and known limitations are
documented in [docs/HARDENING.md](docs/HARDENING.md). In particular, HSM signing of
all EFI files, immutable archival storage, and external audit cadence must not
be inferred from the presence of this policy.

### 1. Defense-in-Depth

Multiple layers of security controls:
- Hardware-rooted kill-switches (UUID, TPM EK binding)
- Time-based expiry mechanisms
- Air-gapped execution environments
- Append-only audit logging
- Cryptographic signing of artifacts

### 2. Least Privilege

- Minimal permissions for all operations
- Role-based access control
- Separation of duties
- Regular access reviews

### 3. Transparency

- Open documentation of security mechanisms
- Public disclosure of vulnerabilities (after remediation)
- Peer-reviewed security architecture
- Reproducible builds

## Vulnerability Disclosure

### Reporting a Vulnerability

If you discover a security vulnerability in Barzakh:

#### 🚨 DO NOT:
- Create a public GitHub issue
- Disclose the vulnerability publicly
- Share details on social media or forums
- Exploit the vulnerability

#### ✅ DO:
1. **Email**: security@deadlockcorp.edu
2. **Subject**: "Barzakh Security Vulnerability Report"
3. **Include**:
   - Detailed description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested remediation (if any)
   - Your contact information

#### 📧 Email Template

```
Subject: Barzakh Security Vulnerability Report

Vulnerability Type: [e.g., Kill-switch bypass, Privilege escalation]
Severity: [Critical/High/Medium/Low]
Affected Component: [e.g., BootkitPkg, build scripts]

Description:
[Detailed description of the vulnerability]

Reproduction Steps:
1. [Step 1]
2. [Step 2]
3. [Step 3]

Impact:
[Potential security impact]

Suggested Fix:
[Your recommendations, if any]

Reporter Information:
Name: [Your name]
Affiliation: [Your institution/organization]
Email: [Your contact email]
PGP Key: [Optional, for encrypted communication]
```

### Response Timeline

We are committed to addressing security vulnerabilities promptly:

| Severity | Initial Response | Triage | Fix Target | Disclosure |
|----------|-----------------|--------|------------|------------|
| **Critical** | 24 hours | 48 hours | 7 days | 30 days |
| **High** | 48 hours | 5 days | 14 days | 60 days |
| **Medium** | 5 days | 10 days | 30 days | 90 days |
| **Low** | 7 days | 14 days | 60 days | 90 days |

### Severity Classification

#### Critical
- Kill-switch bypass allowing unauthorized execution
- Escape from virtualization sandbox
- Arbitrary code execution on host system
- Compromise of audit log integrity

#### High
- Privilege escalation within VM
- TPM/PCR measurement bypass
- Unauthorized network access
- Cryptographic key exposure

#### Medium
- Information disclosure
- Denial of service
- Build system compromise
- Documentation vulnerabilities

#### Low
- Minor configuration issues
- Non-security bugs
- Documentation errors
- Cosmetic issues

## Coordinated Disclosure Process

### For Novel UEFI/Firmware Vulnerabilities

If your research with Barzakh leads to the discovery of a novel vulnerability in UEFI implementations (Intel, AMD, Microsoft, etc.):

#### Phase 1: Internal Triage (Days 0-7)

1. **Immediate Actions**:
   - Document the finding in a classified internal report
   - Notify the Principal Investigator immediately
   - Pause all related testing activities
   - Secure all evidence and reproduction steps

2. **Internal Review**:
   - PI, Information Security Officer, and Legal Counsel assess the finding
   - Determine if it's a genuine 0-day or known issue
   - Classify severity and potential impact
   - Prepare technical advisory

#### Phase 2: Vendor Notification (Days 7-14)

1. **Prepare Advisory**:
   - Detailed technical description
   - Reproduction steps (QEMU-only)
   - Affected firmware versions
   - Suggested mitigations
   - CVE request preparation

2. **Notify Affected Parties**:
   - Vendor PSIRT (Product Security Incident Response Team)
   - CERT/CC (Computer Emergency Response Team Coordination Center)
   - Use encrypted communication channels
   - Request acknowledgment within 48 hours

3. **Vendor Contact Information**:
   - **Intel**: secure@intel.com
   - **AMD**: psirt@amd.com
   - **Microsoft**: secure@microsoft.com
   - **CERT/CC**: cert@cert.org

#### Phase 3: Embargo Period (Days 14-90)

1. **Maintain Confidentiality**:
   - No conference talks or presentations
   - No pre-prints or blog posts
   - No social media discussion
   - Limited internal discussion only

2. **Vendor Collaboration**:
   - Provide additional information as requested
   - Assist with patch development and testing
   - Review vendor advisories for accuracy
   - Coordinate disclosure timeline

3. **Prepare Public Disclosure**:
   - Draft technical write-up
   - Prepare CVE request
   - Update Barzakh-Scanner detection rules
   - Document in academic paper

#### Phase 4: Public Disclosure (Day 90+)

1. **Disclosure Triggers**:
   - Vendor releases patch
   - 90 days elapsed with no vendor response
   - Vulnerability discovered independently by others
   - Active exploitation detected in the wild

2. **Disclosure Package**:
   - CVE identifier and description
   - Technical write-up with details
   - Proof-of-concept (QEMU-only)
   - Detection signatures for Barzakh-Scanner
   - Credit to Barzakh project

3. **Post-Disclosure**:
   - Monitor for exploitation attempts
   - Update project documentation
   - Incorporate into academic paper
   - Share lessons learned with community

### Disclosure Exceptions

Immediate public disclosure (without embargo) if:
- Vulnerability is already publicly known
- Active exploitation is occurring
- Vendor explicitly requests immediate disclosure
- Legal or ethical obligations require it

## Security Features

### Kill-Switch Mechanisms

#### 1. UUID Binding
- **Purpose**: Prevent execution on unauthorized hardware
- **Implementation**: Cryptographic binding to SMBIOS UUID
- **Verification**: Checked at DXE driver entry point
- **Failure Mode**: Graceful abort with `EFI_ABORTED`

#### 2. TPM EK Pinning
- **Purpose**: Hardware root of trust validation
- **Implementation**: TPM Endorsement Key verification
- **Verification**: Checked before any hooks are installed
- **Failure Mode**: Graceful abort with `EFI_ABORTED`

#### 3. Time-Bomb Expiry
- **Purpose**: Prevent use beyond project timeline
- **Implementation**: Hardcoded expiry date check
- **Verification**: Checked against RTC at boot
- **Failure Mode**: Graceful abort with expiry message

### Audit Logging

#### Integrity Guarantees
- **Append-only**: Previous entries cannot be modified
- **GPG-signed**: Each log file has cryptographic signature
- **Timestamped**: ISO 8601 UTC timestamps
- **Immutable**: Backed up to encrypted cold storage

#### Log Contents
- Timestamp of all operations
- Researcher identity
- VM configuration
- Payload variants
- Test outcomes
- Anomalies and errors

### Build Security

#### Reproducible Builds
- Pinned OVMF commit hash
- Deterministic compiler flags
- Fixed `SOURCE_DATE_EPOCH`
- SBOM generation

#### Artifact Signing
- Ed25519 signatures for all `.efi` files
- Signature verification before execution
- Key management via HSM or hardware token
- No private keys in repository

#### Supply Chain Security
- Commit signing required (GPG)
- Branch protection rules
- No unsigned commits accepted
- Dependency pinning

## Incident Response

### Security Incident Classification

#### Level 1: Critical
- Kill-switch bypass
- Unauthorized execution on production hardware
- Audit log tampering
- Key compromise

#### Level 2: High
- Unauthorized access to repository
- Build system compromise
- Unintended network access
- Policy violation

#### Level 3: Medium
- Failed security controls
- Suspicious activity
- Policy violations
- Configuration errors

### Response Procedures

#### Immediate Actions (0-1 hour)
1. Contain the incident
2. Notify Principal Investigator
3. Document all evidence
4. Preserve logs and artifacts
5. Isolate affected systems

#### Investigation (1-24 hours)
1. Assess scope and impact
2. Identify root cause
3. Determine if institutional notification required
4. Prepare incident report
5. Notify affected parties

#### Remediation (24-72 hours)
1. Implement fixes
2. Verify effectiveness
3. Update security controls
4. Review and update policies
5. Conduct lessons learned

#### Post-Incident (72+ hours)
1. Final incident report
2. Update documentation
3. Implement preventive measures
4. Train team on lessons learned
5. Review with stakeholders if required

## Security Contacts

### Primary Contacts

- **Security Issues**: security@deadlockcorp.edu
- **Principal Investigator**: yasindce1998@gmail.com

### Response Times

- **Critical Issues**: 24 hours
- **High Priority**: 48 hours
- **Medium Priority**: 5 business days
- **Low Priority**: 10 business days

## Security Audits

### Regular Audits

- **Quarterly**: Internal security review
- **Bi-annually**: External security audit
- **Annually**: Full compliance review
- **Ad-hoc**: After significant changes

### Audit Scope

- Code review for security issues
- Configuration validation
- Access control verification
- Audit log integrity
- Kill-switch functionality
- Build system security

## Compliance

### Regulatory Compliance

- Institutional security policies
- Data protection regulations
- Export control regulations (if applicable)

### Security Standards

- NIST Cybersecurity Framework
- OWASP Secure Coding Practices
- CIS Controls
- ISO 27001 principles

## Updates to This Policy

This security policy is reviewed and updated:

- Quarterly (minimum)
- After security incidents
- When new threats emerge
- When institutional requirements change

**Last Updated**: May 11, 2026  
**Version**: 1.0.0  
**Next Review**: August 11, 2026

---

## Acknowledgments

We thank the security research community for responsible disclosure and collaboration in advancing defensive security knowledge.

**Remember**: Security is everyone's responsibility. If you see something, say something.
