# REPORT: Phishing Email Analysis — sample-3333.eml

## Overview
- **Sample:** sample-3333.eml
- **Date analyzed:** 2025-9-30
- **Analyst:** Salman Qureshi
- **Verdict:** Credential Phishing (Impersonation / Link-based)

---

## Headers (extracted)
- **Date:** Sat, 8 Jun 2024 11:05:51 -0900
- **Subject:** Your account has been flagged for unusual activity
- **To:** phishing@pot
- **From:** Outlook Support Team <20141064@fue.edu.eg>
- **Return-Path:** 20141064@fue.edu.eg
- **Sender IP:** 40.107.95.90
- **Resolve Host:** mail-dm3nam02on2090.outbound.protection.outlook.com
- **Message-ID:** 6LRbA0LTveohBvLkwkPUOjSWatOYs2XlZkNlxXfiQ@vultr
- **X-Mailer:** PHPMailer 6.6.5

---

## URLs observed
- `http://a.to/24U0Ifm` (shortened)
- `https://euintfarecenter.pagedemo.co/?id=h9bd2112sq` (resolved)

---

## Artifact analysis

### Sender analysis
- Claimed sender: Outlook Support Team
- Actual sender: `20141064@fue.edu.eg` — an Egyptian university domain, unrelated to Outlook services.
- **Assessment:** domain mismatch + use of PHPMailer → high suspicion of crafted phishing email or abuse of a legitimate mail server.

### URL analysis
- Shortened link resolved to a generic hosting provider (`pagedemo.co`) — not Microsoft controlled.
- The phishing landing page impersonated Microsoft account login (credential harvesting).

### Attachment analysis
- No attachments present in the sample. If attachments existed, standard steps would be:
  - Extract file and compute hashes (MD5/SHA1/SHA256).
  - Submit to VirusTotal and internal sandbox for behavioral analysis.
  - Add confirmed malicious hashes to EDR/AV block lists.

---

## Verdict
- **Type:** Credential phishing / impersonation
- **Likelihood:** High
- **Primary tactics:** Social engineering (urgency + false trust signals), link obfuscation (URL shortener → redirect), impersonation.

---

## Recommended defense actions (short)
1. Quarantine the email across the tenant using content search / mail flow rules.
2. Block sender domain `fue.edu.eg` temporarily while investigating (validate before full block).
3. Add the identified URLs/landing domains to proxy and EDR blocklists.
4. Force password resets for any users who interacted with the phishing page.
5. Run an enterprise search for `POST` requests to the landing page (webserver / firewall logs) to detect credential submissions.
6. Use the email as a training example in next phishing awareness exercise.

---

## Notes & Limitations
- At the time of analysis the landing page was reported / removed; some enrichment services returned limited info.
- No attachment to analyze — deeper host-based forensic steps were not required for this sample.
- If further data (e.g., click logs, webserver logs, or EDR telemetry) becomes available, a follow-up investigation should be performed.

