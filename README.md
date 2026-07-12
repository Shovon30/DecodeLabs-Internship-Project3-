[README_P3.md](https://github.com/user-attachments/files/29944216/README_P3.md)
# 🎣 Phishing Awareness Analysis
### DecodeLabs Cybersecurity Internship | Batch 2026 | Project 3

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat&logo=python&logoColor=white)
![Track](https://img.shields.io/badge/Track-Cybersecurity-red?style=flat)
![Status](https://img.shields.io/badge/Status-Completed-brightgreen?style=flat)
![Internship](https://img.shields.io/badge/DecodeLabs-Batch%202026-orange?style=flat)

---

## 📌 Overview

This is **Project 3** of the DecodeLabs Cybersecurity Industrial Training Kit — the detection phase. The goal is to build a rule-based **phishing triage engine** in Python that analyzes emails, SMS, and other messages to identify deceptive tactics, score the threat level, and recommend a defensive action.

> *"The modern cybersecurity perimeter is no longer the network firewall. It is the user."*
> — DecodeLabs, Batch 2026 Kit

This project isn't about writing an algorithm — it's about **encoding human threat-analysis judgment into repeatable logic.**

---

## 🎯 Project Goals

| Requirement | Status |
|---|---|
| Analyze sample emails/messages to identify phishing attempts | ✅ |
| Identify suspicious links or keywords | ✅ |
| List red flags found in phishing messages | ✅ |
| Explain why the message is unsafe | ✅ |
| Bonus: Non-expert triage checklist document | ✅ |
| Bonus: Decision tree with definitive actions | ✅ |

---

## 🧠 Core Concepts Applied

### The IPO Model — Adapted for Threat Detection

Unlike a typical program, this project's IPO model maps to human deception:

```
INPUT (The Bait)         PROCESS (The Psychology)        OUTPUT (The Defense)
──────────────────      ──────────────────────────      ─────────────────────
Email / SMS / QR /  →   11 Red Flag Detectors      →    Risk Score
Call / Deepfake         Domain Lookalike Analysis        Classification
                        Cognitive Trigger Detection       (Safe / Suspicious /
                                                            Malicious)
                                                          Recommended Action
```

### The 11 Official Red Flags

Every check in this engine maps directly to a named red flag from the training kit:

| # | Red Flag | What It Detects |
|---|---|---|
| 1 | Sender-Domain Mismatch | Display name doesn't match the actual sending domain |
| 2 | Fake Forwarded Chain | `FW:`/`RE:` prefix with no genuine thread context |
| 3 | Browser-in-the-Browser | Fake SSO pop-up impersonating a real login window |
| 4 | Dangerous Attachments | File extensions capable of executing code (`.exe`, `.iso`, `.js`...) |
| 5 | Urgent Bypass Requests | Demands secrecy or skipping normal procedure |
| 6 | Sensitive Info Requests | Asks for a password, OTP, or card number directly |
| 7 | Activity Alerts | Alarming "unusual sign-in" pointing to a login page |
| 8 | MFA Fatigue | Repeated unprompted "Approve" push notifications |
| 9 | Callback Scam (TOAD) | Phone number only, no link, urging an immediate call |
| 10 | QR Code Prompts | Unsolicited QR code demanding a scan |
| 11 | Deepfake Meeting Fraud | Voicemail/call asking to "confirm" a payment |

### Lookalike Domain Detection

The engine parses every URL and sender domain for four distinct disguise techniques:

| Technique | Example | Detection Method |
|---|---|---|
| **Typosquatting** | `amaz0n.com` | Levenshtein edit-distance ≤ 2 from a known brand |
| **Homoglyph Attack** | `pаypal.com` (Cyrillic а) | Non-ASCII character / Punycode detection |
| **Combosquatting** | `yourcompany-secure-login.com` | Brand name + trust keyword, wrong root domain |
| **Subdomain Trap** | `decodelabs.tech.login-update.com` | True root domain is the **last two labels** — read right to left |

### Cognitive Trigger Detection

Every phishing message leans on one of four psychological levers, all detected via keyword analysis with **negation-aware matching** (so "Non-Urgent" doesn't falsely trigger the urgency flag):

| Trigger | Example Phrase |
|---|---|
| Authority | "This is your CEO", "bypass standard procedure" |
| Urgency | "immediately", "expires in 30 minutes" |
| Curiosity | "see what your colleague said about you" |
| Fear / Greed | "legal action will follow", "you have won" |

---

## ⚙️ How Scoring Works

Each detected red flag carries a weight (1–4) based on severity. Weights are summed into a single risk score, which maps to a three-tier decision tree:

```
                 Incoming Message
                        │
        ┌───────────────┼───────────────┐
        ▼               ▼               ▼
   Score = 0        Score 1–4        Score ≥ 5
        │               │               │
        ▼               ▼               ▼
      SAFE          SUSPICIOUS       MALICIOUS
        │               │               │
        ▼               ▼               ▼
      CLOSE          WARN USER     BLOCK & ESCALATE
```

This decision tree is the literal deliverable requested by the training kit: *"Every triage event must end in a definitive action."*

---

## 💻 Sample Output

```
════════════════════════════════════════════════════════════
  DecodeLabs | Phishing Triage Report
════════════════════════════════════════════════════════════
  From    : CEO Name <hacker@gmail.com>
  Subject : IMMEDIATE ACTION REQUIRED: Transfer Authorization
  Channel : EMAIL
----------------------------------------------------------------
  Red Flags Found (3):

  🟠 [Sender Domain Mismatch]
      Evidence : Claims to be from 'company.com' but sent from 'gmail.com'
      Why unsafe: The display name suggests a trusted source, but the
      actual sending domain does not match — classic display-name spoofing.

  🟡 [Authority Bypass]
      Evidence : strictly confidential, do not discuss, bypass standard procedure
      Why unsafe: Message impersonates authority and/or demands secrecy
      — a pressure tactic, not policy.

  🟡 [Urgency Trigger]
      Evidence : immediately
      Why unsafe: Creates artificial time pressure to short-circuit
      careful thinking.
----------------------------------------------------------------
  Risk Score     : 8
  Classification : 🔴  MALICIOUS
  Decision       : Block & Escalate
════════════════════════════════════════════════════════════
  ⚠  GOLDEN RULE: PAUSE. VERIFY. REPORT.
     Do not click, reply, or call any number in this message.
════════════════════════════════════════════════════════════
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10 or higher (also compatible with 3.9+ via `from __future__ import annotations`)
- No external libraries required — standard library only

### Installation

```bash
git clone https://github.com/Shovon30/DecodeLabs-Internship-Project3-.git
cd DecodeLabs-Internship-Project3-
```

### Run

```bash
python3 phishing_triage_engine.py
```

### Modes

| Mode | Description |
|---|---|
| `[1]` Analyze Sample Dataset | Runs all 10 built-in test messages (legit + 9 phishing variants) |
| `[2]` Analyze Custom Message | Paste in your own email, SMS, or call transcript |
| `[3]` View Triage Checklist | Prints the non-expert reference card in-terminal |

---

## 🧪 Test Dataset

The engine ships with 10 hand-crafted samples covering every detection category:

| Sample | Expected Result |
|---|---|
| Legitimate project status update | 🟢 SAFE |
| CEO wire transfer scam (BEC) | 🔴 MALICIOUS |
| Fake Microsoft password reset | 🔴 MALICIOUS |
| BEC — lost wallet SMS | 🟡 SUSPICIOUS |
| ChatGPT payment failure phishing | 🔴 MALICIOUS |
| Google account recovery quishing (QR) | 🔴 MALICIOUS |
| Microsoft subscription callback scam (TOAD) | 🔴 MALICIOUS |
| HR benefits portal — subdomain trap | 🔴 MALICIOUS |
| PayPal typosquat + IP-based link | 🔴 MALICIOUS |
| PayPal homoglyph + combosquat | 🔴 MALICIOUS |

---

## 📁 Project Structure

```
DecodeLabs-Internship-Project3/
│
├── phishing_triage_engine.py   # Main detection engine
├── TRIAGE_CHECKLIST.md         # Non-expert reference card (2nd deliverable)
└── README.md                   # Project documentation
```

---

## 🔒 Design Notes

- **Negation-aware keyword matching** — prevents false positives like flagging "Non-Urgent" as urgent.
- **Weighted scoring, not raw counting** — multiple pieces of evidence for the same technique count once toward the score, but all are shown in the report.
- **IP-address handling** — IP-based URLs are checked and returned early, since concepts like "subdomain" and "root domain" don't apply to raw IPs.
- **Naive domain parsing** — the root-domain heuristic uses the last two labels and doesn't handle multi-part TLDs like `.co.uk`. A documented simplification appropriate for a training-kit triage engine, not production DNS parsing.

---

## 🔗 Project Chain

| Project | Focus | Status |
|---|---|---|
| Project 1 — Password Strength Checker | Validation & Entropy | ✅ Completed |
| Project 2 — Basic Encryption & Decryption | Cryptography & Confidentiality | ✅ Completed |
| Project 3 — Phishing Awareness Analysis | Threat Detection & Human Firewall | ✅ Completed |

Project 1 taught validation before trust. Project 2 taught confidentiality through math. Project 3 closes the loop: even perfect encryption fails if a human is tricked into handing over the key.

---

## 👤 Author

**Shovon** — Cybersecurity Track Intern
DecodeLabs Industrial Training Kit | Batch 2026

---

## 📜 License

Built as part of the DecodeLabs Internship Program for educational and portfolio purposes.
