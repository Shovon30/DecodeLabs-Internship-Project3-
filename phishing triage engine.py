# ================================================================
# DecodeLabs | Cybersecurity Track | Batch 2026
# Project 3: Phishing Awareness Analysis — Triage Engine
# ================================================================
# SLIDE MAP (every detector references a slide):
#   Slide 9  -> IPO Model : Input(Bait) -> Process(Psychology) -> Output(Defense)
#   Slide 10 -> Targeting : Mass Phishing / Spear Phishing / Whaling
#   Slide 11 -> Channels  : Smishing(SMS), Vishing(Call), Quishing(QR), SEO Phishing
#   Slide 12 -> Headers   : Display Name Spoofing vs True Domain Spoofing
#   Slide 13 -> Lookalikes: Typosquatting, Homoglyph Attacks, Combosquatting
#   Slide 14 -> Subdomain Trap: "Read URLs right to left" + Dangling DNS Takeover
#   Slide 15 -> Psychology: Authority, Urgency, Curiosity, Fear/Greed
#   Slide 16 -> Red Flags 1-4  : Sender Mismatch, Fake FW Chain, BitB, Attachments
#   Slide 17 -> Red Flags 5-8  : Bypass Requests, Sensitive Info, Alerts, MFA Fatigue
#   Slide 18 -> Red Flags 9-11 : Callback Scam(TOAD), QR Prompts, Deepfake Meetings
#   Slide 19 -> Golden Rule: PAUSE -> VERIFY -> REPORT
#   Slide 24 -> Deliverable Mandate: Triage checklist + Decision Tree
#             Safe -> Close | Suspicious -> Warn User | Malicious -> Block & Escalate
# ================================================================

from __future__ import annotations  # allows list[str]/dict/tuple hints on Python < 3.9

import re
from urllib.parse import urlparse

# ================================================================
# REFERENCE DATA  (Slides 13, 15, 16-18)
# ================================================================

# Well-known brands frequently impersonated — brand keyword -> official domain
KNOWN_BRANDS = {
    "paypal":    "paypal.com",
    "amazon":    "amazon.com",
    "microsoft": "microsoft.com",
    "google":    "google.com",
    "apple":     "apple.com",
    "facebook":  "facebook.com",
    "netflix":   "netflix.com",
    "linkedin":  "linkedin.com",
    "chatgpt":   "openai.com",
    "dropbox":   "dropbox.com",
}

# Keywords commonly appended in Combosquatting attacks [Slide 13]
COMBOSQUAT_KEYWORDS = ["secure", "login", "verify", "update", "support",
                       "account", "billing", "confirm", "auth", "portal"]

# Domains known to shorten/hide the real destination
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl",
                  "ow.ly", "is.gd", "buff.ly", "cutt.ly"}

# File extensions capable of executing code [Slide 16, Red Flag 4]
DANGEROUS_EXTENSIONS = {".exe", ".scr", ".js", ".iso", ".vbs",
                        ".bat", ".jar", ".lnk", ".hta", ".msi", ".ps1"}

# Cognitive trigger keyword banks [Slide 15]
URGENCY_KEYWORDS = ["urgent", "immediately", "act now", "expires in",
                    "locked in", "final notice", "act fast", "verify now",
                    "limited time", "overdue", "asap"]

AUTHORITY_KEYWORDS = ["ceo", "strictly confidential", "do not discuss",
                      "bypass standard procedure", "law enforcement", "irs",
                      "government agency", "executive order",
                      "it department", "it support"]

FEAR_GREED_KEYWORDS = ["legal action", "account will be suspended",
                       "you have won", "claim your prize", "unclaimed funds",
                       "free gift", "lottery", "suspended", "penalty"]

CURIOSITY_KEYWORDS = ["see what", "you won't believe", "someone shared",
                      "click to find out", "shared a file with you"]

SENSITIVE_INFO_KEYWORDS = ["password", "one-time code", "otp",
                           "verification code", "card number", "cvv",
                           "social security", "ssn", "pin number",
                           "login credentials", "employee password"]


# ================================================================
# HELPER: Levenshtein Distance (for Typosquatting detection)
# Slide 13: "amaz0n.com" is 1 edit away from "amazon.com"
# ================================================================
def levenshtein(a: str, b: str) -> int:
    """Classic edit-distance DP. Measures how many single-character
    edits separate two strings — the basis for typosquat detection."""
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr.append(min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


# ================================================================
# HELPER: Negation-aware keyword search
# Prevents "Non-Urgent" from falsely triggering the "urgent" flag —
# a real detection engine must avoid false positives or analysts
# stop trusting it.
# ================================================================
def find_keywords(text: str, keywords: list[str]) -> list[str]:
    text_lower = text.lower()
    found = []
    for kw in keywords:
        pattern = r'\b' + re.escape(kw.lower()) + r'\b'
        for match in re.finditer(pattern, text_lower):
            preceding = text_lower[max(0, match.start() - 5):match.start()]
            if "non-" in preceding or "not " in preceding:
                continue                      # negation guard
            found.append(kw)
            break
    return found


# ================================================================
# URL / DOMAIN ANALYSIS  (Slides 13, 14)
# ================================================================
def extract_urls(text: str) -> list[str]:
    """Pulls raw URLs out of free-form message text."""
    return re.findall(r'https?://[^\s<>"\')]+|www\.[^\s<>"\')]+', text)


def get_hostname(url: str) -> str:
    """Extracts just the hostname from a URL, e.g. 'paypa1.com'."""
    if not re.match(r'^[a-zA-Z]+://', url):
        url = "http://" + url
    return (urlparse(url).hostname or "").lower()


def get_root_domain(hostname: str) -> str:
    """
    Returns the TRUE root domain — the last two labels.
    NOTE: naive heuristic (doesn't handle multi-part TLDs like .co.uk),
    which is a fair simplification for a training-kit triage engine.
    """
    parts = hostname.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def analyze_domain(hostname: str) -> list[tuple]:
    """
    Runs every lookalike-domain check from Slides 13-14 against a
    single hostname. Used for BOTH the sender's email domain and
    every URL found in the message body.

    Returns list of (flag_key, weight, evidence, why) tuples.
    """
    findings = []
    if not hostname:
        return findings

    # ── IP-based URL [strong red flag: no real domain at all] ──────
    # Checked FIRST and returned early: an IP has no "subdomains" or
    # "root domain" in the DNS sense, so none of the lookalike-domain
    # checks below are meaningful once this fires.
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname):
        findings.append((
            "IP_BASED_URL", 4, hostname,
            "Link points directly to a raw IP address instead of a domain — "
            "legitimate services almost never do this."
        ))
        return findings

    root = get_root_domain(hostname)
    subdomain_labels = hostname.split(".")[:-2]   # everything before the root

    # ── Homoglyph / Punycode [Slide 13] ─────────────────────────────
    if "xn--" in hostname or any(ord(c) > 127 for c in hostname):
        findings.append((
            "HOMOGLYPH", 4, hostname,
            "Domain contains non-standard or Punycode-encoded characters — "
            "a classic sign of a homoglyph attack (e.g. Cyrillic 'а' instead of 'a')."
        ))

    # ── Typosquatting & Combosquatting vs. known brands [Slide 13] ──
    for brand, official_domain in KNOWN_BRANDS.items():
        if root == official_domain:
            continue  # exact legitimate match, skip

        # Typosquat: root domain is 1-2 edits away from the real brand
        brand_root = official_domain.split(".")[0]
        root_base = root.split(".")[0]
        if levenshtein(root_base, brand_root) <= 2 and root_base != brand_root:
            findings.append((
                "TYPOSQUATTING", 3, f"{hostname} (mimics {official_domain})",
                f"Domain is a near-identical misspelling of '{official_domain}' — "
                "designed to be misread at a glance."
            ))

        # Combosquat: brand name + suspicious keyword, wrong root domain
        if brand in hostname and any(k in hostname for k in COMBOSQUAT_KEYWORDS):
            findings.append((
                "COMBOSQUATTING", 3, hostname,
                f"Domain embeds the brand name '{brand}' alongside a trust "
                "keyword (secure/verify/login/etc.) but is NOT the official domain."
            ))

    # ── Subdomain Trap [Slide 14 — read right to left] ──────────────
    if len(subdomain_labels) >= 2:
        findings.append((
            "SUBDOMAIN_TRAP", 4, hostname,
            f"True root domain is '{root}'. Everything before it "
            f"('{'.'.join(subdomain_labels)}') is just a fake subdomain "
            "designed to look trustworthy. Always read URLs right to left."
        ))

    # ── URL Shortener [hides destination] ────────────────────────────
    if root in URL_SHORTENERS:
        findings.append((
            "URL_SHORTENER", 2, hostname,
            "Shortened link — the real destination is hidden until clicked."
        ))

    return findings


# ================================================================
# MESSAGE-LEVEL RED FLAG CHECKS  (Slides 16, 17, 18 — Red Flags 1-11)
# ================================================================
def check_sender_domain_mismatch(msg: dict) -> list[tuple]:
    """Red Flag 1 [Slide 16]: Display name / claimed org vs actual domain."""
    sender_email = msg.get("sender_email", "")
    claimed = msg.get("claimed_domain", "")
    if not sender_email or not claimed:
        return []
    actual_domain = sender_email.split("@")[-1].lower()
    if get_root_domain(actual_domain) != get_root_domain(claimed):
        return [(
            "SENDER_DOMAIN_MISMATCH", 3,
            f"Claims to be from '{claimed}' but sent from '{actual_domain}'",
            "The display name suggests a trusted source, but the actual "
            "sending domain does not match — classic display-name spoofing."
        )]
    return []


def check_fake_forwarded_chain(msg: dict) -> list[tuple]:
    """Red Flag 2 [Slide 16]: FW:/RE: prefix with no genuine thread context."""
    subject = msg.get("subject", "")
    if re.match(r'^\s*(FW|RE)\s*:', subject, re.IGNORECASE):
        return [(
            "FAKE_FORWARDED_CHAIN", 1, subject,
            "Subject carries a forwarded/reply prefix — verify you were "
            "actually part of this thread before trusting its contents."
        )]
    return []


def check_dangerous_attachments(msg: dict) -> list[tuple]:
    """Red Flag 4 [Slide 16]: Executable-capable file extensions."""
    findings = []
    for att in msg.get("attachments", []):
        ext = "." + att.rsplit(".", 1)[-1].lower() if "." in att else ""
        if ext in DANGEROUS_EXTENSIONS:
            findings.append((
                "DANGEROUS_ATTACHMENT", 4, att,
                f"File extension '{ext}' can execute code on open — "
                "never seen in routine document attachments."
            ))
    return findings


def check_urgent_bypass(msg: dict) -> list[tuple]:
    """Red Flag 5 [Slide 17]: Demands to bypass normal procedure/secrecy."""
    matches = find_keywords(msg.get("body", ""), AUTHORITY_KEYWORDS)
    if matches:
        return [(
            "AUTHORITY_BYPASS", 3, ", ".join(matches),
            "Message impersonates authority and/or demands secrecy or a "
            "bypass of standard procedure — a pressure tactic, not policy."
        )]
    return []


def check_sensitive_info_request(msg: dict) -> list[tuple]:
    """Red Flag 6 [Slide 17]: Unsolicited request for credentials/PII."""
    matches = find_keywords(msg.get("body", ""), SENSITIVE_INFO_KEYWORDS)
    if matches:
        return [(
            "SENSITIVE_INFO_REQUEST", 4, ", ".join(matches),
            "Legitimate services never ask you to email/type your password, "
            "OTP, or card details in response to a message."
        )]
    return []


def check_mfa_fatigue(msg: dict) -> list[tuple]:
    """Red Flag 8 [Slide 17]: Repeated unprompted MFA push requests."""
    body = msg.get("body", "").lower()
    if body.count("approve") >= 2 or "mfa fatigue" in body:
        return [(
            "MFA_FATIGUE", 3, "Multiple 'Approve' prompts detected",
            "Repeated unsolicited MFA pushes are designed to wear you down "
            "until you tap Approve by reflex or exhaustion."
        )]
    return []


def check_callback_scam(msg: dict) -> list[tuple]:
    """Red Flag 9 [Slide 18]: TOAD — phone number, no link, urgency."""
    body = msg.get("body", "")
    has_phone = bool(re.search(r'1-?800[-.\s]?\d{3}[-.\s]?\d{4}|\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}', body))
    has_url = bool(extract_urls(body)) or bool(msg.get("urls"))
    urgent = bool(find_keywords(body, URGENCY_KEYWORDS))
    if has_phone and not has_url and urgent:
        return [(
            "CALLBACK_SCAM_TOAD", 3, "Phone number present, no verifiable link",
            "No malicious link at all — just an urgent phone number. This "
            "is Telephone-Oriented Attack Delivery (TOAD): the scam happens "
            "on the call, not in the message."
        )]
    return []


def check_qr_prompt(msg: dict) -> list[tuple]:
    """Red Flag 10 [Slide 18]: Unsolicited QR code demanding a scan."""
    body = msg.get("body", "").lower()
    if "qr code" in body or "scan to" in body or msg.get("channel") == "qr":
        return [(
            "QR_PROMPT", 3, "Message requests scanning a QR code",
            "QR codes push you onto an unmanaged mobile device where "
            "desktop URL filters and hover-to-preview don't apply."
        )]
    return []


def check_deepfake_meeting(msg: dict) -> list[tuple]:
    """Red Flag 11 [Slide 18]: Voicemail/meeting impersonation + payment ask."""
    body = msg.get("body", "").lower()
    if ("voicemail" in body or "confirm as discussed" in body) and \
       ("payment" in body or "transfer" in body or "confirm" in body):
        return [(
            "DEEPFAKE_MEETING_FRAUD", 3, "Voicemail + payment confirmation combo",
            "Pairs an AI-cloneable voice message with a follow-up text asking "
            "you to 'confirm as discussed' — verify via a separate, known channel."
        )]
    return []


def check_cognitive_triggers(msg: dict) -> list[tuple]:
    """Psychology layer [Slide 15]: Urgency, Fear/Greed, Curiosity."""
    findings = []
    body = msg.get("body", "") + " " + msg.get("subject", "")

    urgency = find_keywords(body, URGENCY_KEYWORDS)
    if urgency:
        findings.append((
            "URGENCY_TRIGGER", 2, ", ".join(urgency),
            "Creates artificial time pressure to short-circuit careful thinking."
        ))

    fear_greed = find_keywords(body, FEAR_GREED_KEYWORDS)
    if fear_greed:
        findings.append((
            "FEAR_GREED_TRIGGER", 2, ", ".join(fear_greed),
            "Threatens a negative consequence or dangles an unearned reward."
        ))

    curiosity = find_keywords(body, CURIOSITY_KEYWORDS)
    if curiosity:
        findings.append((
            "CURIOSITY_TRIGGER", 1, ", ".join(curiosity),
            "Exploits the urge to fill a knowledge gap ('see what X said')."
        ))

    return findings


# ================================================================
# MASTER ANALYSIS  —  IPO "Process" Stage (Slide 9)
# ================================================================
def analyze_message(msg: dict) -> dict:
    """
    Runs every detector, aggregates flags by category (so multiple
    pieces of evidence for the same technique count once toward the
    score but are all shown in the report), then classifies.

    Decision Tree [Slide 24]:
      score == 0       -> SAFE        -> Close
      1 <= score <= 4   -> SUSPICIOUS  -> Warn User
      score >= 5        -> MALICIOUS   -> Block & Escalate
    """
    flags = {}

    def add(key, weight, evidence, why):
        if key not in flags:
            flags[key] = {"weight": weight, "evidence": [], "why": why}
        flags[key]["evidence"].append(evidence)

    # ── message-level checks ─────────────────────────────────────
    for key, weight, evidence, why in (
        check_sender_domain_mismatch(msg)
        + check_fake_forwarded_chain(msg)
        + check_dangerous_attachments(msg)
        + check_urgent_bypass(msg)
        + check_sensitive_info_request(msg)
        + check_mfa_fatigue(msg)
        + check_callback_scam(msg)
        + check_qr_prompt(msg)
        + check_deepfake_meeting(msg)
        + check_cognitive_triggers(msg)
    ):
        add(key, weight, evidence, why)

    # ── domain-level checks: sender email + every URL ───────────────
    sender_domain = msg.get("sender_email", "").split("@")[-1] if msg.get("sender_email") else ""
    all_hosts = [sender_domain] if sender_domain else []
    body_urls = extract_urls(msg.get("body", "")) + msg.get("urls", [])
    all_hosts += [get_hostname(u) for u in body_urls]

    for host in all_hosts:
        for key, weight, evidence, why in analyze_domain(host):
            add(key, weight, evidence, why)

    # ── scoring & classification ────────────────────────────────────
    score = sum(f["weight"] for f in flags.values())
    if score == 0:
        classification, action = "SAFE", "Close"
    elif score <= 4:
        classification, action = "SUSPICIOUS", "Warn User"
    else:
        classification, action = "MALICIOUS", "Block & Escalate"

    return {"flags": flags, "score": score, "classification": classification, "action": action}


# ================================================================
# DISPLAY — IPO "Output" Stage (Slide 9)
# ================================================================
def display_report(msg: dict, report: dict):
    divider = "=" * 64
    thin = "-" * 64
    sev_icon = {1: "🔵", 2: "🟡", 3: "🟠", 4: "🔴"}
    class_icon = {"SAFE": "🟢", "SUSPICIOUS": "🟡", "MALICIOUS": "🔴"}

    print()
    print(divider)
    print(f"  DecodeLabs | Phishing Triage Report")
    print(divider)
    print(f"  From    : {msg.get('sender_name','?')} <{msg.get('sender_email','N/A')}>")
    print(f"  Subject : {msg.get('subject','(no subject)')}")
    print(f"  Channel : {msg.get('channel','email').upper()}")
    print(thin)

    if not report["flags"]:
        print("  No red flags detected.")
    else:
        print(f"  Red Flags Found ({len(report['flags'])}):")
        print()
        for key, data in report["flags"].items():
            icon = sev_icon.get(data["weight"], "⚪")
            label = key.replace("_", " ").title()
            print(f"  {icon} [{label}]")
            print(f"      Evidence : {', '.join(str(e) for e in data['evidence'])}")
            print(f"      Why unsafe: {data['why']}")
            print()

    print(thin)
    print(f"  Risk Score     : {report['score']}")
    print(f"  Classification : {class_icon[report['classification']]}  {report['classification']}")
    print(f"  Decision       : {report['action']}")
    print(divider)

    if report["classification"] != "SAFE":
        print("  ⚠  GOLDEN RULE [Slide 19]: PAUSE. VERIFY. REPORT.")
        print("     Do not click, reply, or call any number in this message.")
        print("     Verify via a separate, known channel before acting.")
        print(divider)
    print()


def display_checklist():
    """Prints the non-expert triage checklist [Slide 24 deliverable]."""
    print()
    print("=" * 64)
    print("  DecodeLabs | Non-Expert Phishing Triage Checklist")
    print("=" * 64)
    print("""
  Ask these questions about ANY unexpected message:

  1.  Sender-Domain Mismatch   — Does the display name match the
                                  actual email address/domain?
  2.  Fake Forwarded Chain     — Is this an "FW:"/"RE:" you were
                                  never part of?
  3.  Browser-in-the-Browser   — Is a "sign in" pop-up impossible
                                  to drag outside the browser window?
  4.  Dangerous Attachments    — Any .exe, .scr, .js, .iso, .hta file?
  5.  Urgent Bypass Requests   — Told to keep it secret or skip
                                  normal procedure?
  6.  Sensitive Info Requests  — Asked for a password, OTP, or
                                  card number by message?
  7.  Activity Alerts          — An alarming "unusual sign-in"
                                  pointing straight to a login page?
  8.  MFA Fatigue              — Multiple unprompted "Approve"
                                  push notifications?
  9.  Callback Scam (TOAD)     — Just a phone number, no link,
                                  demanding an urgent call?
  10. QR Code Prompts          — An unsolicited QR code to "scan
                                  to unlock" or "verify"?
  11. Deepfake Meeting Fraud   — A voicemail/call asking you to
                                  "confirm" a payment as discussed?

  ── URL RED FLAGS ──────────────────────────────────────────────
  • Is it a raw IP address instead of a domain?
  • Is the spelling ALMOST right? (amaz0n.com)
  • Does it contain foreign characters? (homoglyphs)
  • Read the URL RIGHT TO LEFT. What is the true root domain?

  ── DECISION TREE ──────────────────────────────────────────────
    Safe          -> Close
    Suspicious    -> Warn User
    Malicious     -> Block & Escalate

  ── THE GOLDEN RULE ────────────────────────────────────────────
    1. PAUSE   — Stop interacting with the message.
    2. VERIFY  — Confirm through a separate, known channel.
    3. REPORT  — Use official reporting tools. Never just delete.
""")
    print("=" * 64)
    print()


# ================================================================
# SAMPLE DATASET  — pulled directly from the training kit's own
# examples (Slides 8, 12, 20-22) plus original variations to cover
# every detector at least once.
# ================================================================
SAMPLE_MESSAGES = [
    {
        "label": "Legitimate — Project Update",
        "sender_name": "Project Manager", "sender_email": "sarah.lee@company.com",
        "claimed_domain": "company.com", "channel": "email",
        "subject": "Q3 Project Status Update - Non-Urgent",
        "body": "Hi Team, Please review the attached project status for Q3 "
                "at your earliest convenience. No immediate action is required. "
                "Thanks, Sarah.",
        "attachments": ["Q3_Status.pdf"], "urls": [],
    },
    {
        "label": "CEO Wire Transfer Scam (BEC)",
        "sender_name": "CEO Name", "sender_email": "hacker@gmail.com",
        "claimed_domain": "company.com", "channel": "email",
        "subject": "IMMEDIATE ACTION REQUIRED: Transfer Authorization",
        "body": "URGENT: Process the attached wire transfer instruction "
                "immediately. This is critical and must remain STRICTLY "
                "CONFIDENTIAL. Do not discuss with anyone. Bypass standard "
                "procedure. Thank you.",
        "attachments": [], "urls": [],
    },
    {
        "label": "Fake Microsoft Password Reset",
        "sender_name": "Microsoft Support", "sender_email": "support@logins-updates.com",
        "claimed_domain": "microsoft.com", "channel": "email",
        "subject": "FW: Urgent Your Account Security Alert",
        "body": "Your account will be locked in 30 minutes. Click below to "
                "verify your password immediately using the secure sign in link.",
        "attachments": ["Security_Update_2024.iso"],
        "urls": ["http://logins-updates.com/signin"],
    },
    {
        "label": "BEC — Lost Wallet SMS",
        "sender_name": "CEO", "sender_email": "", "claimed_domain": "",
        "channel": "sms", "subject": "(SMS)",
        "body": "I lost my wallet at the airport. Need you to wire transfer "
                "funds for my flight immediately. - CEO",
        "attachments": [], "urls": [],
    },
    {
        "label": "ChatGPT Payment Failure Phishing",
        "sender_name": "ChatGPT Billing", "sender_email": "billing@chatgpt-support.net",
        "claimed_domain": "openai.com", "channel": "email",
        "subject": "Urgent: ChatGPT Payment Failure",
        "body": "Your subscription payment failed. Please update your "
                "billing information immediately to avoid service interruption.",
        "attachments": [], "urls": ["http://chatgpt-billing-verify.com/update"],
    },
    {
        "label": "Google Account Recovery Quishing (QR)",
        "sender_name": "Google Account Recovery", "sender_email": "",
        "claimed_domain": "", "channel": "qr",
        "subject": "(Physical Poster / QR Code)",
        "body": "Google Account Recovery: Scan to Unlock. Scan this QR code "
                "immediately to prevent account lockout.",
        "attachments": [], "urls": [],
    },
    {
        "label": "Microsoft Subscription Callback Scam (TOAD)",
        "sender_name": "Microsoft Billing", "sender_email": "billing@microsoft-notify.com",
        "claimed_domain": "microsoft.com", "channel": "email",
        "subject": "Official Microsoft Subscription Renewal - Payment Overdue",
        "body": "PAYMENT OVERDUE: Call 1-800-555-0199 to cancel IMMEDIATELY. "
                "Your subscription renewal charge will process automatically "
                "unless you call now.",
        "attachments": [], "urls": [],
    },
    {
        "label": "HR Benefits Portal — Subdomain Trap",
        "sender_name": "Human Resources", "sender_email": "hr@company-benefits-portal.com",
        "claimed_domain": "company.com", "channel": "email",
        "subject": "Action Required: 2026 Healthcare Benefits Questionnaire",
        "body": "Please log in and complete your healthcare benefits "
                "questionnaire by Friday. Enter your employee password to "
                "access the portal.",
        "attachments": [], "urls": ["http://company.com.benefits-portal.net/login"],
    },
    {
        "label": "PayPal Typosquat + IP-based Link",
        "sender_name": "PayPal Security", "sender_email": "security@paypa1.com",
        "claimed_domain": "paypal.com", "channel": "email",
        "subject": "Unusual sign-in activity detected",
        "body": "We noticed unusual sign-in activity on your account. Verify "
                "your identity immediately or your account will be suspended.",
        "attachments": [], "urls": ["http://192.168.45.22/paypal/verify",
                                     "http://paypa1.com/login"],
    },
    {
        "label": "PayPal Homoglyph + Combosquat",
        "sender_name": "PayPal", "sender_email": "service@paypal-support.com",
        "claimed_domain": "paypal.com", "channel": "email",
        "subject": "Confirm your recent transaction",
        "body": "Please confirm your recent transaction by logging in securely.",
        "attachments": [], "urls": ["http://p\u0430ypal.com/confirm"],  # Cyrillic 'а'
    },
]


# ================================================================
# INPUT HELPERS — Custom Message Analysis Mode
# ================================================================
def get_custom_message() -> dict:
    print("\n  Enter message details (press Enter to skip optional fields):\n")
    sender_name = input("  Sender display name        : ").strip()
    sender_email = input("  Sender email address        : ").strip()
    claimed_domain = input("  Domain it CLAIMS to be from : ").strip()
    subject = input("  Subject line                : ").strip()
    print("  Message body (end with an empty line):")
    lines = []
    while True:
        line = input("    ")
        if line == "":
            break
        lines.append(line)
    body = "\n".join(lines)
    urls_raw = input("  Additional URLs (comma-separated): ").strip()
    urls = [u.strip() for u in urls_raw.split(",")] if urls_raw else []
    att_raw = input("  Attachment filenames (comma-separated): ").strip()
    attachments = [a.strip() for a in att_raw.split(",")] if att_raw else []
    channel = input("  Channel [email/sms/qr/call] (default email): ").strip() or "email"

    return {
        "sender_name": sender_name, "sender_email": sender_email,
        "claimed_domain": claimed_domain, "channel": channel,
        "subject": subject, "body": body,
        "urls": urls, "attachments": attachments,
    }


# ================================================================
# MAIN — Orchestrates the Full IPO Model (Slide 9)
# ================================================================
def main():
    BANNER = """
  ╔══════════════════════════════════════════════════════════╗
  ║     DecodeLabs Cybersecurity  |  Batch 2026              ║
  ║     Project 3: Phishing Awareness Analysis                ║
  ║     "The perimeter is no longer the firewall. It's you." ║
  ╚══════════════════════════════════════════════════════════╝
    """
    print(BANNER)

    MENU = """  Select a mode:
  [1] Analyze Sample Dataset  — run all 10 built-in test messages
  [2] Analyze Custom Message  — paste in your own email/SMS
  [3] View Triage Checklist   — the non-expert reference card
  [q] Quit
"""

    while True:
        print(MENU)
        choice = input("  Your choice: ").strip().lower()

        if choice == "1":
            for msg in SAMPLE_MESSAGES:
                report = analyze_message(msg)
                print(f"\n  ▶ SAMPLE: {msg['label']}")
                display_report(msg, report)
                input("  Press Enter for next sample...")

        elif choice == "2":
            msg = get_custom_message()
            report = analyze_message(msg)
            display_report(msg, report)

        elif choice == "3":
            display_checklist()

        elif choice == "q":
            print("  Session ended. Pause. Verify. Report.\n")
            break

        else:
            print("  ✗ Invalid choice. Please enter 1, 2, 3, or q.\n")


if __name__ == "__main__":
    main()