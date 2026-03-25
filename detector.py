import re
from typing import List, Dict, Any
from urllib.parse import urlparse

class PhishDetector:
    def __init__(self):
        # High-risk keywords for email/SMS
        self.urgency_keywords = [
            "urgent", "verify", "suspend", "action required", "immediately", "account lock",
            "security alert", "suspicious activity", "failed login", "billing issue",
            "unauthorized", "confirm", "update now", "click here", "payment", "bank",
            "invoice", "overdue", "refund", "claim", "winner", "prize", "gift card",
            "congratulations", "lottery", "limited time", "expire", "access", "login"
        ]
        
        # Suspicious TLDs
        self.suspicious_tlds = [
            ".xyz", ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".buzz", ".work", ".site",
            ".online", ".icu", ".monster", ".cl", ".loan", ".racing", ".wang", ".bid"
        ]
        
        # Known lookalike brands (homographs / similar names)
        self.brand_keywords = ["paypal", "amazon", "google", "microsoft", "apple", "wellsfargo", "chase", "bankofamerica", "netflix", "facebook", "instagram"]

        # URL shorteners
        self.url_shorteners = ["bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "adf.ly", "rebrand.ly"]

    def analyze_url(self, url: str) -> Dict[str, Any]:
        if not url: return {"risk": "Low", "score": 0, "flags": []}
        
        score = 0
        flags = []
        
        # Add protocol if missing for parsing
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            
            # 1. HTTPS Check
            if parsed.scheme == 'http':
                score += 20
                flags.append("Insecure Protocol: Site does not use HTTPS encryption.")
            
            # 2. IP as Hostname
            if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
                score += 35
                flags.append("IP Hostname: Numerical addresses are often used to hide the actual domain.")
                
            # 3. Suspicious TLD
            for tld in self.suspicious_tlds:
                if domain.endswith(tld):
                    score += 25
                    flags.append(f"Suspicious TLD: The domain ends in '{tld}', which is frequently used by scammers.")
                    break
                    
            # 4. Lookalike / Typosquatting
            for brand in self.brand_keywords:
                # Check for things like payp-al, paypa1, secure-pay-pal
                if brand in domain and domain != f"{brand}.com" and domain != f"www.{brand}.com":
                    # Check if it's a subdomain of the real brand (e.g. login.paypal.com is OK)
                    if not domain.endswith(f".{brand}.com"):
                        score += 30
                        flags.append(f"Brand Impersonation: Domain contains '{brand}' but isn't the official site.")
                        break

            # 5. Excessive Subdomains
            subdomains = domain.split('.')
            if len(subdomains) > 3:
                score += 15
                flags.append("Excessive Subdomains: Multi-layered subdomains are common in phishing URLs.")

            # 6. URL Length
            if len(url) > 75:
                score += 10
                flags.append("Long URL: Phishers often use very long URLs to hide the real domain.")

            # 7. URL Shorteners
            for shortener in self.url_shorteners:
                if domain == shortener or domain.endswith(f".{shortener}"):
                    score += 15
                    flags.append("URL Shortener Detected: These are often used to mask malicious destinations.")
                    break

            # 8. Path Keywords
            danger_path_words = ["login", "verify", "secure", "account", "update", "signin", "banking"]
            for word in danger_path_words:
                if word in path:
                    score += 10
                    flags.append(f"Suspicious Path: The URL contains '{word}', commonly used in phishing forms.")
                    break

            # 9. Hyphens in Domain
            if domain.count("-") > 1:
                score += 10
                flags.append("Excessive Hyphens: Phishing domains often use multi-hyphenated names.")

        except Exception:
            score += 20
            flags.append("URL Parsing Error: Malformed URL structure.")

        risk = "Low"
        if score > 70: risk = "High"
        elif score > 30: risk = "Medium"
        
        return {
            "risk": risk,
            "score": min(score, 100),
            "flags": flags,
            "domain": domain if 'domain' in locals() else "Unknown"
        }

    def analyze_text(self, text: str, mode: str = "email") -> Dict[str, Any]:
        if not text: return {"risk": "Low", "score": 0, "flags": []}
        
        score = 0
        flags = []
        text_lower = text.lower()
        
        # 1. Keyword Detection
        found_keywords = []
        for word in self.urgency_keywords:
            if word in text_lower:
                found_keywords.append(word)
        
        if len(found_keywords) > 0:
            count = len(found_keywords)
            weighted_score = min(count * 8, 40)
            score += weighted_score
            flags.append(f"Urgent Language: Detected {count} high-risk keywords ({', '.join(found_keywords[:3])}...).")

        # 2. URL extraction and analysis
        urls = re.findall(r'(https?://[^\s<>"]+|www\.[^\s<>"]+)', text)
        if urls:
            highest_url_score = 0
            best_url_flags = []
            for url in urls[:3]: # Only check first 3
                url_res = self.analyze_url(url)
                if url_res["score"] > highest_url_score:
                    highest_url_score = url_res["score"]
                    best_url_flags = url_res["flags"]
            
            score += (highest_url_score * 0.7) # Weights URL heavy
            if highest_url_score > 30:
                flags.append(f"Malicious Link: Found a high-risk URL in the message.")
                # Deduplicate and add URL flags
                for f in best_url_flags:
                    if f not in flags: flags.append(f"[Link Info] {f}")

        # 3. OTP / SMS specific patterns
        if mode == "sms":
            if re.search(r"\b\d{4,6}\b", text) and ("code" in text_lower or "otp" in text_lower):
                score += 20
                flags.append("OTP Pattern: SMS looks like a one-time password request, often used in account takeovers.")
            if len(text) < 100 and urls:
                score += 15
                flags.append("Short Message + URL: Common smishing pattern (SMS Phishing).")

        # 4. Email specific patterns (Sender spoofing check would be elsewhere, but we can look for "Reply-To" or "From" fake patterns in text)
        if mode == "email":
            if "dear customer" in text_lower or "dear user" in text_lower:
                score += 10
                flags.append("Generic Greeting: Phishing often uses generic terms instead of your real name.")
            if "hidden-link" in text_lower or "@" in text_lower and not urls:
                # Basic check for obfuscated symbols
                pass

        risk = "Low"
        if score > 70: risk = "High"
        elif score > 30: risk = "Medium"
        
        return {
            "risk": risk,
            "score": min(round(score), 100),
            "flags": flags
        }
