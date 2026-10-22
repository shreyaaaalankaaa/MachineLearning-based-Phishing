from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from typing import Any, ClassVar
from urllib.parse import parse_qsl, urlparse


class URLFeatureExtractor:
    """Extract deterministic lexical and structural features from a URL.

    The extractor deliberately avoids network requests so predictions remain fast,
    reproducible, and safe to run in local or CI environments.
    """

    SHORTENERS : ClassVar[set[str]] = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
        "buff.ly", "cutt.ly", "rb.gy", "rebrand.ly",
    }
    SUSPICIOUS_TLDS : ClassVar[set[str]] = {
        "zip", "mov", "click", "top", "xyz", "work", "support", "gq",
        "tk", "ml", "ga", "cf", "rest", "cam", "buzz",
    }
    PHISHING_TERMS  : ClassVar[set[str]] = {
        "login", "signin", "verify", "verification", "secure", "account",
        "update", "confirm", "suspend", "unlock", "password", "credential",
        "wallet", "bank", "billing", "invoice", "payment", "urgent",
    }
    BRAND_TERMS : ClassVar[set[str]] = {
        "paypal", "microsoft", "apple", "google", "amazon", "netflix",
        "instagram", "facebook", "whatsapp", "coinbase", "binance",
    }

    def normalize(self, url: str) -> str:
        value = (url or "").strip()
        if not value:
            raise ValueError("URL cannot be empty")
        if len(value) > 2048:
            raise ValueError("URL exceeds the 2,048 character limit")
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
            value = f"https://{value}"
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS URLs are supported")
        if not parsed.hostname:
            raise ValueError("A valid hostname is required")
        return value

    def extract_features(self, url: str) -> dict[str, float]:
        value = self.normalize(url)
        parsed = urlparse(value)
        host = (parsed.hostname or "").lower().rstrip(".")
        path_query = f"{parsed.path}?{parsed.query}" if parsed.query else parsed.path
        labels = [part for part in host.split(".") if part]
        tld = labels[-1] if labels else ""
        tokens = [token for token in re.split(r"[^a-z0-9]+", value.lower()) if token]
        token_counts = Counter(tokens)
        host_is_ip = self._is_ip(host)
        entropy = self._entropy(host.replace(".", ""))

        return {
            "url_length": float(len(value)),
            "hostname_length": float(len(host)),
            "path_length": float(len(parsed.path)),
            "query_length": float(len(parsed.query)),
            "fragment_length": float(len(parsed.fragment)),
            "dot_count": float(value.count(".")),
            "hyphen_count": float(value.count("-")),
            "slash_count": float(value.count("/")),
            "at_count": float(value.count("@")),
            "question_count": float(value.count("?")),
            "equals_count": float(value.count("=")),
            "ampersand_count": float(value.count("&")),
            "percent_count": float(value.count("%")),
            "digit_count": float(sum(ch.isdigit() for ch in value)),
            "digit_ratio": self._ratio(sum(ch.isdigit() for ch in value), len(value)),
            "special_ratio": self._ratio(sum(not ch.isalnum() for ch in value), len(value)),
            "subdomain_count": float(max(0, len(labels) - 2) if not host_is_ip else 0),
            "parameter_count": float(len(parse_qsl(parsed.query, keep_blank_values=True))),
            "path_depth": float(len([part for part in parsed.path.split("/") if part])),
            "uses_https": float(parsed.scheme == "https"),
            "has_ip_host": float(host_is_ip),
            "has_explicit_port": float(parsed.port is not None),
            "has_punycode": float("xn--" in host),
            "has_shortener": float(host in self.SHORTENERS or any(host.endswith(f".{d}") for d in self.SHORTENERS)),
            "has_suspicious_tld": float(tld in self.SUSPICIOUS_TLDS),
            "has_double_slash_path": float("//" in parsed.path),
            "has_encoded_chars": float(bool(re.search(r"%[0-9a-fA-F]{2}", value))),
            "has_phishing_term": float(any(term in token_counts for term in self.PHISHING_TERMS)),
            "phishing_term_count": float(sum(token_counts[t] for t in self.PHISHING_TERMS)),
            "brand_term_count": float(sum(token_counts[t] for t in self.BRAND_TERMS)),
            "brand_in_subdomain_or_path": float(self._brand_outside_registered_domain(host, path_query)),
            "hostname_entropy": float(entropy),
            "longest_token_length": float(max((len(token) for token in tokens), default=0)),
        }

    def explain(self, features: dict[str, float]) -> list[dict[str, Any]]:
        rules = [
            ("has_ip_host", "IP address used as the hostname", 24),
            ("has_punycode", "Internationalized-domain encoding detected", 18),
            ("has_shortener", "Known URL-shortening service", 13),
            ("has_suspicious_tld", "Higher-risk top-level domain", 12),
            ("brand_in_subdomain_or_path", "Brand name appears outside the main domain", 18),
            ("has_phishing_term", "Credential or account-related wording", 10),
            ("has_encoded_chars", "Percent-encoded characters present", 7),
            ("has_explicit_port", "Non-default port is explicitly specified", 7),
            ("has_double_slash_path", "Additional double slash appears in the path", 6),
        ]
        reasons: list[dict[str, Any]] = []
        for key, label, weight in rules:
            if features.get(key, 0) > 0:
                reasons.append({"feature": key, "label": label, "weight": weight})
        if features.get("url_length", 0) >= 100:
            reasons.append({"feature": "url_length", "label": "Unusually long URL", "weight": 10})
        if features.get("subdomain_count", 0) >= 3:
            reasons.append({"feature": "subdomain_count", "label": "Deep subdomain structure", "weight": 9})
        if features.get("hostname_entropy", 0) >= 3.7:
            reasons.append({"feature": "hostname_entropy", "label": "Hostname has high character randomness", "weight": 8})
        if features.get("digit_ratio", 0) >= 0.18:
            reasons.append({"feature": "digit_ratio", "label": "High proportion of digits", "weight": 6})
        if features.get("uses_https", 0) == 0:
            reasons.append({"feature": "uses_https", "label": "Connection does not use HTTPS", "weight": 4})
        return sorted(reasons, key=lambda item: item["weight"], reverse=True)

    def feature_names(self) -> list[str]:
        return list(self.extract_features("https://example.com").keys())

    @staticmethod
    def _ratio(value: int, total: int) -> float:
        return value / total if total else 0.0

    @staticmethod
    def _is_ip(host: str) -> bool:
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    @staticmethod
    def _entropy(text: str) -> float:
        if not text:
            return 0.0
        counts = Counter(text)
        length = len(text)
        return -sum((count / length) * math.log2(count / length) for count in counts.values())

    def _brand_outside_registered_domain(self, host: str, path_query: str) -> bool:
        labels = host.split(".")
        registrable_guess = labels[-2] if len(labels) >= 2 else host
        outside = ".".join(labels[:-2]) + " " + path_query.lower()
        return any(brand in outside and brand not in registrable_guess for brand in self.BRAND_TERMS)
