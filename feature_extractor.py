import re
import urllib.parse
import socket
import logging
from typing import Dict, Any

class URLFeatureExtractor:
    """Extract features from URLs for phishing detection."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        # Common legitimate domains for reference
        self.legitimate_domains = {
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'twitter.com', 'linkedin.com', 'github.com',
            'stackoverflow.com', 'wikipedia.org', 'youtube.com'
        }
        
        # Suspicious keywords often found in phishing URLs
        self.phishing_keywords = [
            'verify', 'account', 'update', 'confirm', 'secure', 'suspend',
            'login', 'bank', 'paypal', 'amazon', 'microsoft', 'apple',
            'security', 'alert', 'urgent', 'action', 'required'
        ]
    
    def extract_features(self, url: str) -> Dict[str, Any]:
        """Extract comprehensive features from a URL."""
        try:
            features = {}
            
            # Basic URL properties
            features.update(self._extract_basic_features(url))
            
            # Domain-based features
            features.update(self._extract_domain_features(url))
            
            # Character-based features
            features.update(self._extract_character_features(url))
            
            # Structural features
            features.update(self._extract_structural_features(url))
            
            # Security-related features
            features.update(self._extract_security_features(url))
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting features from URL {url}: {e}")
            return self._get_default_features()
    
    def _extract_basic_features(self, url: str) -> Dict[str, Any]:
        """Extract basic URL features."""
        features = {}
        
        # URL length
        features['url_length'] = len(url)
        
        # Number of dots
        features['num_dots'] = url.count('.')
        
        # Number of slashes
        features['num_slashes'] = url.count('/')
        
        # Number of question marks
        features['num_question_marks'] = url.count('?')
        
        # Number of equal signs
        features['num_equal_signs'] = url.count('=')
        
        # Number of ampersands
        features['num_ampersands'] = url.count('&')
        
        return features
    
    def _extract_domain_features(self, url: str) -> Dict[str, Any]:
        """Extract domain-related features."""
        features = {}
        
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            
            # Domain length
            features['domain_length'] = len(domain)
            
            # Number of subdomains
            domain_parts = domain.split('.')
            features['num_subdomains'] = max(0, len(domain_parts) - 2)
            
            # Domain contains digits
            features['domain_has_digits'] = int(any(c.isdigit() for c in domain))
            
            # Domain contains hyphens
            features['domain_has_hyphens'] = int('-' in domain)
            
            # Is IP address
            features['is_ip_address'] = self._is_ip_address(domain)
            
            # Is legitimate domain
            features['is_legitimate_domain'] = int(any(legit in domain for legit in self.legitimate_domains))
            
            # Port number present
            features['has_port'] = int(':' in parsed.netloc and parsed.netloc.split(':')[-1].isdigit())
            
        except Exception as e:
            self.logger.warning(f"Error extracting domain features: {e}")
            features.update({
                'domain_length': 0,
                'num_subdomains': 0,
                'domain_has_digits': 0,
                'domain_has_hyphens': 0,
                'is_ip_address': 0,
                'is_legitimate_domain': 0,
                'has_port': 0
            })
        
        return features
    
    def _extract_character_features(self, url: str) -> Dict[str, Any]:
        """Extract character-based features."""
        features = {}
        
        # Special characters count
        features['num_special_chars'] = len(re.findall(r'[^a-zA-Z0-9]', url))
        
        # Uppercase letters count
        features['num_uppercase'] = sum(1 for c in url if c.isupper())
        
        # Lowercase letters count
        features['num_lowercase'] = sum(1 for c in url if c.islower())
        
        # Digits count
        features['num_digits'] = sum(1 for c in url if c.isdigit())
        
        # Ratio of digits to total length
        features['digit_ratio'] = features['num_digits'] / len(url) if len(url) > 0 else 0
        
        # Contains suspicious characters
        suspicious_chars = ['@', '%', '&', '=', '?', '#']
        features['has_suspicious_chars'] = int(any(char in url for char in suspicious_chars))
        
        return features
    
    def _extract_structural_features(self, url: str) -> Dict[str, Any]:
        """Extract URL structural features."""
        features = {}
        
        try:
            parsed = urllib.parse.urlparse(url)
            
            # Path length
            features['path_length'] = len(parsed.path)
            
            # Query length
            features['query_length'] = len(parsed.query)
            
            # Fragment length
            features['fragment_length'] = len(parsed.fragment)
            
            # Number of parameters
            features['num_params'] = len(parsed.query.split('&')) if parsed.query else 0
            
            # Path depth (number of directories)
            features['path_depth'] = len([p for p in parsed.path.split('/') if p])
            
            # Uses HTTPS
            features['uses_https'] = int(parsed.scheme == 'https')
            
            # Contains phishing keywords
            url_lower = url.lower()
            features['has_phishing_keywords'] = int(any(keyword in url_lower for keyword in self.phishing_keywords))
            
        except Exception as e:
            self.logger.warning(f"Error extracting structural features: {e}")
            features.update({
                'path_length': 0,
                'query_length': 0,
                'fragment_length': 0,
                'num_params': 0,
                'path_depth': 0,
                'uses_https': 0,
                'has_phishing_keywords': 0
            })
        
        return features
    
    def _extract_security_features(self, url: str) -> Dict[str, Any]:
        """Extract security-related features."""
        features = {}
        
        try:
            parsed = urllib.parse.urlparse(url)
            
            # URL shortener detection
            shorteners = [
                'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
                'short.link', 'tiny.cc', 'is.gd', 'buff.ly'
            ]
            features['is_shortened_url'] = int(any(short in parsed.netloc for short in shorteners))
            
            # Suspicious TLD
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
            features['has_suspicious_tld'] = int(any(parsed.netloc.endswith(tld) for tld in suspicious_tlds))
            
            # Multiple redirections (heuristic based on URL structure)
            features['likely_redirect'] = int('redirect' in url.lower() or 'r.php' in url.lower())
            
            # Contains encoding
            features['has_encoding'] = int('%' in url)
            
        except Exception as e:
            self.logger.warning(f"Error extracting security features: {e}")
            features.update({
                'is_shortened_url': 0,
                'has_suspicious_tld': 0,
                'likely_redirect': 0,
                'has_encoding': 0
            })
        
        return features
    
    def _is_ip_address(self, domain: str) -> int:
        """Check if domain is an IP address."""
        try:
            # Remove port if present
            domain_clean = domain.split(':')[0]
            socket.inet_aton(domain_clean)
            return 1
        except socket.error:
            return 0
    
    def _get_default_features(self) -> Dict[str, Any]:
        """Return default feature values for error cases."""
        return {
            'url_length': 0, 'num_dots': 0, 'num_slashes': 0, 'num_question_marks': 0,
            'num_equal_signs': 0, 'num_ampersands': 0, 'domain_length': 0,
            'num_subdomains': 0, 'domain_has_digits': 0, 'domain_has_hyphens': 0,
            'is_ip_address': 0, 'is_legitimate_domain': 0, 'has_port': 0,
            'num_special_chars': 0, 'num_uppercase': 0, 'num_lowercase': 0,
            'num_digits': 0, 'digit_ratio': 0, 'has_suspicious_chars': 0,
            'path_length': 0, 'query_length': 0, 'fragment_length': 0,
            'num_params': 0, 'path_depth': 0, 'uses_https': 0,
            'has_phishing_keywords': 0, 'is_shortened_url': 0,
            'has_suspicious_tld': 0, 'likely_redirect': 0, 'has_encoding': 0
        }

    def get_feature_names(self) -> list:
        """Get list of all feature names."""
        return list(self._get_default_features().keys())
