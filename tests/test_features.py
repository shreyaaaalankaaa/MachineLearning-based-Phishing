from feature_extractor import URLFeatureExtractor


def test_feature_extraction_is_deterministic():
    extractor = URLFeatureExtractor()
    url = "https://secure-paypal.example.net/login?verify=1"
    assert extractor.extract_features(url) == extractor.extract_features(url)


def test_ip_and_keywords_are_detected():
    features = URLFeatureExtractor().extract_features("http://203.0.113.10/verify/account")
    assert features["has_ip_host"] == 1
    assert features["has_phishing_term"] == 1
