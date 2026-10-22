import pytest
from app.ioc_validator import (
    validate_and_normalize_ioc,
    detect_ioc_type,
    normalize_defanged,
    IOCValidationError
)

def test_defanging_normalization():
    assert normalize_defanged("hxxps://malicious[.]example[.]com/path") == "https://malicious.example.com/path"
    assert normalize_defanged("192[.]168[.]1[.]100") == "192.168.1.100"
    assert normalize_defanged("2001[:]db8[:]85a3[:]8d3[:]1319[:]8a2e[:]370[:]7348") == "2001:db8:85a3:8d3:1319:8a2e:370:7348"

def test_ipv4_validation():
    normalized, ioc_type = validate_and_normalize_ioc("8.8.8.8")
    assert normalized == "8.8.8.8"
    assert ioc_type == "ipv4"
    
    # Defanged IPv4
    norm_defanged, t = validate_and_normalize_ioc("1[.]1[.]1[.]1")
    assert norm_defanged == "1.1.1.1"
    assert t == "ipv4"

    # Out of range IPv4
    with pytest.raises(IOCValidationError):
        validate_and_normalize_ioc("999.1.1.1", explicit_type="ipv4")

def test_ipv6_validation():
    ipv6_valid = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    normalized, ioc_type = validate_and_normalize_ioc(ipv6_valid)
    assert ioc_type == "ipv6"

    with pytest.raises(IOCValidationError):
        validate_and_normalize_ioc("2001:xyz::1", explicit_type="ipv6")

def test_domain_validation():
    normalized, ioc_type = validate_and_normalize_ioc("evil-domain.com")
    assert normalized == "evil-domain.com"
    assert ioc_type == "domain"

    # Defanged domain
    norm_def, t = validate_and_normalize_ioc("c2-server[.]evil[.]ru")
    assert norm_def == "c2-server.evil.ru"
    assert t == "domain"

    # Invalid domain
    with pytest.raises(IOCValidationError):
        validate_and_normalize_ioc("not_a_domain_at_all!", explicit_type="domain")

def test_url_validation():
    url = "https://phishing.site/login?user=admin"
    normalized, ioc_type = validate_and_normalize_ioc(url)
    assert ioc_type == "url"
    assert normalized.startswith("https://phishing.site/login")

    # Defanged URL
    norm_def, t = validate_and_normalize_ioc("hxxp://badsite[.]com/payload.exe")
    assert t == "url"
    assert norm_def.startswith("http://badsite.com")

def test_hashes_validation():
    md5_hash = "44d88612fea8a8f36de82e1278abb02f"
    norm_md5, t_md5 = validate_and_normalize_ioc(md5_hash)
    assert t_md5 == "md5"
    assert norm_md5 == md5_hash

    sha1_hash = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
    norm_sha1, t_sha1 = validate_and_normalize_ioc(sha1_hash)
    assert t_sha1 == "sha1"
    assert norm_sha1 == sha1_hash

    sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    norm_sha256, t_sha256 = validate_and_normalize_ioc(sha256_hash)
    assert t_sha256 == "sha256"
    assert norm_sha256 == sha256_hash

def test_empty_or_whitespace_input():
    with pytest.raises(IOCValidationError):
        validate_and_normalize_ioc("   ")
