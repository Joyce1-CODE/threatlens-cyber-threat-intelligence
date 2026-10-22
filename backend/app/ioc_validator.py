import re
import ipaddress
from urllib.parse import urlparse
from typing import Tuple, Optional

# Supported IOC Types
VALID_IOC_TYPES = {"ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"}

# Regex patterns for validation
DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)
MD5_REGEX = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_REGEX = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_REGEX = re.compile(r"^[a-fA-F0-9]{64}$")

class IOCValidationError(Exception):
    """Custom exception for IOC validation failures with clear explanatory message."""
    def __init__(self, message: str, field: str = "indicator"):
        super().__init__(message)
        self.message = message
        self.field = field

def normalize_defanged(input_str: str) -> str:
    """Cleans common cybersecurity defanging patterns (e.g. hxxp, [.], [:])."""
    cleaned = input_str.strip()
    
    # Replace defanged protocols
    cleaned = re.sub(r"^hxxps?://", lambda m: "https://" if "s" in m.group(0).lower() else "http://", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"^h\*\*ps?://", lambda m: "https://" if "s" in m.group(0).lower() else "http://", cleaned, flags=re.IGNORECASE)
    
    # Replace defanged dots, brackets, colons
    cleaned = cleaned.replace("[.]", ".").replace("(.)", ".").replace("{.}", ".")
    cleaned = cleaned.replace("[:]", ":").replace("(:)", ":")
    
    # Remove leading/trailing quotes or backticks
    chars_to_strip = "\"'` "
    cleaned = cleaned.strip(chars_to_strip)
    return cleaned

def detect_ioc_type(value: str) -> str:
    """Auto-detect the indicator type from normalized string."""
    # 1. Hashes
    if MD5_REGEX.match(value):
        return "md5"
    if SHA1_REGEX.match(value):
        return "sha1"
    if SHA256_REGEX.match(value):
        return "sha256"
        
    # 2. IP addresses
    try:
        ip_obj = ipaddress.ip_address(value)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            return "ipv4"
        if isinstance(ip_obj, ipaddress.IPv6Address):
            return "ipv6"
    except ValueError:
        pass
        
    # 3. URLs
    if value.lower().startswith(("http://", "https://")):
        try:
            parsed = urlparse(value)
            if parsed.scheme and parsed.netloc:
                return "url"
        except Exception:
            pass
            
    # 4. Domain
    domain_candidate = value.split(":")[0] if ":" in value else value
    if DOMAIN_REGEX.match(domain_candidate):
        return "domain"
        
    # 5. Check if it looks like URL without scheme (e.g. malicious.com/bad/path)
    if "/" in value and not value.startswith("/"):
        domain_part = value.split("/")[0].split(":")[0]
        if DOMAIN_REGEX.match(domain_part):
            return "url"
            
    raise IOCValidationError(
        f"Unable to determine indicator type for '{value}'. "
        "Please provide a valid IPv4, IPv6, Domain, URL, MD5, SHA-1, or SHA-256 hash."
    )

def validate_and_normalize_ioc(indicator: str, explicit_type: Optional[str] = None) -> Tuple[str, str]:
    """
    Validates and normalizes an indicator.
    Returns (normalized_indicator, detected_type).
    Raises IOCValidationError on malformed input.
    """
    if not indicator or not indicator.strip():
        raise IOCValidationError("Indicator cannot be empty.")
        
    normalized = normalize_defanged(indicator)
    requested_type = (explicit_type or "auto").lower().strip()
    
    if requested_type not in VALID_IOC_TYPES and requested_type != "auto":
        raise IOCValidationError(
            f"Invalid indicator type '{requested_type}'. Supported types: {', '.join(sorted(VALID_IOC_TYPES))} or 'auto'."
        )
        
    detected_type = detect_ioc_type(normalized) if requested_type == "auto" else requested_type
    
    # Specific type verification
    if detected_type == "ipv4":
        try:
            ip = ipaddress.IPv4Address(normalized)
            normalized = str(ip)
        except ValueError:
            raise IOCValidationError(f"'{normalized}' is not a valid IPv4 address (expected 4 octets 0-255 separated by dots).")
            
    elif detected_type == "ipv6":
        try:
            ip = ipaddress.IPv6Address(normalized)
            normalized = str(ip)
        except ValueError:
            raise IOCValidationError(f"'{normalized}' is not a valid IPv6 address.")
            
    elif detected_type == "domain":
        domain_candidate = normalized.lower().rstrip(".")
        if domain_candidate.startswith(("http://", "https://")):
            parsed = urlparse(domain_candidate)
            domain_candidate = (parsed.netloc or "").split(":")[0]
            
        if not DOMAIN_REGEX.match(domain_candidate):
            raise IOCValidationError(f"'{normalized}' is not a valid domain name (e.g. domain.com).")
        normalized = domain_candidate
        
    elif detected_type == "url":
        if not normalized.lower().startswith(("http://", "https://")):
            normalized = "http://" + normalized
            
        try:
            parsed = urlparse(normalized)
            if not parsed.scheme or not parsed.netloc:
                raise IOCValidationError(f"'{normalized}' is not a valid URL (missing scheme or network host).")
            normalized = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path or ''}"
            if parsed.params:
                normalized += f";{parsed.params}"
            if parsed.query:
                normalized += f"?{parsed.query}"
            if parsed.fragment:
                normalized += f"#{parsed.fragment}"
        except Exception as e:
            raise IOCValidationError(f"Failed to parse URL '{normalized}': {str(e)}")
            
    elif detected_type in {"md5", "sha1", "sha256"}:
        normalized = normalized.lower().strip()
        if detected_type == "md5" and not MD5_REGEX.match(normalized):
            raise IOCValidationError(f"'{normalized}' is not a valid 32-character hexadecimal MD5 hash.")
        elif detected_type == "sha1" and not SHA1_REGEX.match(normalized):
            raise IOCValidationError(f"'{normalized}' is not a valid 40-character hexadecimal SHA-1 hash.")
        elif detected_type == "sha256" and not SHA256_REGEX.match(normalized):
            raise IOCValidationError(f"'{normalized}' is not a valid 64-character hexadecimal SHA-256 hash.")
            
    return normalized, detected_type
