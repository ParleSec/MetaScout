"""
Pattern matching for metadata analysis
"""

import re
from typing import Dict, List, Any

from ..core.models import MetadataFinding
from ..config.constants import PRIVACY_CONCERNS
from .base import BaseAnalyzer


class PatternAnalyzer(BaseAnalyzer):
    """
    Analyzer for finding patterns in metadata across all file types.
    Focuses on identifying personally identifiable information (PII)
    and other sensitive data patterns.
    """
    
    @classmethod
    def can_handle(cls, file_type: str) -> bool:
        """This analyzer can handle any file type."""
        return True
    
    def analyze(self, metadata: Dict[str, Any]) -> List[MetadataFinding]:
        """
        Search for patterns like emails, phone numbers, SSNs, etc. in metadata.
        
        Args:
            metadata: Dictionary containing metadata to analyze
            
        Returns:
            List of MetadataFinding objects representing pattern matches
        """
        findings = []
        
        # Flatten metadata for easier searching
        flat_metadata = self._flatten_dict(metadata)
        
        # Search for patterns defined in PRIVACY_CONCERNS
        privacy_findings = self._search_privacy_patterns(flat_metadata)
        findings.extend(privacy_findings)
        
        # Search for domain names
        domain_findings = self._search_domain_names(flat_metadata)
        findings.extend(domain_findings)
        
        # Search for IP addresses
        ip_findings = self._search_ip_addresses(flat_metadata)
        findings.extend(ip_findings)
        
        # Search for credit card numbers
        cc_findings = self._search_credit_cards(flat_metadata)
        findings.extend(cc_findings)
        
        # Search for API keys and tokens
        api_findings = self._search_api_keys(flat_metadata)
        findings.extend(api_findings)
        
        # Search for URLs
        url_findings = self._search_urls(flat_metadata)
        findings.extend(url_findings)
        
        return findings
    
    def _flatten_dict(self, d: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, str]:
        """
        Flatten a nested dictionary into a single level dictionary.
        
        Args:
            d: Dictionary to flatten
            parent_key: Key of parent dictionary (for recursion)
            sep: Separator to use between keys
            
        Returns:
            Flattened dictionary with keys joined by separator
        """
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            elif isinstance(v, (list, tuple)):
                # Handle lists by joining elements with a comma
                if all(isinstance(x, (str, int, float, bool)) for x in v):
                    items.append((new_key, ', '.join(str(x) for x in v)))
                else:
                    # If list contains complex items, process each item
                    for i, item in enumerate(v):
                        if isinstance(item, dict):
                            items.extend(self._flatten_dict(item, f"{new_key}{sep}{i}", sep=sep).items())
                        else:
                            items.append((f"{new_key}{sep}{i}", str(item)))
            elif isinstance(v, (str, int, float, bool)) or v is None:
                items.append((new_key, str(v) if v is not None else ''))
            else:
                # For other types, just convert to string
                items.append((new_key, str(v)))
                
        return dict(items)
    
    def _search_privacy_patterns(self, flat_metadata: Dict[str, str]) -> List[MetadataFinding]:
        """
        Search for patterns defined in PRIVACY_CONCERNS.
        
        Args:
            flat_metadata: Flattened metadata dictionary
            
        Returns:
            List of MetadataFinding objects
        """
        findings = []
        
        for pattern_name, pattern in PRIVACY_CONCERNS.items():
            matches = set()
            for key, value in flat_metadata.items():
                if isinstance(value, str):
                    found = pattern.findall(value)
                    for match in found:
                        if isinstance(match, tuple):  # Some regex patterns return tuples
                            match = match[0]
                        matches.add(match)
            
            if matches:
                severity = "high" if pattern_name in ('email', 'ssn') else "medium"
                findings.append(MetadataFinding(
                    type="privacy",
                    description=f"Found {pattern_name} in metadata",
                    severity=severity,
                    data={"matches": list(matches), "pattern": pattern_name}
                ))
        
        return findings
    
    def _search_domain_names(self, flat_metadata: Dict[str, str]) -> List[MetadataFinding]:
        """
        Search for domain names in metadata.
        
        Args:
            flat_metadata: Flattened metadata dictionary
            
        Returns:
            List of MetadataFinding objects
        """
        findings = []
        
        # Pattern for domain names
        domain_pattern = re.compile(r'(?<!\w)(?:https?://)?(?:www\.)?([a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z0-9]{2,}(?:\.[a-zA-Z0-9]{2,})*)(?!\w)')
        
        matches = set()
        for key, value in flat_metadata.items():
            if isinstance(value, str):
                found = domain_pattern.findall(value)
                matches.update(found)
        
        # Exclude common domains that aren't privacy concerns
        common_domains = {'google.com', 'microsoft.com', 'apple.com', 'adobe.com', 
                         'amazon.com', 'facebook.com', 'twitter.com', 'github.com'}
        filtered_matches = [m for m in matches if m.lower() not in common_domains]
        
        if filtered_matches:
            findings.append(MetadataFinding(
                type="information",
                description=f"Found {len(filtered_matches)} domain names in metadata",
                severity="low",
                data={"domains": filtered_matches}
            ))
        
        return findings
    
    def _search_ip_addresses(self, flat_metadata: Dict[str, str]) -> List[MetadataFinding]:
        """
        Search for IP addresses in metadata.
        
        Args:
            flat_metadata: Flattened metadata dictionary
            
        Returns:
            List of MetadataFinding objects
        """
        findings = []
        
        # Pattern for IPv4 addresses
        ipv4_pattern = re.compile(r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
        
        # Pattern for IPv6 addresses (simplified)
        ipv6_pattern = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b')
        
        ipv4_matches = set()
        ipv6_matches = set()
        
        for key, value in flat_metadata.items():
            if isinstance(value, str):
                ipv4_found = ipv4_pattern.findall(value)
                ipv6_found = ipv6_pattern.findall(value)
                ipv4_matches.update(ipv4_found)
                ipv6_matches.update(ipv6_found)
        
        # Exclude local and private IP ranges
        filtered_ipv4 = []
        for ip in ipv4_matches:
            # Exclude 127.0.0.1, 10.x.x.x, 192.168.x.x, 172.16-31.x.x
            octets = [int(o) for o in ip.split('.')]
            if octets[0] == 127 or octets[0] == 10 or \
               (octets[0] == 192 and octets[1] == 168) or \
               (octets[0] == 172 and 16 <= octets[1] <= 31):
                continue
            filtered_ipv4.append(ip)
        
        all_ips = filtered_ipv4 + list(ipv6_matches)
        if all_ips:
            findings.append(MetadataFinding(
                type="privacy",
                description=f"Found {len(all_ips)} IP addresses in metadata",
                severity="medium",
                data={"ip_addresses": all_ips}
            ))
        
        return findings
    
    def _search_credit_cards(self, flat_metadata: Dict[str, str]) -> List[MetadataFinding]:
        """
        Search for credit card numbers in metadata.
        
        Args:
            flat_metadata: Flattened metadata dictionary
            
        Returns:
            List of MetadataFinding objects
        """
        findings = []
        
        # Pattern for credit card numbers
        cc_pattern = re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b')
        
        matches = set()
        for key, value in flat_metadata.items():
            if isinstance(value, str):
                found = cc_pattern.findall(value)
                matches.update(found)
        
        if matches:
            findings.append(MetadataFinding(
                type="privacy",
                description=f"Found {len(matches)} potential credit card numbers in metadata",
                severity="high",
                data={"credit_cards": ["XXXX-XXXX-XXXX-" + cc[-4:] for cc in matches]}  # Mask all but last 4 digits
            ))
        
        return findings
    
    def _search_api_keys(self, flat_metadata: Dict[str, str]) -> List[MetadataFinding]:
        """
        Search for potential API keys and tokens in metadata.
        
        Args:
            flat_metadata: Flattened metadata dictionary
            
        Returns:
            List of MetadataFinding objects
        """
        findings = []
        
        # Pattern for potential API keys
        api_key_pattern = re.compile(r'\b([a-zA-Z0-9]{20,40})\b')
        
        # Terms that suggest a value might be an API key or token
        key_terms = ['key', 'token', 'api', 'secret', 'password', 'auth', 'credential']
        
        matches = []
        for key, value in flat_metadata.items():
            if isinstance(value, str) and any(term in key.lower() for term in key_terms):
                found = api_key_pattern.findall(value)
                for match in found:
                    matches.append((key, match))
        
        if matches:
            findings.append(MetadataFinding(
                type="security",
                description=f"Found {len(matches)} potential API keys or tokens in metadata",
                severity="high",
                data={"api_keys": [f"{key}: {value[:3]}...{value[-3:]}" for key, value in matches]}  # Mask most of the key
            ))
        
        return findings
    
    def _search_urls(self, flat_metadata: Dict[str, str]) -> List[MetadataFinding]:
        """
        Search for URLs in metadata.
        
        Args:
            flat_metadata: Flattened metadata dictionary
            
        Returns:
            List of MetadataFinding objects
        """
        findings = []
        
        # Pattern for URLs
        url_pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s,.)]*')
        
        matches = set()
        for key, value in flat_metadata.items():
            if isinstance(value, str):
                found = url_pattern.findall(value)
                matches.update(found)
        
        if matches:
            findings.append(MetadataFinding(
                type="information",
                description=f"Found {len(matches)} URLs in metadata",
                severity="low",
                data={"urls": list(matches)}
            ))
        
        return findings