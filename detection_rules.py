#!/usr/bin/env python3
"""
Phishing Detection Rules Module

This module implements heuristic-based rules for detecting phishing emails
based on features extracted from email headers.
"""

import re
from typing import Dict, List, Optional, Union, Tuple, Any
import logging

logger = logging.getLogger(__name__)

# Define rule weights for scoring
RULE_WEIGHTS = {
    # Sender-related rules
    "from_reply_to_mismatch": 25,
    "from_return_path_mismatch": 20,
    "free_provider_business_context": 15,
    "display_name_contains_email": 10,
    "missing_sender_domain": 20,
    "domain_no_mx": 15,
    "domain_no_spf": 10,
    "domain_no_dmarc": 10,
    
    # Recipient-related rules
    "undisclosed_recipients": 15,
    "bcc_only": 20,
    "excessive_recipients": 10,
    
    # Subject-related rules
    "subject_urgent": 15,
    "subject_account": 15,
    "subject_financial": 15,
    "subject_prize": 20,
    "subject_excessive_punctuation": 10,
    "subject_all_caps": 15,
    
    # Date-related rules
    "future_date": 25,
    "very_old_date": 15,
    "time_discrepancies": 20,
    
    # Received chain rules
    "unusual_chain_length": 15,
    "inconsistent_routing": 25,
    "suspicious_ips": 20,
    "missing_hops": 15,
    
    # Authentication rules
    "spf_fail": 25,
    "missing_dkim": 15,
    "dmarc_fail": 20,
    
    # Message-ID rules
    "missing_message_id": 15,
    "malformed_message_id": 20,
    "message_id_domain_mismatch": 20,
    
    # Content rules
    "unusual_encoding": 15
}


class PhishingDetector:
    """Class for detecting phishing emails using heuristic rules."""
    
    def __init__(self, threshold: float = 50.0, verbose: bool = False):
        """
        Initialize the PhishingDetector with a threshold score.
        
        Args:
            threshold: Score threshold for classifying an email as phishing (0-100)
            verbose: Whether to include detailed analysis in results
        """
        self.threshold = threshold
        self.verbose = verbose
        self.rules_triggered = []
        self.header_analysis = {}
    
    def analyze(self, features: Dict) -> Dict:
        """
        Analyze email features to detect phishing indicators.
        
        Args:
            features: Dictionary containing extracted email features
            
        Returns:
            Dictionary containing analysis results
        """
        # Reset state for new analysis
        self.rules_triggered = []
        self.header_analysis = {}
        
        # Apply all detection rules
        self._check_sender_rules(features)
        self._check_recipient_rules(features)
        self._check_subject_rules(features)
        self._check_date_rules(features)
        self._check_received_chain_rules(features)
        self._check_authentication_rules(features)
        self._check_message_id_rules(features)
        self._check_content_rules(features)
        
        # Calculate phishing probability score
        score = self._calculate_score()
        is_phishing = score >= self.threshold
        
        # Prepare result
        result = {
            "is_phishing": is_phishing,
            "phishing_probability": score,
            "indicators": self.rules_triggered,
        }
        
        # Include detailed header analysis if verbose
        if self.verbose:
            result["header_analysis"] = self.header_analysis
        
        return result
    
    def _check_sender_rules(self, features: Dict) -> None:
        """
        Check sender-related phishing indicators.
        
        Args:
            features: Dictionary containing extracted email features
        """
        sender = features.get("sender", {})
        
        # Check From and Reply-To mismatch
        if sender.get("email_mismatch"):
            self._add_indicator(
                "from_reply_to_mismatch",
                "From and Reply-To addresses don't match",
                f"From: {sender.get('from_email')} vs Reply-To: {sender.get('reply_to_email')}"
            )
            
            # Add to header analysis
            self._add_header_analysis("from", sender.get("from_email"), "safe")
            self._add_header_analysis(
                "reply-to", 
                sender.get("reply_to_email"), 
                "suspicious", 
                "Doesn't match From address"
            )
        
        # Check domain mismatch
        if sender.get("domain_mismatch"):
            self._add_indicator(
                "from_reply_to_mismatch",
                "From and Reply-To domains don't match",
                f"From domain: {sender.get('from_domain')} vs Reply-To domain: {sender.get('reply_to_domain')}"
            )
        
        # Check Return-Path mismatch
        return_path = sender.get("return_path_email")
        from_email = sender.get("from_email")
        
        if return_path and from_email and return_path != from_email:
            self._add_indicator(
                "from_return_path_mismatch",
                "From and Return-Path addresses don't match",
                f"From: {from_email} vs Return-Path: {return_path}"
            )
            
            # Add to header analysis
            self._add_header_analysis(
                "return-path", 
                return_path, 
                "suspicious", 
                "Doesn't match From address"
            )
        
        # Check for free email provider in business context
        if sender.get("is_free_provider"):
            # This is a weak signal, so we'll only flag it if it looks like a business email
            from_name = sender.get("from_name", "")
            if from_name and ("inc" in from_name.lower() or 
                             "corp" in from_name.lower() or 
                             "ltd" in from_name.lower() or 
                             "company" in from_name.lower() or
                             "enterprise" in from_name.lower()):
                self._add_indicator(
                    "free_provider_business_context",
                    "Business sender using free email provider",
                    f"Sender '{from_name}' using {sender.get('from_domain')}"
                )
                
                # Add to header analysis
                self._add_header_analysis(
                    "from", 
                    sender.get("from_email"), 
                    "suspicious", 
                    "Business sender using free email provider"
                )
        
        # Check for display name containing email
        if sender.get("display_name_contains_email"):
            self._add_indicator(
                "display_name_contains_email",
                "Display name contains an email address",
                f"Display name: {sender.get('from_name')}"
            )
            
            # Add to header analysis
            self._add_header_analysis(
                "from", 
                f"{sender.get('from_name')} <{sender.get('from_email')}>", 
                "suspicious", 
                "Display name contains an email address"
            )
        
        # Check for missing sender domain
        if not sender.get("from_domain"):
            self._add_indicator(
                "missing_sender_domain",
                "Sender email has no domain",
                f"From: {sender.get('from_email')}"
            )
            
            # Add to header analysis
            self._add_header_analysis(
                "from", 
                sender.get("from_email"), 
                "suspicious", 
                "Sender email has no domain"
            )
        
        # Check for domain without MX records
        if sender.get("from_domain") and "domain_has_mx" in sender and not sender.get("domain_has_mx"):
            self._add_indicator(
                "domain_no_mx",
                "Sender domain has no MX records",
                f"Domain: {sender.get('from_domain')}"
            )
            
            # Add to header analysis
            self._add_header_analysis(
                "from", 
                sender.get("from_email"), 
                "suspicious", 
                "Sender domain has no MX records"
            )
        
        # Check for domain without SPF
        if sender.get("from_domain") and "domain_has_spf" in sender and not sender.get("domain_has_spf"):
            self._add_indicator(
                "domain_no_spf",
                "Sender domain has no SPF records",
                f"Domain: {sender.get('from_domain')}"
            )
        
        # Check for domain without DMARC
        if sender.get("from_domain") and "domain_has_dmarc" in sender and not sender.get("domain_has_dmarc"):
            self._add_indicator(
                "domain_no_dmarc",
                "Sender domain has no DMARC records",
                f"Domain: {sender.get('from_domain')}"
            )
    
    def _check_recipient_rules(self, features: Dict) -> None:
        """
        Check recipient-related phishing indicators.
        
        Args:
            features: Dictionary containing extracted email features
        """
        recipient = features.get("recipient", {})
        
        # Check for undisclosed recipients
        if recipient.get("has_undisclosed_recipients"):
            self._add_indicator(
                "undisclosed_recipients",
                "Email sent to undisclosed recipients",
                "The To field contains 'undisclosed recipients'"
            )
            
            # Add to header analysis
            self._add_header_analysis(
                "to", 
                "undisclosed recipients", 
                "suspicious", 
                "Email sent to undisclosed recipients"
            )
        
        # Check for BCC only
        if recipient.get("has_bcc_only"):
            self._add_indicator(
                "bcc_only",
                "Email sent using BCC only",
                "No visible recipients in To or CC fields"
            )
            
            # Add to header analysis
            self._add_header_analysis(
                "to", 
                "(empty)", 
                "suspicious", 
                "Email sent using BCC only"
            )
        
        # Check for excessive recipients
        total_recipients = recipient.get("total_recipients", 0)
        if total_recipients > 15:  # Arbitrary threshold
            self._add_indicator(
                "excessive_recipients",
                "Email sent to an unusually large number of recipients",
                f"Total recipients: {total_recipients}"
            )
            
            # Add to header analysis
            self._add_header_analysis(
                "to/cc", 
                f"{total_recipients} recipients", 
                "suspicious", 
                "Unusually large number of recipients"
            )
    
    def _check_subject_rules(self, features: Dict) -> None:
        """
        Check subject-related phishing indicators.
        
        Args:
            features: Dictionary containing extracted email features
        """
        subject = features.get("subject", {})
        subject_text = subject.get("text", "")
        
        # Check for urgent language
        if subject.get("contains_urgent"):
            self._add_indicator(
                "subject_urgent",
                "Subject contains urgent language",
                f"Subject: {subject_text}"
            )
            
            # Add to header analysis
            self._add_header_analysis(
                "subject", 
                subject_text, 
                "suspicious", 
                "Contains urgent language"
            )
        
        # Check for account-related language
        if subject.get("contains_account"):
            self._add_indicator(
                "subject_account",
                "Subject contains account-related language",
                f"Subject: {subject_text}"
            )
            
            # Add to header analysis if not already added
            if "subject" not in self.header_analysis:
                self._add_header_analysis(
                    "subject", 
                    subject_text, 
                    "suspicious", 
                    "Contains account-related language"
                )
        
        # Check for financial language
        if subject.get("contains_financial"):
            self._add_indicator(
                "subject_financial",
                "Subject contains financial language",
                f"Subject: {subject_text}"
            )
            
            # Add to header analysis if not already added
            if "subject" not in self.header_analysis:
                self._add_header_analysis(
                    "subject", 
                    subject_text, 
                    "suspicious", 
                    "Contains financial language"
                )
        
        # Check for prize-related language
        if subject.get("contains_prize"):
            self._add_indicator(
                "subject_prize",
                "Subject contains prize-related language",
                f"Subject: {subject_text}"
            )
            
            # Add to header analysis if not already added
            if "subject" not in self.header_analysis:
                self._add_header_analysis(
                    "subject", 
                    subject_text, 
                    "suspicious", 
                    "Contains prize-related language"
                )
        
        # Check for excessive punctuation
        if subject.get("excessive_punctuation"):
            self._add_indicator(
                "subject_excessive_punctuation",
                "Subject contains excessive punctuation",
                f"Subject: {subject_text}"
            )
            
            # Add to header analysis if not already added
            if "subject" not in self.header_analysis:
                self._add_header_analysis(
                    "subject", 
                    subject_text, 
                    "suspicious", 
                    "Contains excessive punctuation"
                )
        
        # Check for all caps
        if subject.get("all_caps"):
            self._add_indicator(
                "subject_all_caps",
                "Subject is in all capital letters",
                f"Subject: {subject_text}"
            )
            
            # Add to header analysis if not already added
            if "subject" not in self.header_analysis:
                self._add_header_analysis(
                    "subject", 
                    subject_text, 
                    "suspicious", 
                    "Written in all capital letters"
                )
    
    def _check_date_rules(self, features: Dict) -> None:
        """
        Check date-related phishing indicators.
        
        Args:
            features: Dictionary containing extracted email features
        """
        date = features.get("date", {})
        
        # Check for future date
        if date.get("future_date"):
            self._add_indicator(
                "future_date",
                "Email has a future date",
                f"Date: {date.get('header_date')}"
            )
            
            # Add to header analysis
            self._add_header_analysis(
                "date", 
                date.get("header_date"), 
                "suspicious", 
                "Email has a future date"
            )
        
        # Check for very old date
        if date.get("old_date"):
            self._add_indicator(
                "very_old_date",
                "Email has a very old date",
                f"Date: {date.get('header_date')}"
            )
            
            # Add to header analysis
            self._add_header_analysis(
                "date", 
                date.get("header_date"), 
                "suspicious", 
                "Email has a very old date"
            )
        
        # Check for time discrepancies
        if date.get("time_discrepancies"):
            self._add_indicator(
                "time_discrepancies",
                "Time discrepancies in email headers",
                "Inconsistent timestamps in Received headers"
            )
            
            # Add to header analysis
            self._add_header_analysis(
                "received", 
                "Multiple headers", 
                "suspicious", 
                "Time discrepancies between Received headers"
            )
    
    def _check_received_chain_rules(self, features: Dict) -> None:
        """
        Check received chain-related phishing indicators.
        
        Args:
            features: Dictionary containing extracted email features
        """
        chain = features.get("received_chain", {})
        
        # Check for unusual chain length
        if chain.get("unusual_chain_length"):
            count = chain.get("received_count", 0)
            reason = "Too many hops" if count > 10 else "Too few hops"
            
            self._add_indicator(
                "unusual_chain_length",
                f"Unusual number of mail servers in delivery path",
                f"{reason} ({count} servers)"
            )
            
            # Add to header analysis
            self._add_header_analysis(
                "received", 
                f"{count} headers", 
                "suspicious", 
                f"Unusual number of mail servers in delivery path"
            )
        
        # Check for inconsistent routing
        if chain.get("inconsistent_routing"):
            self._add_indicator(
                "inconsistent_routing",
                "Inconsistent mail routing detected",
                "Mail server chain has unexpected routing patterns"
            )
            
            # Add to header analysis
            self._add_header_analysis(
                "received", 
                "Multiple headers", 
                "suspicious", 
                "Inconsistent mail routing detected"
            )
        
        # Check for suspicious IPs
        suspicious_ips = chain.get("suspicious_ips", [])
        if suspicious_ips:
            self._add_indicator(
                "suspicious_ips",
                "Suspicious IP addresses in mail routing",
                f"Suspicious IPs: {', '.join(suspicious_ips)}"
            )
            
            # Add to header analysis
            self._add_header_analysis(
                "received", 
                f"Contains IPs: {', '.join(suspicious_ips)}", 
                "suspicious", 
                "Suspicious IP addresses in mail routing"
            )
        
        # Check for missing hops
        if chain.get("missing_hops"):
            self._add_indicator(
                "missing_hops",
                "Missing hops in mail routing chain",
                "Unexpected gaps in the mail server chain"
            )
            
            # Add to header analysis
            self._add_header_analysis(
                "received", 
                "Multiple headers", 
                "suspicious", 
                "Missing hops in mail routing chain"
            )
    
    def _check_authentication_rules(self, features: Dict) -> None:
        """
        Check authentication-related phishing indicators.
        
        Args:
            features: Dictionary containing extracted email features
        """
        auth = features.get("authentication", {})
        
        # Check for SPF failure
        if auth.get("has_spf") and not auth.get("spf_pass"):
            self._add_indicator(
                "spf_fail",
                "SPF authentication failed",
                "Email failed Sender Policy Framework verification"
            )
            
            # Add to header analysis
            self._add_header_analysis(
                "received-spf", 
                "fail", 
                "suspicious", 
                "SPF authentication failed"
            )
        
        # Check for missing DKIM
        if not auth.get("has_dkim"):
            self._add_indicator(
                "missing_dkim",
                "No DKIM signature",
                "Email lacks DomainKeys Identified Mail signature"
            )
        
        # Check for DMARC failure
        if auth.get("has_dmarc") and not auth.get("dmarc_pass"):
            self._add_indicator(
                "dmarc_fail",
                "DMARC authentication failed",
                "Email failed Domain-based Message Authentication verification"
            )
            
            # Add to header analysis
            self._add_header_analysis(
                "authentication-results", 
                "dmarc=fail", 
                "suspicious", 
                "DMARC authentication failed"
            )
    
    def _check_message_id_rules(self, features: Dict) -> None:
        """
        Check Message-ID related phishing indicators.
        
        Args:
            features: Dictionary containing extracted email features
        """
        message_id = features.get("message_id", {})
        
        # Check for missing Message-ID
        if not message_id.get("has_message_id"):
            self._add_indicator(
                "missing_message_id",
                "Missing Message-ID header",
                "Email does not have a Message-ID header"
            )
            
            # Add to header analysis
            self._add_header_analysis(
                "message-id", 
                "(missing)", 
                "suspicious", 
                "Missing Message-ID header"
            )
        
        # Check for malformed Message-ID
        if message_id.get("malformed"):
            self._add_indicator(
                "malformed_message_id",
                "Malformed Message-ID header",
                f"Message-ID: {message_id.get('value')}"
            )
            
            # Add to header analysis
            self._add_header_analysis(
                "message-id", 
                message_id.get("value"), 
                "suspicious", 
                "Malformed Message-ID format"
            )
        
        # Check for domain mismatch
        if message_id.get("domain_mismatch"):
            self._add_indicator(
                "message_id_domain_mismatch",
                "Message-ID domain doesn't match sender",
                f"Message-ID domain: {message_id.get('domain')}"
            )
            
            # Add to header analysis
            self._add_header_analysis(
                "message-id", 
                message_id.get("value"), 
                "suspicious", 
                "Domain doesn't match sender domain"
            )
    
    def _check_content_rules(self, features: Dict) -> None:
        """
        Check content-related phishing indicators.
        
        Args:
            features: Dictionary containing extracted email features
        """
        content = features.get("content", {})
        
        # Check for unusual encoding
        if content.get("unusual_encoding"):
            self._add_indicator(
                "unusual_encoding",
                "Unusual content encoding",
                f"Encoding: {content.get('transfer_encoding')}"
            )
            
            # Add to header analysis
            self._add_header_analysis(
                "content-transfer-encoding", 
                content.get("transfer_encoding"), 
                "suspicious", 
                "Unusual content encoding"
            )
    
    def _add_indicator(self, rule_name: str, name: str, description: str) -> None:
        """
        Add a phishing indicator to the results.
        
        Args:
            rule_name: Internal rule identifier
            name: Human-readable indicator name
            description: Detailed description of the indicator
        """
        self.rules_triggered.append({
            "rule": rule_name,
            "name": name,
            "description": description,
            "weight": RULE_WEIGHTS.get(rule_name, 10)  # Default weight if not defined
        })
    
    def _add_header_analysis(self, header: str, value: str, status: str, reason: str = "") -> None:
        """
        Add header analysis information.
        
        Args:
            header: Header name
            value: Header value
            status: Analysis status ("safe", "suspicious", "neutral")
            reason: Reason for the status
        """
        self.header_analysis[header] = {
            "value": value,
            "status": status,
            "reason": reason
        }
    
    def _calculate_score(self) -> float:
        """
        Calculate the phishing probability score based on triggered rules.
        
        Returns:
            Score between 0 and 100
        """
        if not self.rules_triggered:
            return 0.0
        
        # Sum the weights of all triggered rules
        total_weight = sum(rule.get("weight", 10) for rule in self.rules_triggered)
        
        # Calculate score (cap at 100)
        score = min(total_weight, 100)
        
        return score


if __name__ == "__main__":
    # Simple test if run directly
    import sys
    import json
    from email_parser import EmailParser
    from feature_extractor import FeatureExtractor
    
    if len(sys.argv) > 1:
        parser = EmailParser(sys.argv[1])
        email_data = parser.parse()
        
        extractor = FeatureExtractor(email_data)
        features = extractor.extract_all_features()
        
        detector = PhishingDetector(verbose=True)
        result = detector.analyze(features)
        
        print(f"Phishing probability: {result['phishing_probability']}%")
        print(f"Verdict: {'POTENTIAL PHISHING' if result['is_phishing'] else 'LIKELY LEGITIMATE'}")
        
        if result["indicators"]:
            print("\nSuspicious indicators:")
            for indicator in result["indicators"]:
                print(f" - {indicator['name']}: {indicator['description']}")
    else:
        print("Please provide an email file path as argument")