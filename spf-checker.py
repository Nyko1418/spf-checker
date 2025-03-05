#!/usr/bin/env python3

import argparse  # Helps us handle command-line arguments like --detail or --ipv6
import json  # For exporting results to JSON files
import csv  # For exporting results to CSV files
from typing import Dict, List, Optional, Tuple  # Type hints make the code clearer for what we expect
import dns.resolver  # Library to look up DNS records, like SPF in TXT records
import dns.exception  # Handles errors when DNS lookups fail
from tabulate import tabulate  # Makes pretty tables for our output
import logging  # Lets us print debug messages to understand what’s happening
from datetime import datetime  # Not used here, but included for potential future timestamping
import re  # Regular expressions to check for patterns like "spf-12345678.pphosted.com"


class SPFValidator:
    # This class does all the heavy lifting: fetching, validating, and counting IPs in SPF records
    def __init__(self, domain: str, include_ipv6: bool = False, debug: bool = False):
        # Constructor sets up our object with the domain we’re checking and some options
        self.domain = domain.lower()  # Convert domain to lowercase
        self.include_ipv6 = include_ipv6  # Should we count IPv6 addresses? Default is no
        self.debug = debug  # Should we print extra info for debugging? Default is no
        self.ip_counts: Dict[str, Dict[str, int]] = {}  # Stores IP counts for each mechanism (e.g., "mx": {"ipv4": 4})
        self.includes_seen: List[str] = []  # Tracks domains we’ve seen in "include:" to avoid loops
        self.top_level_mechanisms: List[str] = []  # Keeps the main parts of the SPF record we’re checking
        self.dmarc_policy: Optional[str] = None
        self.dmarc_record: Optional[str] = None
        self.max_includes = 10  # RFC 7208 says no more than 10 includes to prevent abuse
        self.setup_logging()  # Set up our debug logging system

    def setup_logging(self):
        # This sets up a way to print messages to help us debug or see what’s happening
        logging.basicConfig(
            level=logging.DEBUG if self.debug else logging.INFO,  # Debug mode shows more, info mode is quieter
            format='%(asctime)s - %(levelname)s - %(message)s'  # Timestamp + message type + message
        )
        self.logger = logging.getLogger(__name__)  # Our logger to write messages

    def fetch_spf_record(self) -> Optional[str]:
        # Looks up the SPF record (a TXT record starting with "v=spf1") for the domain
        try:
            answers = dns.resolver.resolve(self.domain, 'TXT')  # Ask DNS for TXT records
            for rdata in answers:
                # DNS might return bytes or strings, so we handle both
                if isinstance(rdata.strings, (list, tuple)):
                    txt = ''.join(
                        s.decode('utf-8') if isinstance(s, bytes) else s 
                        for s in rdata.strings 
                    )  # Combine all parts into one string
                else:
                    txt = rdata.strings.decode('utf-8') if isinstance(rdata.strings, bytes) else rdata.strings
                if txt.startswith('v=spf1'):  # Is this an SPF record?
                    self.logger.debug(f"Found SPF record: {txt}")  # Yay, log it!
                    return txt  # Return the SPF record we found
            self.logger.warning("No SPF record found.")  # Oops, nothing here
            return None
        except dns.exception.DNSException as e:
            self.logger.error(f"DNS query failed: {e}")  # Something went wrong with DNS
            return None

    def fetch_dmarc_record(self) -> Optional[str]:
        # Looks up the DMARC record for the domain
        try:
            dmarc_domain = f"_dmarc.{self.domain}"
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                txt = ''.join(s.decode('utf-8') if isinstance(s, bytes) else s for s in rdata.strings)
                if txt.startswith('v=DMARC1'):
                    for tag in txt.split(';'):
                        tag = tag.strip()
                        if tag.startswith('p='):
                            policy = tag.split('=')[1].lower()
                            if policy in ('none', 'quarantine', 'reject'):
                                self.dmarc_policy = policy
                    self.logger.debug(f"Found DMARC record: {txt}")
                    return txt
            return None
        except dns.exception.DNSException as e:
            self.logger.debug(f"DMARC DNS query failed: {e}")
            return None
    def count_ips(self, mechanism: str) -> Tuple[int, int]:
        # Counts how many IPv4 and IPv6 addresses a mechanism (like "ip4:1.2.3.4/24") covers
        try:
            if mechanism.startswith('ip4:'):  # IPv4 address or range?
                ip_part = mechanism[4:]  # Remove "ip4:" to get "1.2.3.4/24" or "1.2.3.4"
                if '/' in ip_part:  # Is it a range like "1.2.3.4/24"?
                    ip, prefix = ip_part.split('/')  # Split into IP and prefix (e.g., "24")
                    prefix = int(prefix)  # Convert "24" to number 24
                    if 0 <= prefix <= 32:  # Valid range for IPv4?
                        # 2^(32 - prefix) gives us the number of IPs (e.g., /24 = 256 IPs)
                        return 2 ** (32 - prefix), 0
                    else:
                        self.logger.error(f"Invalid IPv4 prefix: {prefix}")
                        return 0, 0
                else:  # Just one IP, like "1.2.3.4"
                    return 1, 0
            elif mechanism.startswith('ip6:') and self.include_ipv6:  # IPv6, but only if we want it
                ip_part = mechanism[4:]
                if '/' in ip_part:
                    ip, prefix = ip_part.split('/')
                    prefix = int(prefix)
                    if 0 <= prefix <= 128:  # IPv6 goes up to 128 bits
                        return 0, 2 ** (128 - prefix)
                    else:
                        self.logger.error(f"Invalid IPv6 prefix: {prefix}")
                        return 0, 0
                else:
                    return 0, 1
            elif mechanism.startswith('include:'):  # Another SPF record to check?
                domain = mechanism.split(':', 1)[1]  # Get the domain after "include:"
                return self.process_include(domain)  # Dive into that SPF record
            elif mechanism in ('a', 'mx'):  # "a" or "mx" records?
                return self.resolve_a_or_mx(mechanism)  # Count IPs from those
        except Exception as e:
            self.logger.error(f"Error processing mechanism {mechanism}: {e}")
        return 0, 0  # If something goes wrong, count nothing

    def resolve_a_or_mx(self, mechanism: str) -> Tuple[int, int]:
        # Counts IPs from "a" (domain’s IP) or "mx" (mail server IPs)
        ipv4_count, ipv6_count = 0, 0
        try:
            if mechanism == 'a':
                answers = dns.resolver.resolve(self.domain, 'A')  # Get IPv4 addresses
                ipv4_count = len(answers)
                if self.include_ipv6:
                    answers = dns.resolver.resolve(self.domain, 'AAAA')  # Get IPv6 too
                    ipv6_count = len(answers)
            elif mechanism == 'mx':
                answers = dns.resolver.resolve(self.domain, 'MX')  # Get mail servers
                for mx in answers:
                    hostname = str(mx.exchange)  # Each mail server’s name
                    ipv4_count += len(dns.resolver.resolve(hostname, 'A'))
                    if self.include_ipv6:
                        ipv6_count += len(dns.resolver.resolve(hostname, 'AAAA'))
        except dns.exception.DNSException as e:
            self.logger.debug(f"Resolution failed for {mechanism}: {e}")
        return ipv4_count, ipv6_count

    def process_include(self, include_domain: str) -> Tuple[int, int]:
        # Handles "include:" by fetching and counting IPs from another SPF record
        if include_domain in self.includes_seen:  # Already seen this domain?
            self.logger.debug(f"Skipping duplicate include: {include_domain}")
            return 0, 0  # Don’t count it again
        if len(self.includes_seen) >= self.max_includes:  # Too many includes?
            self.logger.error("Exceeded maximum include lookups (RFC 7208 limit)")
            raise ValueError("Too many includes")  # Stop to follow the rules

        self.includes_seen.append(include_domain)  # Mark this domain as seen
        validator = SPFValidator(include_domain, self.include_ipv6, self.debug)  # New checker for this domain
        spf_record = validator.fetch_spf_record()
        if not spf_record or not spf_record.startswith('v=spf1'):
            self.logger.debug(f"No valid SPF record for {include_domain}")
            return 0, 0

        total_ipv4, total_ipv6 = 0, 0
        for part in spf_record.split()[1:]:  # Skip "v=spf1", check the rest
            if part in ('all', '+all', '-all', '~all', '?all'):  # These don’t count IPs
                continue
            ipv4, ipv6 = self.count_ips(part)  # Count IPs for this part
            total_ipv4 += ipv4
            total_ipv6 += ipv6
            if part not in self.ip_counts:  # Store new counts
                self.ip_counts[part] = {"ipv4": ipv4, "ipv6": ipv6}
        
        self.ip_counts[include_domain] = {"ipv4": total_ipv4, "ipv6": total_ipv6}  # Total for this include
        return total_ipv4, total_ipv6

    def validate(self) -> Dict:
        # Main function: validates the SPF record and counts all IPs
        spf_record = self.fetch_spf_record()
        if not spf_record:  # No record?
            self.dmarc_record = self.fetch_dmarc_record()
            return {"valid": False, "error": "No SPF record found", "ip_counts": {}, "total_ipv4": 0, "total_ipv6": 0, "spf_record": None, "has_pphosted_include": False, "includes_used": 0, "includes_percentage": 0}

        parts = spf_record.split()  # Split into pieces like "v=spf1", "mx", etc.
        if parts[0] != "v=spf1":  # Must start with "v=spf1" to be valid
            return {"valid": False, "error": "Invalid SPF version", "ip_counts": {}, "total_ipv4": 0, "total_ipv6": 0, "spf_record": spf_record, "has_pphosted_include": False, "includes_used": 0, "includes_percentage": 0}

        # Check if there’s a special "pphosted" include like "spf-12345678.pphosted.com"
        pphosted_pattern = re.compile(r'include:spf-\d{8}\.pphosted\.com')  # Looks for 8 digits
        has_pphosted_include = bool(pphosted_pattern.search(spf_record))  # True if found
        self.dmarc_record = self.fetch_dmarc_record()

        total_ipv4, total_ipv6 = 0, 0
        # Save the main parts we’re checking (not "all" stuff)
        self.top_level_mechanisms = [part for part in parts[1:] if part not in ('all', '+all', '-all', '~all', '?all')]
        for part in self.top_level_mechanisms:
            ipv4, ipv6 = self.count_ips(part)  # Count IPs for each part
            total_ipv4 += ipv4
            total_ipv6 += ipv6
            if part not in self.ip_counts:  # Only add if not already counted
                self.ip_counts[part] = {"ipv4": ipv4, "ipv6": ipv6}

        # Calculate include usage percentage
        includes_used = len(self.includes_seen)
        includes_percentage = (includes_used / self.max_includes) * 100

        # Return everything we learned
        return {
            "valid": includes_used <= self.max_includes,  # Valid if under 10 includes
            "error": None,
            "ip_counts": self.ip_counts,
            "total_ipv4": total_ipv4,
            "total_ipv6": total_ipv6,
            "spf_record": spf_record,
            "has_pphosted_include": has_pphosted_include,
            "includes_used": includes_used,
            "includes_percentage": includes_percentage
        }

def display_results(result: Dict, detail: bool, validator: SPFValidator):
    # Shows the results in a nice, readable way with colors and tables
    GREEN = '\033[32m'  # Green text for good stuff
    RED = '\033[31m'  # Red text for warnings or bad stuff    
    RESET = '\033[0m'  # Back to normal text
    
    # Show the SPF record first so users know what we’re working with
    print("\nSPF Record:")
    if result['spf_record']:        
        print(f"{result['spf_record']}\n")
    else:        
        print(f"Not found\n")
    print("DMARC Record:")
    if validator.dmarc_record:        
        print(f"{validator.dmarc_record}\n")
        if validator.dmarc_policy == 'reject':
            dmarc_color = GREEN
        elif validator.dmarc_policy == 'quarantine':
            dmarc_color = '\033[33m'  # Yellow
        else:
            dmarc_color = RED
        if validator.dmarc_policy:
            print(f"DMARC Policy: {dmarc_color}{validator.dmarc_policy}{RESET}\n")
        else:
            print(f"DMARC Policy: {dmarc_color}none{RESET}\n")
    else:
        print(f"Not found\n")
        print(f"DMARC Policy: {RED}no entry{RESET}\n")

    # Tell the user if there’s a pphosted include
    if result['has_pphosted_include']:
        print(f"{GREEN}SPF record contains a pphosted SPF include{RESET}")
    else:
        print(f"{RED}SPF record does not contain a pphosted SPF include{RESET}")

    print(f"SPF Validation Result for {args.domain}:")
    valid_text = f"{GREEN}True{RESET}" if result['valid'] else f"{RED}False{RESET}"
    print(f"Valid: {valid_text}")  # Green for valid, red for invalid
    if result['error']:
        print(f"Error: {result['error']}")
    print(f"Total IPv4 Addresses: {result['total_ipv4']:,}")  # Commas make big numbers easy to read
    if args.ipv6:
        print(f"Total IPv6 Addresses: {result['total_ipv6']:,}")
    
    # Show include lookup usage information
    includes_used = result['includes_used']
    includes_percentage = result['includes_percentage']
    
    # Color code based on percentage (green < 70%, yellow < 90%, red >= 90%)
    if includes_percentage < 70:
        color = GREEN
    elif includes_percentage < 90:
        color = '\033[33m'  # Yellow
    else:
        color = RED
        
    print(f"SPF Include Lookups: {includes_used}/{validator.max_includes} ({color}{includes_percentage:.1f}%{RESET})")

    # If they want details, show a table of the main parts
    if detail and result['ip_counts']:
        table = []
        for mechanism in validator.top_level_mechanisms:
            counts = result['ip_counts'].get(mechanism, {"ipv4": 0, "ipv6": 0})
            ipv4 = counts.get('ipv4', 0)
            if args.ipv6:  # Show IPv6 if they asked for it
                ipv6 = counts.get('ipv6', 0)
                table.append([mechanism, f"{ipv4:,}", f"{ipv6:,}"])
            else:
                table.append([mechanism, f"{ipv4:,}"])
        headers = ['Mechanism', 'IPv4 Count', 'IPv6 Count'] if args.ipv6 else ['Mechanism', 'IPv4 Count']
        print("\nDetailed IP Counts:")
        print(tabulate(table, headers=headers, tablefmt='grid'))  # Pretty table!

def export_results(result: Dict, filename: str, format: str):
    # Saves the results to a file if the user wants
    data = {
        "domain": args.domain,
        "valid": result['valid'],
        "error": result['error'],
        "total_ipv4": result['total_ipv4'],
        "total_ipv6": result['total_ipv6'] if args.ipv6 else None,
        "ip_counts": result['ip_counts'],
        "spf_record": result['spf_record'],
        "has_pphosted_include": result['has_pphosted_include'],
        "includes_used": result['includes_used'],
        "includes_percentage": result['includes_percentage']
    }
    if format == 'json':  # JSON is like a structured text file
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)  # Nice formatting with indent
    elif format == 'csv':  # CSV is like a spreadsheet
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Mechanism', 'IPv4 Count', 'IPv6 Count'] if args.ipv6 else ['Mechanism', 'IPv4 Count'])
            for mech in validator.top_level_mechanisms:
                counts = result['ip_counts'].get(mech, {"ipv4": 0, "ipv6": 0})
                ipv4 = counts.get('ipv4', 0)
                ipv6 = counts.get('ipv6', 0) if args.ipv6 else '-'
                writer.writerow([mech, ipv4, ipv6])

if __name__ == "__main__":
    # This runs when you start the script from the command line
    parser = argparse.ArgumentParser(
        description="SPF Record Checker & Validator compliant with RFC 7208.",
        epilog="Example: python spf_checker.py example.com --detail --ipv6"
    )  # Sets up how users can give us options
    parser.add_argument("domain", help="Domain to check SPF record for")  # Must give a domain
    parser.add_argument("--detail", action="store_true", help="Show detailed IP counts for top-level mechanisms")
    parser.add_argument("--ipv6", action="store_true", help="Include IPv6 address counts")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--export", metavar="FILE", help="Export results to FILE (json or csv based on extension)")
    
    args = parser.parse_args()  # Read what the user typed
    
    validator = SPFValidator(args.domain, args.ipv6, args.debug)  # Create our checker
    result = validator.validate()  # Do the work
    
    display_results(result, args.detail, validator)  # Show the results
    
    if args.export:  # Save to a file if they asked
        format = 'json' if args.export.endswith('.json') else 'csv'
        export_results(result, args.export, format)
        print(f"\nResults exported to {args.export}")
