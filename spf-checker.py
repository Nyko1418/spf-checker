#!/usr/bin/env python3

import argparse
import json
import csv
from typing import Dict, List, Optional, Tuple
import dns.resolver
import dns.exception
from tabulate import tabulate
import logging
from datetime import datetime
import re

class SPFValidator:
    def __init__(self, domain: str, include_ipv6: bool = False, debug: bool = False):
        self.domain = domain.lower()
        self.include_ipv6 = include_ipv6
        self.debug = debug
        self.ip_counts: Dict[str, Dict[str, int]] = {}
        self.includes_seen: List[str] = []
        self.top_level_mechanisms: List[str] = []
        self.dmarc_policy: Optional[str] = None
        self.dmarc_record: Optional[str] = None
        self.max_includes = 10
        self.setup_logging()

    def setup_logging(self):
        logging.basicConfig(
            level=logging.DEBUG if self.debug else logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

    def fetch_spf_record(self) -> Optional[str]:
        try:
            answers = dns.resolver.resolve(self.domain, 'TXT')
            for rdata in answers:
                if isinstance(rdata.strings, (list, tuple)):
                    txt = ''.join(s.decode('utf-8') if isinstance(s, bytes) else s for s in rdata.strings)
                else:
                    txt = rdata.strings.decode('utf-8') if isinstance(rdata.strings, bytes) else rdata.strings
                if txt.startswith('v=spf1'):
                    self.logger.debug(f"Found SPF record: {txt}")
                    return txt
            self.logger.warning("No SPF record found.")
            return None
        except dns.exception.DNSException as e:
            self.logger.error(f"DNS query failed: {e}")
            return None

    def fetch_dmarc_record(self) -> Optional[str]:
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
        try:
            if mechanism.startswith('ip4:'):
                ip_part = mechanism[4:]
                if '/' in ip_part:
                    ip, prefix = ip_part.split('/')
                    prefix = int(prefix)
                    if 0 <= prefix <= 32:
                        return 2 ** (32 - prefix), 0
                    else:
                        self.logger.error(f"Invalid IPv4 prefix: {prefix}")
                        return 0, 0
                else:
                    return 1, 0
            elif mechanism.startswith('ip6:') and self.include_ipv6:
                ip_part = mechanism[4:]
                if '/' in ip_part:
                    ip, prefix = ip_part.split('/')
                    prefix = int(prefix)
                    if 0 <= prefix <= 128:
                        return 0, 2 ** (128 - prefix)
                    else:
                        self.logger.error(f"Invalid IPv6 prefix: {prefix}")
                        return 0, 0
                else:
                    return 0, 1
            elif mechanism.startswith('include:'):
                domain = mechanism.split(':', 1)[1]
                return self.process_include(domain)
            elif mechanism in ('a', 'mx'):
                return self.resolve_a_or_mx(mechanism)
        except Exception as e:
            self.logger.error(f"Error processing mechanism {mechanism}: {e}")
        return 0, 0

    def resolve_a_or_mx(self, mechanism: str) -> Tuple[int, int]:
        ipv4_count, ipv6_count = 0, 0
        try:
            if mechanism == 'a':
                answers = dns.resolver.resolve(self.domain, 'A')
                ipv4_count = len(answers)
                if self.include_ipv6:
                    answers = dns.resolver.resolve(self.domain, 'AAAA')
                    ipv6_count = len(answers)
            elif mechanism == 'mx':
                answers = dns.resolver.resolve(self.domain, 'MX')
                for mx in answers:
                    hostname = str(mx.exchange)
                    ipv4_count += len(dns.resolver.resolve(hostname, 'A'))
                    if self.include_ipv6:
                        ipv6_count += len(dns.resolver.resolve(hostname, 'AAAA'))
        except dns.exception.DNSException as e:
            self.logger.debug(f"Resolution failed for {mechanism}: {e}")
        return ipv4_count, ipv6_count

    def process_include(self, include_domain: str) -> Tuple[int, int]:
        if include_domain in self.includes_seen:
            self.logger.debug(f"Skipping duplicate include: {include_domain}")
            return 0, 0
        if len(self.includes_seen) >= self.max_includes:
            self.logger.error("Exceeded maximum include lookups (RFC 7208 limit)")
            raise ValueError("Too many includes")

        self.includes_seen.append(include_domain)
        validator = SPFValidator(include_domain, self.include_ipv6, self.debug)
        spf_record = validator.fetch_spf_record()
        if not spf_record or not spf_record.startswith('v=spf1'):
            self.logger.debug(f"No valid SPF record for {include_domain}")
            return 0, 0

        total_ipv4, total_ipv6 = 0, 0
        for part in spf_record.split()[1:]:
            if part in ('all', '+all', '-all', '~all', '?all'):
                continue
            ipv4, ipv6 = self.count_ips(part)
            total_ipv4 += ipv4
            total_ipv6 += ipv6
            if part not in self.ip_counts:
                self.ip_counts[part] = {"ipv4": ipv4, "ipv6": ipv6}
        
        self.ip_counts[include_domain] = {"ipv4": total_ipv4, "ipv6": total_ipv6}
        return total_ipv4, total_ipv6

    def validate(self) -> Dict:
        spf_record = self.fetch_spf_record()
        if not spf_record:
            self.dmarc_record = self.fetch_dmarc_record()
            return {"valid": False, "error": "No SPF record found", "ip_counts": {}, "total_ipv4": 0, "total_ipv6": 0, "spf_record": None, "has_pphosted_include": False, "includes_used": 0, "includes_percentage": 0}

        parts = spf_record.split()
        if parts[0] != "v=spf1":
            return {"valid": False, "error": "Invalid SPF version", "ip_counts": {}, "total_ipv4": 0, "total_ipv6": 0, "spf_record": spf_record, "has_pphosted_include": False, "includes_used": 0, "includes_percentage": 0}

        pphosted_pattern = re.compile(r'include:spf-\d{8}\.pphosted\.com')
        has_pphosted_include = bool(pphosted_pattern.search(spf_record))
        self.dmarc_record = self.fetch_dmarc_record()

        total_ipv4, total_ipv6 = 0, 0
        self.top_level_mechanisms = [part for part in parts[1:] if part not in ('all', '+all', '-all', '~all', '?all')]
        for part in self.top_level_mechanisms:
            ipv4, ipv6 = self.count_ips(part)  # Fixed: changed 'countips' to 'count_ips'
            total_ipv4 += ipv4
            total_ipv6 += ipv6
            if part not in self.ip_counts:
                self.ip_counts[part] = {"ipv4": ipv4, "ipv6": ipv6}

        includes_used = len(self.includes_seen)
        includes_percentage = (includes_used / self.max_includes) * 100

        return {
            "valid": includes_used <= self.max_includes,
            "error": None,
            "ip_counts": self.ip_counts,
            "total_ipv4": total_ipv4,
            "total_ipv6": total_ipv6,
            "spf_record": spf_record,
            "has_pphosted_include": has_pphosted_include,
            "includes_used": includes_used,
            "includes_percentage": includes_percentage
        }

def read_domains_from_file(filepath: str) -> List[str]:
    domains = []
    domain_pattern = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$')
    try:
        with open(filepath, 'r') as f:
            for i, line in enumerate(f, 1):
                domain = line.strip()
                if not domain:
                    continue
                if not domain_pattern.match(domain):
                    raise ValueError(f"Invalid domain at line {i}: {domain}")
                domains.append(domain.lower())
        if not domains:
            raise ValueError("File is empty or contains no valid domains")
        return domains
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {filepath}")

def display_results(result: Dict, detail: bool, validator: SPFValidator, args: argparse.Namespace):
    GREEN = '\033[32m'
    RED = '\033[31m'
    RESET = '\033[0m'

    print("\nSPF Record:")
    print(f"{result['spf_record']}\n" if result['spf_record'] else "Not found\n")
    print("DMARC Record:")
    if validator.dmarc_record:
        print(f"{validator.dmarc_record}\n")
        dmarc_color = GREEN if validator.dmarc_policy == 'reject' else '\033[33m' if validator.dmarc_policy == 'quarantine' else RED
        print(f"DMARC Policy: {dmarc_color}{validator.dmarc_policy or 'none'}{RESET}\n")
    else:
        print("Not found\n")
        print(f"DMARC Policy: {RED}no entry{RESET}\n")

    if result['has_pphosted_include']:
        print(f"{GREEN}SPF record contains a pphosted SPF include{RESET}")
    else:
        print(f"{RED}SPF record does not contain a pphosted SPF include{RESET}")

    print(f"SPF Validation Result for {validator.domain}:")
    valid_text = f"{GREEN}True{RESET}" if result['valid'] else f"{RED}False{RESET}"
    print(f"Valid: {valid_text}")
    if result['error']:
        print(f"Error: {result['error']}")
    print(f"Total IPv4 Addresses: {result['total_ipv4']:,}")
    if args.ipv6:
        print(f"Total IPv6 Addresses: {result['total_ipv6']:,}")

    includes_used = result['includes_used']
    includes_percentage = result['includes_percentage']
    color = GREEN if includes_percentage < 70 else '\033[33m' if includes_percentage < 90 else RED
    print(f"SPF Include Lookups: {includes_used}/{validator.max_includes} ({color}{includes_percentage:.1f}%{RESET})")

    if detail and result['ip_counts']:
        table = []
        for mechanism in validator.top_level_mechanisms:
            counts = result['ip_counts'].get(mechanism, {"ipv4": 0, "ipv6": 0})
            ipv4 = counts.get('ipv4', 0)
            row = [mechanism, f"{ipv4:,}"]
            if args.ipv6:
                ipv6 = counts.get('ipv6', 0)
                row.append(f"{ipv6:,}")
            table.append(row)
        headers = ['Mechanism', 'IPv4 Count'] + (['IPv6 Count'] if args.ipv6 else [])
        print("\nDetailed IP Counts:")
        print(tabulate(table, headers=headers, tablefmt='grid'))

def export_results(result: Dict, filename: str, format: str, validator: SPFValidator, domain: str):
    data = {
        "domain": domain,
        "valid": result['valid'],
        "error": result['error'],
        "total_ipv4": result['total_ipv4'],
        "total_ipv6": result['total_ipv6'] if validator.include_ipv6 else None,
        "ip_counts": result['ip_counts'],
        "spf_record": result['spf_record'],
        "has_pphosted_include": result['has_pphosted_include'],
        "includes_used": result['includes_used'],
        "includes_percentage": result['includes_percentage']
    }
    if format == 'json':
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
    elif format == 'csv':
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            headers = ['Mechanism', 'IPv4 Count'] + (['IPv6 Count'] if validator.include_ipv6 else [])
            writer.writerow(headers)
            for mech in validator.top_level_mechanisms:
                counts = result['ip_counts'].get(mech, {"ipv4": 0, "ipv6": 0})
                ipv4 = counts.get('ipv4', 0)
                row = [mech, ipv4]
                if validator.include_ipv6:
                    row.append(counts.get('ipv6', 0))
                writer.writerow(row)

def export_batch_results(results: Dict[str, Dict], filename: str, format: str):
    if format == 'json':
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
    elif format == 'csv':
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            headers = ['Domain', 'Valid', 'Total IPv4', 'Total IPv6', 'Includes Used', 'SPF Record']
            writer.writerow(headers)
            for domain, result in results.items():
                writer.writerow([
                    domain,
                    result['valid'],
                    result['total_ipv4'],
                    result['total_ipv6'],
                    result['includes_used'],
                    result['spf_record']
                ])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SPF Record Checker & Validator compliant with RFC 7208.",
        epilog="Example: python spf_checker.py example.com --detail --ipv6 or python spf_checker.py --file domains.txt"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("domain", nargs="?", help="Domain to check SPF record for")
    group.add_argument("--file", help="File containing one domain per line")
    parser.add_argument("--detail", action="store_true", help="Show detailed IP counts for top-level mechanisms")
    parser.add_argument("--ipv6", action="store_true", help="Include IPv6 address counts")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--export", metavar="FILE", help="Export results to FILE (json or csv based on extension)")

    args = parser.parse_args()

    if args.file:
        domains = read_domains_from_file(args.file)
        results = {}
        
        for i, domain in enumerate(domains, 1):
            print(f"\nProcessing {domain} ({i}/{len(domains)})")
            validator = SPFValidator(domain, args.ipv6, args.debug)
            result = validator.validate()
            results[domain] = result
            display_results(result, args.detail, validator, args)
        
        export_file = args.export or f"spf_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        export_format = 'json' if export_file.endswith('.json') else 'csv'
        export_batch_results(results, export_file, export_format)
        print(f"\nResults exported to {export_file}")
    else:
        validator = SPFValidator(args.domain, args.ipv6, args.debug)
        result = validator.validate()
        display_results(result, args.detail, validator, args)
        
        if args.export:
            export_format = 'json' if args.export.endswith('.json') else 'csv'
            export_results(result, args.export, export_format, validator, args.domain)
            print(f"\nResults exported to {args.export}")