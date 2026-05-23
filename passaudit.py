#!/usr/bin/env python3
"""
PassAudit - Password Strength Auditor
For authorized password policy auditing only.
"""

import argparse
import math
import re
import sys
import os
import json
import csv
import hashlib
import getpass
from collections import Counter
from datetime import datetime

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = WHITE = MAGENTA = RESET = ""
    class Style:
        RESET_ALL = ""

VERSION = "1.0.0"

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "master",
    "dragon", "111111", "baseball", "iloveyou", "trustno1", "sunshine",
    "letmein", "welcome", "shadow", "superman", "michael", "football",
    "password1", "password123", "admin", "root", "toor", "pass", "test",
    "guest", "info", "adnim", "administrator", "changeme", "default",
    "p@ssw0rd", "passw0rd", "p@ssword", "qwerty123", "1q2w3e4r",
    "000000", "1234567", "123456789", "1234567890",
}

KEYBOARD_WALKS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890",
    "qwerty", "asdfgh", "zxcvbn", "1qaz2wsx", "qazwsx",
    "abcdef", "abc123", "xyzabc",
]

SEQUENCES = "abcdefghijklmnopqrstuvwxyz0123456789"


def calculate_entropy(password):
    """Calculate password entropy in bits."""
    charset = 0
    if re.search(r'[a-z]', password):
        charset += 26
    if re.search(r'[A-Z]', password):
        charset += 26
    if re.search(r'[0-9]', password):
        charset += 10
    if re.search(r'[^a-zA-Z0-9]', password):
        charset += 33

    if charset == 0:
        return 0
    return len(password) * math.log2(charset)


def detect_patterns(password):
    """Detect common password patterns."""
    issues = []
    pw_lower = password.lower()

    # Repeated characters
    if re.search(r'(.)\1{2,}', password):
        issues.append("Contains repeated characters (e.g., 'aaa')")

    # Keyboard walks
    for walk in KEYBOARD_WALKS:
        if walk in pw_lower or walk[::-1] in pw_lower:
            issues.append(f"Contains keyboard walk pattern: '{walk}'")
            break

    # Sequential characters
    for i in range(len(pw_lower) - 2):
        if pw_lower[i:i+3] in SEQUENCES:
            issues.append("Contains sequential characters")
            break

    # Common substitutions (l33tspeak)
    leet_pw = pw_lower.replace('4', 'a').replace('3', 'e').replace('1', 'i')
    leet_pw = leet_pw.replace('0', 'o').replace('5', 's').replace('7', 't')
    for common in COMMON_PASSWORDS:
        if common in leet_pw and common != pw_lower:
            issues.append(f"Common word with l33tspeak substitution: '{common}'")
            break

    # Dictionary words
    dict_words = ["password", "admin", "login", "welcome", "monkey", "master",
                  "dragon", "letmein", "qwerty", "love", "god", "money",
                  "computer", "internet", "security"]
    for word in dict_words:
        if word in pw_lower:
            issues.append(f"Contains dictionary word: '{word}'")
            break

    # Date patterns
    if re.search(r'(19|20)\d{2}', password):
        issues.append("Contains year pattern")

    # All same type
    if password.isalpha():
        issues.append("Letters only - no digit/special characters")
    elif password.isdigit():
        issues.append("Digits only - no letters/special characters")

    return issues


def check_breach(password):
    """Check password against HaveIBeenPwned using k-anonymity."""
    if not HAS_REQUESTS:
        return None, "requests library not installed"

    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    try:
        resp = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=5)
        if resp.status_code != 200:
            return None, f"API returned {resp.status_code}"

        for line in resp.text.splitlines():
            hash_suffix, count = line.split(':')
            if hash_suffix == suffix:
                return int(count), None

        return 0, None
    except Exception as e:
        return None, str(e)


def score_password(password):
    """Score a password and return detailed analysis."""
    entropy = calculate_entropy(password)
    patterns = detect_patterns(password)
    length = len(password)

    # Base score from entropy
    if entropy < 28:
        score = 10
        rating = "Very Weak"
        color = Fore.RED
    elif entropy < 35:
        score = 25
        rating = "Weak"
        color = Fore.RED
    elif entropy < 50:
        score = 45
        rating = "Fair"
        color = Fore.YELLOW
    elif entropy < 65:
        score = 65
        rating = "Strong"
        color = Fore.GREEN
    else:
        score = 85
        rating = "Very Strong"
        color = Fore.GREEN

    # Penalties
    if password.lower() in COMMON_PASSWORDS:
        score = 0
        rating = "CRITICAL: Common Password"
        color = Fore.RED
    elif length < 8:
        score = max(score - 20, 0)
    elif length < 6:
        score = max(score - 30, 0)

    # Pattern penalties
    score -= len(patterns) * 5
    score = max(0, min(100, score))

    # Bonuses
    if length >= 16:
        score = min(100, score + 10)
    has_mixed = (any(c.isupper() for c in password) and
                 any(c.islower() for c in password) and
                 any(c.isdigit() for c in password) and
                 any(not c.isalnum() for c in password))
    if has_mixed:
        score = min(100, score + 10)

    return {
        "password": password[:2] + "*" * (len(password) - 2),
        "length": length,
        "entropy": round(entropy, 1),
        "score": score,
        "rating": rating,
        "color": color,
        "patterns": patterns,
        "breach_count": None,
        "breach_error": None,
    }


def print_result(result):
    """Print a password audit result."""
    color = result["color"]
    print(f"\n  {Fore.CYAN}Password:{Style.RESET_ALL} {result['password']}")
    print(f"  {Fore.CYAN}Length:{Style.RESET_ALL}   {result['length']}")
    print(f"  {Fore.CYAN}Entropy:{Style.RESET_ALL}  {result['entropy']} bits")
    print(f"  {Fore.CYAN}Score:{Style.RESET_ALL}    {color}{result['score']}/100 ({result['rating']}){Style.RESET_ALL}")

    if result["patterns"]:
        print(f"  {Fore.YELLOW}Issues:{Style.RESET_ALL}")
        for p in result["patterns"]:
            print(f"    - {p}")

    if result["breach_count"] is not None:
        if result["breach_count"] > 0:
            print(f"  {Fore.RED}BREACHED: Found {result['breach_count']:,} times in data breaches!{Style.RESET_ALL}")
        else:
            print(f"  {Fore.GREEN}Not found in breach database{Style.RESET_ALL}")
    elif result["breach_error"]:
        print(f"  {Fore.YELLOW}Breach check: {result['breach_error']}{Style.RESET_ALL}")


def check_policy(password, policy):
    """Check password against a policy."""
    failures = []

    if len(password) < policy.get("min_length", 8):
        failures.append(f"Too short (min: {policy['min_length']})")

    if policy.get("min_upper", 0) > 0:
        upper = sum(1 for c in password if c.isupper())
        if upper < policy["min_upper"]:
            failures.append(f"Need {policy['min_upper']} uppercase (has {upper})")

    if policy.get("min_lower", 0) > 0:
        lower = sum(1 for c in password if c.islower())
        if lower < policy["min_lower"]:
            failures.append(f"Need {policy['min_lower']} lowercase (has {lower})")

    if policy.get("min_digits", 0) > 0:
        digits = sum(1 for c in password if c.isdigit())
        if digits < policy["min_digits"]:
            failures.append(f"Need {policy['min_digits']} digits (has {digits})")

    if policy.get("min_special", 0) > 0:
        special = sum(1 for c in password if not c.isalnum())
        if special < policy["min_special"]:
            failures.append(f"Need {policy['min_special']} special chars (has {special})")

    return failures


POLICIES = {
    "nist": {"min_length": 8},
    "pci-dss": {"min_length": 7, "min_upper": 1, "min_lower": 1, "min_digits": 1},
    "hipaa": {"min_length": 8, "min_upper": 1, "min_lower": 1, "min_digits": 1, "min_special": 1},
    "strong": {"min_length": 12, "min_upper": 2, "min_lower": 2, "min_digits": 2, "min_special": 1},
}


def main():
    parser = argparse.ArgumentParser(
        description="PassAudit - Password Strength Auditor",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    sub = parser.add_subparsers(dest="command")

    # audit
    audit = sub.add_parser("audit", help="Audit password strength")
    audit.add_argument("password", nargs="?", help="Password to audit")
    audit.add_argument("-f", "--file", help="File with passwords (one per line)")
    audit.add_argument("--breach-check", action="store_true", help="Check against breach database")
    audit.add_argument("--report", choices=["json", "csv"], help="Report format")
    audit.add_argument("--output", help="Output filename")

    # policy
    policy_cmd = sub.add_parser("policy", help="Check against password policy")
    policy_cmd.add_argument("-f", "--file", required=True, help="Password file")
    policy_cmd.add_argument("--standard", choices=list(POLICIES.keys()), help="Use standard policy")
    policy_cmd.add_argument("--min-length", type=int, default=8)
    policy_cmd.add_argument("--min-upper", type=int, default=0)
    policy_cmd.add_argument("--min-lower", type=int, default=0)
    policy_cmd.add_argument("--min-digits", type=int, default=0)
    policy_cmd.add_argument("--min-special", type=int, default=0)

    args = parser.parse_args()

    print(f"\n{Fore.CYAN}╔══════════════════════════════════╗")
    print(f"║    PassAudit v{VERSION}             ║")
    print(f"╚══════════════════════════════════╝{Style.RESET_ALL}")

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "audit":
        passwords = []
        if args.file:
            with open(args.file) as f:
                passwords = [line.strip() for line in f if line.strip()]
        elif args.password:
            passwords = [args.password]
        else:
            pw = getpass.getpass("Enter password to audit: ")
            passwords = [pw]

        results = []
        for pw in passwords:
            result = score_password(pw)

            if args.breach_check:
                count, err = check_breach(pw)
                result["breach_count"] = count
                result["breach_error"] = err

            print_result(result)
            results.append(result)

        # Summary
        if len(results) > 1:
            scores = [r["score"] for r in results]
            print(f"\n{Fore.CYAN}{'='*50}")
            print(f"  SUMMARY: {len(results)} passwords audited")
            print(f"  Average score: {sum(scores)/len(scores):.1f}")
            print(f"  Weakest: {min(scores)}/100")
            print(f"  Strongest: {max(scores)}/100")
            print(f"{'='*50}{Style.RESET_ALL}")

        if args.output and args.report:
            with open(args.output, 'w') as f:
                if args.report == "json":
                    json.dump(results, f, indent=2, default=str)
                elif args.report == "csv":
                    w = csv.writer(f)
                    w.writerow(["Password", "Length", "Entropy", "Score", "Rating", "Issues"])
                    for r in results:
                        w.writerow([r["password"], r["length"], r["entropy"],
                                   r["score"], r["rating"], "; ".join(r["patterns"])])
            print(f"\n{Fore.GREEN}[+] Report saved to {args.output}{Style.RESET_ALL}")

    elif args.command == "policy":
        policy = POLICIES.get(args.standard, {
            "min_length": args.min_length,
            "min_upper": args.min_upper,
            "min_lower": args.min_lower,
            "min_digits": args.min_digits,
            "min_special": args.min_special,
        })

        print(f"\n{Fore.CYAN}[*] Policy: {args.standard or 'custom'}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Requirements: {policy}{Style.RESET_ALL}\n")

        with open(args.file) as f:
            passwords = [line.strip() for line in f if line.strip()]

        passed = 0
        failed = 0
        for pw in passwords:
            failures = check_policy(pw, policy)
            if not failures:
                passed += 1
                print(f"  {Fore.GREEN}PASS{Style.RESET_ALL} {pw[:2]}{'*' * (len(pw)-2)}")
            else:
                failed += 1
                print(f"  {Fore.RED}FAIL{Style.RESET_ALL} {pw[:2]}{'*' * (len(pw)-2)}: {', '.join(failures)}")

        print(f"\n{Fore.CYAN}{'='*50}")
        print(f"  Results: {passed} passed, {failed} failed out of {len(passwords)}")
        print(f"{'='*50}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
