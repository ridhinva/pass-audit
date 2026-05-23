# PassAudit - Password Strength Auditor

Audits password strength using entropy calculation, pattern detection, dictionary checks, and breach database lookups (HaveIBeenPwned API). For security professionals auditing credential policies.

## Features

- Entropy-based password strength scoring
- Pattern detection (keyboard walks, repeats, sequences)
- Dictionary word detection
- Common password checking
- HaveIBeenPwned k-anonymity API integration
- Bulk password file auditing
- Password policy compliance checking
- CSV/JSON report generation

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/pass-audit.git
cd pass-audit
pip3 install -r requirements.txt
chmod +x passaudit.py
```

## Usage

### Audit Single Password
```bash
# Interactive mode (password not shown in terminal)
python3 passaudit.py audit

# Direct password (use with caution - visible in shell history)
python3 passaudit.py audit "MyP@ssw0rd123"

# Check against breach database
python3 passaudit.py audit "password123" --breach-check
```

### Audit Password File
```bash
# Audit a file of passwords (one per line)
python3 passaudit.py audit -f passwords.txt

# With breach checking and report
python3 passaudit.py audit -f passwords.txt --breach-check --report json --output audit.json
```

### Password Policy Check
```bash
# Check against custom policy
python3 passaudit.py policy -f passwords.txt --min-length 12 --min-upper 2 --min-digits 2 --min-special 1

# Check against standard policies
python3 passaudit.py policy -f passwords.txt --standard nist
python3 passaudit.py policy -f passwords.txt --standard pci-dss
```

### Generate Password Report
```bash
# Generate strength distribution report
python3 passaudit.py audit -f passwords.txt --report json --output report.json
python3 passaudit.py audit -f passwords.txt --report csv --output report.csv
```

### Password Scoring

| Score | Rating    | Entropy  | Description |
|-------|-----------|----------|-------------|
| 0-20  | Very Weak | <28 bits | Crackable in seconds |
| 21-40 | Weak      | 28-35 bits | Crackable in hours |
| 41-60 | Fair      | 35-50 bits | Crackable in weeks |
| 61-80 | Strong    | 50-65 bits | Crackable in years |
| 81-100| Very Strong | >65 bits | Computationally infeasible |

## Legal Disclaimer

This tool is for authorized password policy auditing. Do not use to crack or steal credentials.

## License

MIT License
