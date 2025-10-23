
# Dark Wxlf

> Advanced Bug Bounty Automation Framework - Automated reconnaissance, vulnerability discovery, and exploitation

**Created by: GhxstSh3ll @ ibdtech**

## 🎯 What It Does

Dark Wxlf is a comprehensive bug bounty automation tool that follows expert methodology:

**Phase 1: Passive OSINT** (Undetectable)
- Multi-source subdomain enumeration (4 parallel sources)
- Certificate Transparency mining
- DNS analysis
- Zero target contact

**Phase 2: Active Reconnaissance** (Detectable)
- Live host discovery
- Port scanning
- Web application identification
- Service enumeration

**Phase 3: Intelligent Analysis**
- Attack surface mapping
- Expert testing recommendations
- Prioritized vulnerability targets

**Phase 4: Systematic Testing & Exploitation**
- XSS (Cross-Site Scripting)
- SQL Injection
- IDOR (Insecure Direct Object Reference)
- SSRF (Server-Side Request Forgery)
- Open Redirect
- Automated PoC generation
- Reproducible exploitation steps

## 🚀 Key Features

- **100% Free** - No API keys or subscriptions required
- **Parallel Processing** - 4 recon tools running simultaneously
- **Smart Detection** - Actual vulnerability validation, not just fuzzing
- **Expert Logic** - Follows professional bug bounty hunter methodology
- **Detailed PoCs** - Step-by-step reproduction with exploitation examples
- **CVSS Scoring** - Industry-standard severity ratings
- **Scope-Aware Testing** - Choose specific vulnerability types to test
- **Professional Reports** - Ready for bug bounty platform submission

## 📋 Requirements

### System Requirements
- **OS**: Linux (Kali, Parrot, Ubuntu, Debian)
- **Python**: 3.8+
- **Privileges**: sudo (for port scanning)

### Required Tools

```bash
# System packages
sudo apt update
sudo apt install python3 python3-pip nmap amass whois -y

# Python dependencies
sudo apt install python3-requests python3-termcolor python3-pyfiglet -y

# Install Go
sudo apt install golang-go -y

# Install Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Add Go bin to PATH
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc
```

## 🔧 Installation

### Quick Install

```bash
# Clone repository
git clone https://github.com/ibdtech/dark-wxlf.git
cd dark-wxlf

# Install Python dependencies
sudo apt install python3-requests python3-termcolor python3-pyfiglet -y

# Run
python3 dark_wxlf.py
```

### Verify Installation

```bash
# Check required tools
subfinder -version
amass -version
nmap --version
python3 --version
```

## 🎮 Usage

### Basic Usage

```bash
python3 dark_wxlf.py
```

### Workflow

1. **Enter Target Domain**
   ```
   example.com
   ```

2. **Phase 1: Passive OSINT** (Automatic)
   - Runs 4 subdomain enumeration tools in parallel
   - Certificate transparency mining
   - Completely undetectable

3. **Phase 2: Active Recon** (Requires confirmation)
   - Live host discovery
   - Web application enumeration
   - Service detection

4. **Phase 3: Analysis** (Automatic)
   - Attack surface mapping
   - Expert recommendations

5. **Phase 4: Testing** (Interactive)
   - Select vulnerability types to test
   - Choose from: XSS, SQLi, IDOR, SSRF, Open Redirect
   - Or test everything (comprehensive mode)

### Example Session

```bash
$ python3 dark_wxlf.py

[10:30:15] [INFO] Starting passive info gathering...
[10:30:20] [✓] Subfinder got 45 results
[10:30:25] [✓] Amass got 32 results
[10:30:30] [✓] crt.sh got 78 results
[10:31:00] [✓] Phase 1 done: Found 123 subdomains

[?] Continue with active recon? (yes/no): yes

[10:32:00] [✓] Found 45 live hosts
[10:33:00] [✓] Discovered 12 web apps

[?] Start vulnerability testing? (yes/no): yes
[?] Select tests (1,2,3 or 6 for all): 6

[10:35:00] [✓] XSS found: api.example.com (param: query)
[10:36:00] [✓] SQLi found: login.example.com (param: user)
[10:37:00] [✓] Report saved: bug_bounty_report_example.com_20250120_103700.txt
```

## 📂 Output Files

| File | Description |
|------|-------------|
| `dark_wxlf_[domain]_[timestamp].txt` | Full reconnaissance report |
| `bug_bounty_report_[domain]_[timestamp].txt` | Detailed vulnerability report with PoCs |

## 📖 Examples

### Example 1: Full Comprehensive Scan

```bash
python3 dark_wxlf.py
# Enter: testphp.vulnweb.com
# Confirm active recon: yes
# Start testing: yes
# Select: 6 (all tests)
```

### Example 2: Targeted XSS Testing

```bash
python3 dark_wxlf.py
# Enter: example.com
# Confirm active recon: yes
# Start testing: yes
# Select: 1 (XSS only)
```

### Example 3: Passive Recon Only

```bash
python3 dark_wxlf.py
# Enter: example.com
# Confirm active recon: no
# (Stops after passive OSINT)
```

## ⚠️ Legal Disclaimer

**CRITICAL: Read Before Use**

This tool is for **authorized security testing only**.

✅ **Allowed Uses:**
- Systems you own
- Bug bounty programs (within scope)
- Authorized penetration testing engagements
- Written permission from target owner

❌ **Prohibited Uses:**
- Unauthorized systems
- Out-of-scope targets
- Illegal activities
- Any system without explicit permission

**You are solely responsible for your actions. Unauthorized access to computer systems is illegal and punishable by law.**

## 🛡️ Responsible Disclosure

When you discover vulnerabilities:

1. **Report to security team first** - Don't publicly disclose
2. **Allow time to patch** (90 days standard)
3. **Follow bug bounty program rules**
4. **Document everything** - Use Dark Wxlf's generated reports
5. **Be professional** - Clear, detailed, reproducible reports

## 🔒 Safety Features

- **Passive mode** - Completely undetectable reconnaissance
- **Confirmation prompts** - Must explicitly approve active scanning
- **Scope selection** - Choose specific tests to stay within program scope
- **Non-destructive** - No data modification or DoS attempts
- **Professional output** - Platform-ready submissions

## 📊 Vulnerability Types Detected

### XSS (Cross-Site Scripting)
- Reflected XSS
- Parameter injection
- Multiple payload types
- Real reflection validation

### SQL Injection
- Error-based detection
- Classic payloads
- SQL error pattern matching
- Database compromise validation

### IDOR (Insecure Direct Object Reference)
- ID parameter detection
- Authorization bypass
- Privacy violation identification

### SSRF (Server-Side Request Forgery)
- Internal network access
- Cloud metadata exploitation
- URL parameter validation

### Open Redirect
- Redirect parameter detection
- Phishing vector identification
- Unvalidated redirect testing

## 🎯 Use Cases

- **Bug Bounty Hunters** - Automated recon and vuln discovery
- **Penetration Testers** - Comprehensive security assessment
- **Security Researchers** - Vulnerability validation
- **Red Teamers** - Attack surface mapping

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create feature branch (`git checkout -b feature/improvement`)
3. Commit changes (`git commit -m 'Add feature'`)
4. Push to branch (`git push origin feature/improvement`)
5. Open Pull Request

## 📝 Roadmap

- [ ] Additional vulnerability modules (XXE, RCE, LFI)
- [ ] API testing capabilities
- [ ] GraphQL endpoint testing
- [ ] WebSocket vulnerability detection
- [ ] Automated report submission to platforms
- [ ] JSON/PDF report formats
- [ ] Docker containerization

## 🐛 Known Issues

- Amass may be slow on first run (building database)
- Subfinder requires Go to be properly configured
- Some tests may trigger WAF/IPS alerts
- Port scanning requires sudo/root

## 💬 Support

- **Issues**: [GitHub Issues](https://github.com/ibdtech/dark-wxlf/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ibdtech/dark-wxlf/discussions)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **ProjectDiscovery** - Subfinder
- **OWASP** - Amass
- **Bug Bounty Community** - Methodology and best practices
- **Security Researchers** - Vulnerability patterns and detection techniques

## Why Dark Wxlf?

### Innovation
- First free tool combining passive OSINT with automated exploitation
- Follows actual bug bounty hunter methodology
- Generates platform-ready submissions automatically

### Accuracy
- Real vulnerability validation (not just fuzzing)
- Multiple data sources for comprehensive coverage
- Smart parameter detection and testing

### Professional
- Detailed PoC generation
- CVSS scoring
- Reproducible exploitation steps
- Ready for bug bounty submission

---

**Created by GhxstSh3ll**



**For educational and authorized testing purposes only.**
