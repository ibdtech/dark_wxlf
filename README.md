# Dark Wxlf

automated bug bounty recon + vuln scanner i built for myself. does everything from subdomain enum to actual exploitation testing. way faster than doing this stuff manually.

## what it does

basically automates the boring parts of bug bounty hunting:

**Phase 1 - Passive Recon** (completely silent, target never knows)
- grabs subdomains from subfinder, amass, crt.sh, hackertarget
- runs everything in parallel so it's fast
- no direct contact with target

**Phase 2 - Active Scanning** (asks permission first)
- checks which hosts are actually alive
- finds web apps on different ports
- maps out the attack surface

**Phase 3 - Analysis**
- detects WAFs (cloudflare, akamai, etc)
- fuzzes for hidden directories with ffuf
- runs nuclei templates if you want
- figures out what tech stack they're using

**Phase 4 - Vulnerability Testing**
- 19 different vulnerability types
- you pick which ones to test
- can also run 1000+ nuclei templates
- generates detailed PoCs for everything

## vulnerability coverage

built-in tests:
- XSS (reflected, stored, DOM)
- SQL injection with error detection
- IDOR / broken access control
- SSRF with AWS metadata checks
- Open redirects
- XXE (xml external entities)
- Command injection (blind + time-based)
- Path traversal / LFI
- Sensitive file exposure (.env, .git, backups, etc)
- CORS misconfigurations
- Missing security headers
- Rate limiting issues
- CRLF injection
- GraphQL introspection
- JWT vulnerabilities
- Subdomain takeover
- SSTI (template injection)
- Host header injection
- WebSocket security issues

plus 1000+ more checks if you install nuclei

## install

```bash
# clone it
git clone https://github.com/yourusername/dark-wxlf.git
cd dark-wxlf

# install python stuff
pip install requests termcolor pyfiglet aiohttp

# optional but recommended - for advanced features
go install github.com/ffuf/ffuf@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@master

# update nuclei templates
nuclei -update-templates

# get wordlists for fuzzing
sudo apt install seclists
# or just grab dirb's common.txt
```

make sure `~/go/bin` is in your PATH:
```bash
export PATH=$PATH:~/go/bin
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### verify installation

run the diagnostic script to check everything:
```bash
bash check_deps.sh
```

this will show you what's installed, what's missing, and if anything needs PATH fixes.

if tools are installed but dark wxlf can't find them, it's a PATH issue:
```bash
# quick fix for current session
export PATH=$PATH:~/go/bin

# permanent fix
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc

# verify it worked
which nuclei
which ffuf
```

## usage

```bash
python3 dark_wxlf.py
```

it'll walk you through everything with menus:
1. enter target domain
2. passive recon runs automatically
3. asks if you want active scanning (say yes unless you're being sneaky)
4. pick advanced recon options (waf detection, fuzzing, nuclei)
5. choose output formats (txt, json, html)
6. select which vulnerability tests to run
7. get detailed reports with PoCs

### quick options

when it asks for vulnerability tests:
- `all` - run everything (takes a while but thorough)
- `critical` - just the critical severity ones
- `quick` - fast scan (xss, sqli, idor, files)
- `1,2,5` - specific test numbers

for advanced recon:
- `all` - waf detection + fuzzing + nuclei
- `skip` - none of that, just basic tests
- `1,3` - pick specific features

output formats:
- `all` - txt + json + html
- `1` - just text
- `2` - json only (good for piping to other tools)
- `3` - html report (looks really nice)

## output

generates comprehensive reports:

**TXT Report**
- classic text format
- organized by severity
- includes full PoCs
- easy to copy/paste

**JSON Report**
```json
{
  "scan_info": {
    "target": "example.com",
    "timestamp": "2024-10-23...",
    "waf_detected": ["Cloudflare"]
  },
  "summary": {
    "critical": 3,
    "high": 7,
    ...
  },
  "findings": [...]
}
```

**HTML Report**
- dark theme
- color coded by severity
- collapsible sections
- actually looks professional for bug bounty submissions

## features that make it better

**WAF Detection**
- knows when cloudflare/akamai/etc is in the way
- warns you so you're not wasting time
- adjusts testing approach

**Smart Fuzzing**
- uses ffuf for directory discovery
- auto-finds wordlists on your system
- adds discovered paths to vuln testing

**Nuclei Integration**
- 1000+ pre-built templates
- covers CVEs, misconfigs, exposed panels
- auto-parses results into your report

**Multiple Output Formats**
- txt for reading
- json for automation
- html for bug bounty submissions

**Interactive Menus**
- pick exactly what you want to test
- skip features you don't need
- quick options for common scenarios

## vulnerability test reference

```
Test #  | Name                    | Severity
--------|-------------------------|----------
1       | XSS                     | HIGH
2       | SQL Injection           | CRITICAL
3       | IDOR                    | HIGH
4       | SSRF                    | CRITICAL
5       | Open Redirect           | MEDIUM
6       | XXE                     | CRITICAL
7       | Command Injection       | CRITICAL
8       | Path Traversal          | HIGH
9       | Sensitive Files         | HIGH
10      | CORS Misconfiguration   | MEDIUM
11      | Security Headers        | LOW
12      | Rate Limiting           | MEDIUM
13      | CRLF Injection          | MEDIUM
14      | GraphQL Introspection   | MEDIUM
15      | JWT Vulnerabilities     | HIGH
16      | Subdomain Takeover      | HIGH
17      | SSTI                    | CRITICAL
18      | Host Header Injection   | MEDIUM
19      | WebSocket Security      | MEDIUM
```

## example workflow

```bash
# start scan
python3 dark_wxlf.py

# enter target
[?] Enter target domain: bugcrowd.com

# it finds like 50 subdomains automatically

# active recon?
[?] Continue with active recon? yes

# advanced recon menu pops up
[?] Select options: all

# picks output formats
[?] Select formats: all

# vulnerability tests menu
[?] Enter test numbers: critical

# scans for a bit...
# drops 3 reports in your directory
```

## real talk

this thing has found me actual bugs. the subdomain takeover check alone has paid for itself multiple times. xxe and ssti detection is solid. cors testing catches a lot of low-hanging fruit.

if you're doing bug bounties manually without automation you're leaving money on the table. this does in 10 minutes what would take hours by hand.

## what works without optional tools

the tool is smart - if you don't install the optional stuff it just skips those features and keeps going. you still get:

✅ all 19 vulnerability tests
✅ subdomain enumeration (crt.sh + hackertarget)
✅ waf detection
✅ all 3 report formats
✅ complete scanning

you just won't have:
- advanced fuzzing (needs ffuf)
- nuclei templates (needs nuclei)
- better subdomain discovery (needs subfinder/amass)

tool tells you what's missing and keeps working. no crashes, no errors.

**pro tip:** run `bash check_deps.sh` to see exactly what you have and what you're missing

## common use cases

**quick bug hunt**
```
Advanced: 1,3 (WAF + Nuclei)
Output: 1 (TXT)
Tests: critical
Time: ~15 min
```

**comprehensive audit**
```
Advanced: all
Output: all
Tests: all
Time: ~45 min
```

**stealth recon**
```
Active Recon: no
Advanced: skip
Output: 1
Time: ~5 min
```

**api security test**
```
Advanced: 1,3
Output: 2 (JSON)
Tests: 4,6,10,14,15
Time: ~20 min
```

## troubleshooting

**"tool not found" but you just installed it**

this is almost always a PATH issue. the tool is installed but your shell can't find it.

```bash
# quick fix (current session only)
export PATH=$PATH:~/go/bin

# permanent fix (recommended)
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc

# verify
which nuclei ffuf subfinder
```

run the diagnostic script to check everything:
```bash
bash check_deps.sh
```

**"ffuf not found"**
```bash
go install github.com/ffuf/ffuf@latest
export PATH=$PATH:~/go/bin
```

**"nuclei not found"**
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
export PATH=$PATH:~/go/bin
```

**"no wordlist found"**
```bash
sudo apt install seclists
```

**tool installed but not working**
```bash
# check if it's really there
ls ~/go/bin/

# if you see the tool, it's just PATH
export PATH=$PATH:~/go/bin

# test manually
~/go/bin/nuclei -version
~/go/bin/ffuf -h
```

**permission errors**
```bash
chmod +x dark_wxlf.py
```

**import errors**
```bash
pip install requests termcolor pyfiglet aiohttp
# or use pip3
pip3 install requests termcolor pyfiglet aiohttp
```

**still broken?**

check PATH_FIX.txt for detailed troubleshooting

## tips for better results

1. always run passive recon first to see what you're dealing with
2. check subdomain takeovers - they're everywhere
3. waf detected? be more careful with rate limits
4. use html reports for bug bounty submissions
5. json output is perfect for tracking over time
6. test both http and https
7. graphql introspection dumps the entire api schema
8. jwt none algorithm = instant critical
9. don't skip "low" severity stuff, it adds up
10. cors with credentials is usually high/critical

## bug bounty priorities

**test these first (highest value):**
- sql injection (test 2)
- command injection (test 7)
- xxe (test 6)
- ssti (test 17)
- ssrf (test 4)

**easy wins:**
- subdomain takeover (test 16)
- sensitive files (test 9)
- security headers (test 11)

**api-specific:**
- graphql (test 14)
- jwt (test 15)
- cors (test 10)

## what's different from other tools

most scanners either:
- do everything automatically (no control)
- require tons of setup and config files
- cost money
- look like AI wrote them

this one:
- lets you pick exactly what to test
- works out of the box
- 100% free
- actual human code style
- gracefully handles missing tools
- generates pro reports

## notes

- tested on kali, ubuntu, parrot
- works in wsl too
- maintains session if you ctrl+c
- all tools are free open source
- no api keys or accounts needed
- output files don't overwrite (timestamped)

## performance

typical scan times on average target:

```
Passive Recon:        2-5 min
Active Recon:         3-10 min
WAF Detection:        30 sec
Fuzzing:              2-5 min
Nuclei:               3-10 min
Vulnerability Tests:  5-30 min

Full comprehensive:   15-60 min total
Quick critical scan:  10-15 min
```

threading and parallel processing on everything that matters so it's pretty fast.

## files you'll get

after a scan you'll have:
```
bug_bounty_report_target_20241023_143045.txt   (text report)
bug_bounty_report_target_20241023_143045.json  (json data)
bug_bounty_report_target_20241023_143045.html  (web report)
dark_wxlf_target_20241023_143045.txt           (raw scan data)
```

all timestamped so you can run multiple scans without overwriting.

**included helper files:**
- `check_deps.sh` - diagnostic script to check all dependencies
- `PATH_FIX.txt` - detailed troubleshooting guide for PATH issues

## integrating with other tools

the json output is perfect for piping into other tools:

```bash
# run scan
python3 dark_wxlf.py

# parse results with jq
cat bug_bounty_report_*.json | jq '.findings[] | select(.severity=="CRITICAL")'

# send to slack/discord
curl -X POST webhook-url -d @bug_bounty_report_*.json

# import to database
python3 import_results.py bug_bounty_report_*.json
```

## legal stuff

**disclaimer:** for authorized testing only. don't be stupid. get permission. check the scope. you know the drill.

i'm not responsible if you:
- get banned from a bug bounty program
- get in legal trouble
- dos something by accident
- violate terms of service

this is a tool. tools can be used wrong. don't use it wrong.

## what people have found with this

real bugs found using this scanner:

- subdomain takeovers on major platforms
- xxe in xml parsers leading to file disclosure
- command injection in debug endpoints
- exposed .git directories with full source
- graphql introspection revealing admin mutations
- jwt none algorithm bypassing auth
- ssti in template engines
- cors allowing credential theft
- sensitive files (.env with api keys)
- path traversal reading config files

## roadmap

might add in the future (let me know what you want):
- screenshot capture with playwright
- better api testing
- automatic exploitation for some vulns
- database for tracking targets over time
- more fuzzing wordlists
- parameter discovery
- better crawling with katana
- notification webhooks
- ci/cd integration

## contributing

found a bug? got a feature idea? pr's welcome.

keep the code style the same - human written, not ai generated.

## credits

built by me GhxstSh3ll

uses these awesome tools:
- subfinder (projectdiscovery)
- amass (owasp)
- ffuf (ffuf project)
- nuclei (projectdiscovery)
- requests (python)
- termcolor (python)

inspired by every bug bounty hunter who's shared their methodology

## support

if this helps you get paid on bug bounties:
- star the repo ⭐
- share it with other hunters
- contribute improvements

## license

MIT - do whatever you want with it. fork it, sell it, modify it, i don't care.

see LICENSE file for the boring legal text.

## final thoughts

bug bounty hunting is competitive. automation helps you find bugs faster. this tool finds bugs that humans miss because humans get tired and skip stuff.

use it as a starting point. customize it for your workflow. add your own tests. make it yours.

good luck and happy hunting 🐺

---

**stats:**
- 2,645 lines of code
- 19 vulnerability tests
- 1000+ nuclei templates
- 3 output formats
- 0 api keys needed
- $0 cost
- 100% open source

**github:** https://github.com/yourusername/dark-wxlf

**made with 💀 by GhxstSh3ll**
