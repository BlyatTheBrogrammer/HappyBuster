"""
HappyBuster Toolkit - A Modular Python Security Toolkit
Usage: python happybuster.py <command> [options]

Commands:
    tS          TCP port scanner
    eN          Subdomain enumerator
    bG          Banner grabber
    dF          Directory fuzzer
    hsh         Hash identifier & cracker
    inf         Network information gatherer
    analyze     AI vulnerability analysis
    prioritize  AI target prioritization
    suggest     AI exploit suggestions
"""

# Importing the main libraries (pentesting)
import argparse
import socket
import sys
import os
from modules.utils import banner, error, warn, Colors, c

# Importing the libraries for the LLM
from transformers import (
    AutoTokenizer,
    AutoModelForCausalLM,  
    pipeline,
    TextGenerationPipeline
)
import torch

banner_text = """
    ██╗  ██╗ █████╗ ██████╗ ██████╗ ██╗   ██╗
    ██║  ██║██╔══██╗██╔══██╗██╔══██╗╚██╗ ██╔╝
    ███████║███████║██████╔╝██████╔╝ ╚████╔╝ 
    ██╔══██║██╔══██║██╔═══╝ ██╔══██╗  ╚██╔╝  
    ██║  ██║██║  ██║██║     ██████╔╝   ██║   
    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═════╝    ╚═╝   
                                             
    HappyBuster Toolkit - Python Modular Security Toolkit
"""

print(banner_text)

# ============================================================================
# COMMAND HANDLERS
# ============================================================================

def cmd_tS(args):
    """TCP Port Scanner"""
    from modules.port_scanner import scan
    scan(
        host=args.target,
        port_range=args.ports,
        timeout=args.timeout,
        concurrency=args.concurrency,
        output_json=args.output,
    )
    return None

def cmd_eN(args):
    """Subdomain Enumerator"""
    from modules.subdomain_enum import enumerate_subdomains
    wordlist = None 
    if args.wordlist:
        with open(args.wordlist) as f:
            wordlist = [l.strip() for l in f if l.strip()]
    
    enumerate_subdomains(
        domain=args.target,
        wordlist=wordlist,
        threads=args.threads,
        output_json=args.output,
    )
    return None

def cmd_bG(args):
    """Banner Grabber"""
    from modules.banner_grabber import grab
    if args.ports:
        ports = []
        for part in args.ports.split(","):
            part = part.strip()
            if "-" in part:
                lo, hi = part.split("-", 1)
                ports.extend(range(int(lo), int(hi) + 1))
            else:
                ports.append(int(part))
    else:
        ports = [17, 20, 21, 22, 25, 32, 37, 45, 49, 53, 80, 110, 143, 443, 3306, 5432, 6379, 8080, 27017]
    
    grab(
        host=args.target,
        ports=ports,
        timeout=args.timeout,
        workers=args.threads,
        output_json=args.output,
    )
    return None

def cmd_dF(args):
    """Directory Fuzzer"""
    from modules.dir_fuzzer import fuzz
    wordlist = None 
    if args.wordlist:
        with open(args.wordlist) as f:
            wordlist = [l.strip() for l in f if l.strip()]
        
        exts = args.extensions.split(",") if args.extensions else None 
        fuzz(
            url=args.target,
            wordlist=wordlist,
            threads=args.threads,
            timeout=args.timeout,
            output_json=args.output,
        )
    return None  

def cmd_hsh(args):
    """Hash Identifier & Cracker"""
    from modules.hash_tools import analyze
    analyze(
        hash_str=args.hash,
        wordlist_path=args.wordlist,
        crack_it=not args.no_crack,
        output_json=args.output,
    )
    return None

def cmd_inf(args):
    """Network Information Gatherer"""
    from modules.network_info import gather
    gather(
        target=args.target,
        do_whois=not args.no_whois,
        do_geo=not args.no_geo,
        do_headers=not args.no_headers,  
        output_json=args.output,
    )
    return None

# ============================================================================
# LLM ANALYZER CLASS
# ============================================================================

class LLMAnalyzer:
    def __init__(self, model_name="distilgpt2", device=None):
        """Initialize local LLM without API"""
        
        if device is None:
            self.device = "cuda" if torch.cuda.is_available() else "cpu"
        else:
            self.device = device

        print(f"[*] Loading model: {model_name} on {self.device}")

        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForCausalLM.from_pretrained(
            model_name,
            torch_dtype=torch.float32,
            device_map="auto" if self.device == "cuda" else None
        ).to(self.device)

        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token

        self.generator = pipeline(
            "text-generation",
            model=self.model,
            tokenizer=self.tokenizer,
            device=0 if self.device == "cuda" else -1
        )

        print(f"[+] Model loaded successfully")

    def analyze_vulnerability(self, scan_result, max_length=150):
        """Analyze vulnerability from scan results"""
        prompt = f"""
You are an expert Application Security Engineer and Vulnerability Triage Specialist. 
Analyze the following raw vulnerability scan result and provide a structured, professional assessment.

### Input Data:
{scan_result}

### Required Output Format:
1. **Vulnerability Identification & Classification**
   - **Identifier:** (e.g., CVE, CWE ID)
   - **Severity Rating:** (Critical/High/Medium/Low) based on CVSS v3.1/v4.0

2. **Technical Description & Impact Analysis**
   - Root cause explanation
   - Potential business and technical impact

3. **Attack Vector & Feasibility**
   - Conditions required to trigger vulnerability
   - Conceptual attack mechanism

4. **Remediation & Mitigation Strategy**
   - Primary Fix: Actionable steps
   - Compensating Controls: Short-term mitigations

5. **Testing & Verification**
   - How to verify the fix
   - Recommended testing methodology

6. **References & Standards**
   - CVE/CWE databases
   - Security frameworks (OWASP, NIST)

### Analysis:
"""
        try:
            result = self.generator(
                prompt,
                max_length=max_length,
                num_return_sequences=1,
                temperature=0.7,
                do_sample=True,
                truncation=True
            )
            return result[0]['generated_text'].split("Analysis:")[-1].strip()
        except Exception as e:
            return f"Error analyzing: {str(e)}"
        
    def prioritize_targets(self, targets_list, max_length=200):
        """Rank targets by security risk"""
        prompt = f"""
You are a Senior Penetration Testing Consultant specializing in threat assessment.

### TASK: Conduct Risk-Based Target Prioritization Analysis

### INPUT DATA:
Discovered Targets/Services:
{targets_list}

### ANALYSIS FRAMEWORK:
1. CVSS v3.1 Score Estimation
2. Attack Surface Assessment
3. Business Impact Potential
4. Exploitation Complexity
5. Lateral Movement Risk

### REQUIRED OUTPUT FORMAT:

**PRIORITY RANKING:**

**[RANK 1 - CRITICAL]**
- Target: [hostname/service]
- Risk Score: [1-10]
- Primary Vulnerabilities: [List likely CVEs]
- Attack Surface: [Network exposure, auth requirements]
- Business Impact: [Data at risk, criticality]
- Exploitation Feasibility: [Easy/Medium/Hard]
- Recommended Assessment Approach: [Testing methodology]

**[RANK 2 - HIGH]** / **[RANK 3 - MEDIUM]**
[Same format...]

### EXPLOITATION SEQUENCING:
Strategic order for testing that maximizes efficiency and enables pivoting

### STRATEGIC RECOMMENDATIONS:
- Simultaneous vs. sequential testing
- Time allocation per target
- Key dependencies

### Ranking:
"""
        try:
            result = self.generator(
                prompt,
                max_length=max_length,
                num_return_sequences=1,
                temperature=0.7,
                do_sample=True,
                truncation=True
            )
            return result[0]['generated_text'].split('Ranking:')[-1].strip()
        except Exception as e:
            return f"Error ranking: {str(e)}"
    
    def suggest_exploits(self, service_info, max_length=200):
        """Suggest exploits for discovered services"""
        prompt = f"""
You are a Certified Ethical Hacker and Vulnerability Research Specialist.

### TASK: Comprehensive Vulnerability & Exploit Analysis

### INPUT DATA:
Target Service Information:
{service_info}

### ANALYSIS FRAMEWORK:
1. Known CVE Database Analysis
2. CWE Classification
3. CVSS Risk Scoring
4. Exploitation Likelihood
5. Required Conditions

### REQUIRED OUTPUT FORMAT:

**VULNERABILITY ASSESSMENT REPORT:**

**[VULNERABILITY 1]**
- CVE/Identifier: [CVE-XXXX-XXXXX or CWE-XXX]
- Service/Component: [Affected software]
- Severity: [Critical/High/Medium/Low + CVSS Score]
- Root Cause: [Technical explanation]
- Attack Vector: [Network/Local/Physical + complexity]
- Impact Assessment: [Confidentiality/Integrity/Availability]
- Exploitation Status: [PoC/In-the-wild/Theoretical]
- Affected Versions: [Version range]

### EXPLOITATION METHODOLOGY:
1. Reconnaissance Phase
2. Exploitation Phase (conceptual, not step-by-step)
3. Post-Exploitation

### RECOMMENDED ASSESSMENT TOOLS:
- Scanning tools
- Exploitation frameworks
- Validation methods

### DEFENSIVE RECOMMENDATIONS:
- Immediate Actions
- Long-term Hardening
- Detection Methods
- Monitoring

### ETHICAL GUIDELINES:
**IMPORTANT:** This analysis is for AUTHORIZED SECURITY TESTING ONLY.
- Explicit written permission from system owner required
- Responsible disclosure practices
- No unauthorized testing

### Suggestions:
"""
        try:
            result = self.generator(
                prompt,
                max_length=max_length,
                num_return_sequences=1,
                temperature=0.7,
                do_sample=True,
                truncation=True
            )
            return result[0]['generated_text'].split("Suggestions:")[-1].strip()
        except Exception as e:
            return f"Error suggesting: {str(e)}"

# ============================================================================
# LLM COMMAND HANDLERS
# ============================================================================

def cmd_analyze(args):
    """AI Vulnerability Analysis"""
    if args.file:
        with open(args.file) as f:
            scan_result = f.read()
    else:
        scan_result = args.input

    llm = LLMAnalyzer()
    analysis = llm.analyze_vulnerability(scan_result)

    print("\n[*] AI Vulnerability Analysis:\n")
    print(analysis)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(analysis)

def cmd_prioritize(args):
    """AI Target Prioritization"""
    if args.file:
        with open(args.file) as f:
            targets = f.read()
    else:
        targets = args.targets

    llm = LLMAnalyzer()
    prioritization = llm.prioritize_targets(targets)

    print("\n[*] AI Target Prioritization:\n")
    print(prioritization)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(prioritization)

def cmd_suggest(args):
    """AI Exploit Suggestions"""
    llm = LLMAnalyzer()
    suggestions = llm.suggest_exploits(args.service)

    print("\n[*] AI Exploit Suggestions:\n")
    print(suggestions)

    if args.output:
        with open(args.output, 'w') as f:
            f.write(suggestions)

# ============================================================================
# ARGUMENT PARSER
# ============================================================================

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="happybuster",
        description=c("HappyBuster - Python Modular Security Toolkit", Colors.GREEN),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{c('Examples:', Colors.RED)}
  {c('python3 happybuster.py tS', Colors.GREEN)} example.com --ports 1-1000 
  {c('python3 happybuster.py eN', Colors.GREEN)} example.com --threads 100
  {c('python3 happybuster.py bG', Colors.GREEN)} xxx.xxx.xxx.xxx --ports 22,80,443
  {c('python3 happybuster.py dF', Colors.GREEN)} http://example.com -e .php,.bak
  {c('python3 happybuster.py hsh', Colors.GREEN)} 5fgf5234g32523hfhfsa7884jh
  {c('python3 happybuster.py inf', Colors.GREEN)} example.com
  {c('python3 happybuster.py analyze', Colors.GREEN)} -i "SQL injection found" -o report.txt
  {c('python3 happybuster.py prioritize', Colors.GREEN)} "nginx,mysql,ssh" -o priority.txt
  {c('python3 happybuster.py suggest', Colors.GREEN)} "nginx 1.24.0" -o exploits.txt

{c('ALWAYS USE ON SYSTEMS YOU OWN OR WHERE YOU HAVE PERMISSION TO TEST.', Colors.YELLOW)}
{c('All scanning and exploitation must be AUTHORIZED.', Colors.YELLOW)}
""",
    )
    
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # TCP Port Scanner
    p_tS = sub.add_parser("tS", help="TCP port scanner")
    p_tS.add_argument("target", help="Target host/IP")
    p_tS.add_argument("-p", "--ports", default="1-2024", help="Port range (e.g. 1-65535 or 80,443,8080)")
    p_tS.add_argument("-t", "--timeout", type=float, default=1.0, help="Connection timeout (default 1.0s)")
    p_tS.add_argument("-c", "--concurrency", type=int, default=500, help="Concurrent connections (default 500)")
    p_tS.add_argument("-o", "--output", help="Save results to JSON file")

    # Subdomain Enumerator
    p_eN = sub.add_parser("eN", help="Subdomain enumerator")
    p_eN.add_argument("target", help="Target domain (e.g. example.com)")
    p_eN.add_argument("-w", "--wordlist", help="Custom wordlist file")
    p_eN.add_argument("-T", "--threads", type=int, default=50, help="Threads (default 50)")
    p_eN.add_argument("-o", "--output", help="Save results to JSON file")

    # Banner Grabber
    p_bG = sub.add_parser("bG", help="Service banner grabber")
    p_bG.add_argument("target", help="Target host/IP")
    p_bG.add_argument("-p", "--ports", help="Ports to probe (e.g. 22,80,443 or 1-1024)")
    p_bG.add_argument("-t", "--timeout", type=float, default=3.0, help="Socket timeout (default 3.0s)")
    p_bG.add_argument("-T", "--threads", type=int, default=20, help="Threads (default 20)")
    p_bG.add_argument("-o", "--output", help="Save results to JSON file")

    # Directory Fuzzer
    p_dF = sub.add_parser("dF", help="Directory/file fuzzer")
    p_dF.add_argument("target", help="Target URL (e.g. http://example.com)")
    p_dF.add_argument("-w", "--wordlist", help="Custom wordlist file")
    p_dF.add_argument("-e", "--extensions", help="File extensions (e.g. .php,.bak,.txt)")
    p_dF.add_argument("-T", "--threads", type=int, default=30, help="Threads (default 30)")
    p_dF.add_argument("-t", "--timeout", type=float, default=5.0, help="Request timeout (default 5.0s)")
    p_dF.add_argument("-o", "--output", help="Save results to JSON file")
    
    # Hash Identifier & Cracker
    p_hsh = sub.add_parser("hsh", help="Hash identifier & cracker")
    p_hsh.add_argument("hash", help="Hash to analyze/crack")
    p_hsh.add_argument("-w", "--wordlist", help="Wordlist for cracking")
    p_hsh.add_argument("--no-crack", action="store_true", help="Skip cracking attempt")
    p_hsh.add_argument("-o", "--output", help="Save results to JSON file")

    # Network Information Gatherer
    p_inf = sub.add_parser("inf", help="Network information gatherer")
    p_inf.add_argument("target", help="Target domain, hostname, or IP")
    p_inf.add_argument("--no-whois", action="store_true", help="Skip WHOIS lookup")
    p_inf.add_argument("--no-geo", action="store_true", help="Skip IP geolocation")
    p_inf.add_argument("--no-headers", action="store_true", help="Skip HTTP header fetch")
    p_inf.add_argument("-o", "--output", help="Save results to JSON file")

    # AI Analysis
    p_analyze = sub.add_parser("analyze", help="AI vulnerability analysis")
    p_analyze.add_argument("-i", "--input", help="Vulnerability description")
    p_analyze.add_argument("-f", "--file", help="Read scan results from file")
    p_analyze.add_argument("-o", "--output", help="Save analysis to file")

    # AI Prioritization
    p_prioritize = sub.add_parser("prioritize", help="AI target prioritization")
    p_prioritize.add_argument("targets", nargs="?", help="Target list")
    p_prioritize.add_argument("-f", "--file", help="Read targets from file")
    p_prioritize.add_argument("-o", "--output", help="Save prioritization to file")

    # AI Exploit Suggestions
    p_suggest = sub.add_parser("suggest", help="AI exploit suggestions")
    p_suggest.add_argument("service", help="Service name/version")
    p_suggest.add_argument("-o", "--output", help="Save suggestions to file")

    return parser

# ============================================================================
# ENTRY POINT
# ============================================================================

def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)
    
    handlers = {
        "tS": cmd_tS,
        "eN": cmd_eN,
        "bG": cmd_bG,
        "dF": cmd_dF,
        "hsh": cmd_hsh,
        "inf": cmd_inf,
        "analyze": cmd_analyze,
        "prioritize": cmd_prioritize,
        "suggest": cmd_suggest,
    }

    try:
        handlers[args.command](args)
    except KeyboardInterrupt:
        print()
        warn("Interrupted by user")
        sys.exit(0)
    except Exception as e:
        error(f"Unexpected error: {e}")
        if os.getenv("HappyBuster_DEBUG"):
            raise
        sys.exit(1)

if __name__ == "__main__":
    main()