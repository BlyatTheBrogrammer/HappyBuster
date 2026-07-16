HappyBuster 🚀

A modular Python security toolkit for authorized penetration testing, vulnerability assessment, and security research.
⚠️ LEGAL DISCLAIMER

HappyBuster is designed for authorized security testing only.


✅ Use only on systems you own or have explicit written permission to test
✅ Follow all applicable laws and regulations in your jurisdiction
✅ Adhere to responsible disclosure practices
❌ Unauthorized access to computer systems is illegal
❌ This tool should never be used for malicious purposes


By using HappyBuster, you agree to use it legally and ethically.


🎯 Features

Core Security Tools

ToolCommandDescriptionTCP Port ScannertSFast multi-threaded port scanning with configurable rangesSubdomain EnumeratoreNDNS subdomain discovery using wordlist-based enumerationBanner GrabberbGService identification through banner/version detectionDirectory FuzzerdFWeb directory and file discovery with extension filteringHash AnalyzerhshHash identification and dictionary-based crackingOSINT GathererinfNetwork reconnaissance (WHOIS, GeoIP, HTTP headers)

AI-Powered Analysis (New!)

FeatureCommandDescriptionVulnerability AnalysisanalyzeAI-powered vulnerability assessment and remediation suggestionsTarget PrioritizationprioritizeRisk-based target ranking using CVSS scoringExploit SuggestionssuggestCVE identification and exploitation methodology


📋 Requirements


Python 3.8+
Libraries:


bash  pip install transformers torch requests beautifulsoup4 pycryptodome

Optional


GPU Support: CUDA/cuDNN for faster LLM processing
Kali Linux / Parrot OS: Recommended for security testing



🔧 Installation

1. Clone the Repository

bashgit clone https://github.com/yourusername/happybuster.git
cd happybuster

2. Install Dependencies

bashpip install -r requirements.txt

3. Verify Installation

bashpython3 happybuster.py --help


📖 Usage

General Syntax

bashpython3 happybuster.py <command> [options]

TCP Port Scanner

bash# Scan common ports (1-2024)
python3 happybuster.py tS 192.168.1.1

# Scan specific range with threads
python3 happybuster.py tS 192.168.1.1 -p 1-65535 -c 1000 -t 2.0

# Scan specific ports
python3 happybuster.py tS example.com -p 22,80,443,3306

# Save results to JSON
python3 happybuster.py tS 192.168.1.1 -o scan_results.json

Subdomain Enumeration

bash# Basic enumeration
python3 happybuster.py eN example.com

# With custom wordlist
python3 happybuster.py eN example.com -w /path/to/wordlist.txt

# Increase thread count
python3 happybuster.py eN example.com -T 200 -o subdomains.json

Banner Grabbing

bash# Default common ports
python3 happybuster.py bG 192.168.1.1

# Specific ports
python3 happybuster.py bG 192.168.1.1 -p 22,80,443,8080

# Custom timeout and threads
python3 happybuster.py bG example.com -p 1-1000 -t 5.0 -T 50 -o banners.json

Directory Fuzzing

bash# Fuzz with default wordlist
python3 happybuster.py dF http://example.com -w /path/to/wordlist.txt

# Add file extensions
python3 happybuster.py dF http://example.com -w wordlist.txt -e .php,.bak,.txt

# Aggressive scanning
python3 happybuster.py dF http://example.com -w wordlist.txt -T 100 -t 3.0

# Save results
python3 happybuster.py dF http://example.com -w wordlist.txt -o directories.json

Hash Cracking

bash# Identify hash type
python3 happybuster.py hsh 5d41402abc4b2a76b9719d911017c592 --no-crack

# Crack with wordlist
python3 happybuster.py hsh 5d41402abc4b2a76b9719d911017c592 -w /usr/share/wordlists/rockyou.txt

# Save results
python3 happybuster.py hsh 5d41402abc4b2a76b9719d911017c592 -w wordlist.txt -o hash_analysis.json

OSINT Information Gathering

bash# Full reconnaissance
python3 happybuster.py inf example.com

# Skip certain checks
python3 happybuster.py inf example.com --no-geo --no-whois

# Save structured output
python3 happybuster.py inf 8.8.8.8 -o recon.json

AI-Powered Vulnerability Analysis

bash# Analyze vulnerability description
python3 happybuster.py analyze -i "SQL injection found in login form"

# Analyze from file
python3 happybuster.py analyze -f scan_results.txt

# Save AI analysis
python3 happybuster.py analyze -i "Open SSH port 22" -o analysis.txt

AI Target Prioritization

bash# Rank targets by risk
python3 happybuster.py prioritize "nginx 1.24, MySQL 5.7, OpenSSH 9.6"

# Read from file
python3 happybuster.py prioritize -f targets.txt

# Save prioritized list
python3 happybuster.py prioritize "service1, service2" -o priority.txt

AI Exploit Suggestions

bash# Get exploit recommendations
python3 happybuster.py suggest "nginx 1.24.0"

# With specific service details
python3 happybuster.py suggest "OpenSSH 9.6p1 Ubuntu" -o exploits.txt


🧠 AI Features

HappyBuster integrates local LLM processing (via Hugging Face Transformers) for intelligent vulnerability analysis:

Models Used


Default: distilgpt2 (fast, lightweight)
Alternatives: gpt2, distilbert-base-uncased


Capabilities


Vulnerability Assessment: Severity rating, CVSS scoring, impact analysis
Target Prioritization: Risk-based ranking with exploitation strategies
Exploit Recommendations: CVE identification, attack vectors, remediation


GPU Acceleration

bash# GPU support requires
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118

🛠️ Configuration

Environment Variables

bash# Enable debug mode (prints full error tracebacks)
export HappyBuster_DEBUG=1
python3 happybuster.py tS example.com

# Specify LLM model
export HAPPYBUSTER_MODEL=gpt2
python3 happybuster.py analyze -i "vulnerability description"

Custom Wordlists

Place custom wordlists in wordlists/ directory or specify path:

bashpython3 happybuster.py eN example.com -w /path/to/custom/wordlist.txt


📊 Output Formats

JSON Output

All commands support JSON export:

bashpython3 happybuster.py tS 192.168.1.1 -o results.json

Example JSON Structure

json{
  "target": "192.168.1.1",
  "command": "tS",
  "timestamp": "2024-07-17T18:30:45Z",
  "results": {
    "open_ports": [22, 80, 443],
    "services": {
      "22": "OpenSSH 9.6p1",
      "80": "nginx 1.24.0",
      "443": "nginx (SSL/TLS)"
    }
  }
}


🔐 Security Best Practices


Authorization First

Always obtain written permission before testing
Maintain documentation of authorization
Scope testing to approved systems only



Network Segmentation

Test on isolated lab environments first
Use VPN when testing remote systems
Never test production without backup/disaster recovery



Responsible Disclosure

Report vulnerabilities to vendors/owners immediately
Allow reasonable time for patching before public disclosure
Follow CVE/CVSS guidelines



Tool Hardening

Run with minimal privileges (never sudo unless necessary)
Use firewall rules to limit outbound connections
Monitor tool output for accidental data leakage






🚀 Performance Tips

OptimizationMethodImpactFaster ScanningIncrease -c (concurrency)High - use 500-2000 for fast networksGPU AccelerationInstall CUDA/cuDNNHigh - 10-50x LLM speedupTargeted EnumerationUse smaller wordlists firstMedium - 80/20 rule appliesParallel FuzzingIncrease -T (threads)Medium - diminishing returns >100Early StoppingMonitor results in real-timeLow - but saves time


🐛 Troubleshooting

Issue: "Module not found: transformers"

bashpip install transformers torch

Issue: "Port already in use"

Use different LPORT:

bashpython3 happybuster.py tS 192.168.1.1 -c 100  # Reduce concurrency

Issue: "LLM takes too long to load"

Use faster model:

bashexport HAPPYBUSTER_MODEL=distilgpt2
python3 happybuster.py analyze -i "vulnerability"

Issue: CUDA not detected

bashpython3 -c "import torch; print(torch.cuda.is_available())"
# If False, install CPU-only torch or install CUDA


📚 Educational Resources

Recommended Reading


OWASP Top 10
NIST Cybersecurity Framework
Responsible Disclosure Guide


CTF Practice


HackTheBox - Use HappyBuster for reconnaissance
TryHackMe - Ethical hacking training
PortSwigger Web Security - Web vulnerabilities



🤝 Contributing

Contributions are welcome! Please:


Fork the repository
Create a feature branch (git checkout -b feature/amazing-feature)
Commit changes (git commit -m 'Add amazing feature')
Push to branch (git push origin feature/amazing-feature)
Open a Pull Request


Code Style


Follow PEP 8 guidelines
Add docstrings to all functions
Include error handling and logging
Test on multiple Python versions (3.8+)



📄 License

This project is licensed under the MIT License - see LICENSE file for details.

Third-Party Libraries


transformers - Apache 2.0 (Hugging Face)
torch - BSD (Facebook/Meta)
requests - Apache 2.0
beautifulsoup4 - MIT



⚖️ Disclaimer

HappyBuster is provided "as is" without warranty. Users are responsible for:


Understanding applicable laws in their jurisdiction
Obtaining proper authorization before testing
Using the tool ethically and legally
Consequences of misuse


Misuse of this tool for unauthorized access is illegal.


📞 Support & Contact


Issues: Report bugs via GitHub Issues
Discussions: Use GitHub Discussions for questions
Security: Report security issues to [security contact]



🙏 Acknowledgments


Hugging Face - Transformers library
OWASP - Security frameworks
HackTheBox - Inspiration for tool development
Security Research Community - Knowledge sharing



Made with ❤️ for ethical hackers and security professionals.
Created on 17jul 2026