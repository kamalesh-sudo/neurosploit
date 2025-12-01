import os
import sys
import time
import json
import requests
from termcolor import colored
import pyfiglet
from .core import run_enhanced_recon, run_mock_recon, build_ai_prompt
import threading
import itertools
from datetime import datetime
import urllib3
import subprocess
import requests
import time
import socket
from .attacksurface_engine import AttackSurfaceEngine

def is_ollama_running(host='localhost', port=11434):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        return sock.connect_ex((host, port)) == 0

def start_ollama_server():
    print("🚀 Starting Ollama server...")
    try:
        subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(5)  # Wait a bit for the server to start
        if is_ollama_running():
            print("✅ Ollama server started.")
        else:
            print("❌ Failed to start Ollama server.")
    except FileNotFoundError:
        print("❌ 'ollama' not found. Please install Ollama: https://ollama.com")

# --- Main Execution Flow ---



urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def loading_effect(text):
    """Animated text loading effect"""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(0.002)
    print()

def print_banner():
    """Display NeuroSploit banner"""
    banner = colored(pyfiglet.figlet_format("NeuroSploit", font="slant"), 'red')
    loading_effect(banner)
    print(colored("By Harish Ragav  |  AI-Powered Reconnaissance Tool", 'yellow'))
    print(colored("Version 2.0 - Enhanced with Real Subdomain Enumeration", 'green'))
    print(colored("=" * 70, 'cyan'))

def select_execution_mode():
    print("\n" + colored("🧠 SELECT ENGINE:", 'cyan', attrs=['bold']))
    print("1. Classic Reconnaissance")
    print("2. Attack Surface Engine (triage mode)")
    choice = input(colored("\n> Choose engine (1-2): ", 'yellow')).strip()
    return 'attack_surface' if choice == '2' else 'recon'

def get_targets():
    """Get target domains from user input"""
    print("\n" + colored("📋 SELECT INPUT METHOD:", 'cyan', attrs=['bold']))
    print("1. 🎯 Single domain")
    print("2. 📁 Multiple domains (from file)")
    print("3. 🔍 Interactive domain entry")
    
    choice = input(colored("\n> Choose option (1-3): ", 'yellow')).strip()
    
    targets = []
    if choice == "1":
        domain = input(colored("Enter domain (e.g., example.com): ", 'green')).strip()
        if domain:
            targets = [domain]

    elif choice == "2":
        path = input(colored("Enter file name (file should be in neurosploit/neurosploit/data/*) or enter full path :  ", 'green')).strip()

        # If no path separators, treat as filename in home directory
        if not os.path.sep in path:
            path = os.path.expanduser(f"~/neurosploit/neurosploit/data/{path}")
        else:
            path = os.path.expanduser(path)

        if os.path.exists(path):
            with open(path, "r") as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            print(colored(f"✅ Loaded {len(targets)} domains from: {path}", 'green'))
        else:
            print(colored(f"❌ File not found: {path}", 'red'))
            return []

 
    elif choice == "3":
        print(colored("Enter domains (one per line, empty line to finish):", 'green'))
        while True:
            domain = input("Domain: ").strip()
            if not domain:
                break
            targets.append(domain)
    else:
        print(colored("❌ Invalid choice.", 'red'))
        return []
    
    return targets

def select_scan_mode():
    """Select reconnaissance mode"""
    print("\n" + colored("🔧 SELECT SCAN MODE:", 'cyan', attrs=['bold']))
    print("1. 🚀 Quick scan (Mock data - Fast)")
    print("2. 🔍 Full reconnaissance (Real data - Slower)")
    print("3. 🎯 Custom scan (Choose options)")
    
    choice = input(colored("\n> Choose scan mode (1-3): ", 'yellow')).strip()
    
    scan_config = {
        'mode': 'mock',
        'threads': 50,
        'timeout': 5,
        'save_results': True
    }
    
    if choice == "1":
        scan_config['mode'] = 'mock'
        print(colored("✅ Quick scan mode selected", 'green'))
    elif choice == "2":
        scan_config['mode'] = 'full'
        print(colored("✅ Full reconnaissance mode selected", 'green'))
    elif choice == "3":
        scan_config['mode'] = 'full'
        # Custom options
        try:
            threads = input(colored("Number of threads (default: 50): ", 'green')).strip()
            scan_config['threads'] = int(threads) if threads else 50
            
            timeout = input(colored("Timeout in seconds (default: 5): ", 'green')).strip()
            scan_config['timeout'] = int(timeout) if timeout else 5
            
            save = input(colored("Save results to file? (y/n, default: y): ", 'green')).strip().lower()
            scan_config['save_results'] = save != 'n'
        except ValueError:
            print(colored("⚠️  Invalid input, using defaults", 'yellow'))
    else:
        print(colored("❌ Invalid choice, using quick scan", 'red'))
    
    return scan_config

def progress_bar(current, total, bar_length=40):
    """Display progress bar"""
    fraction = current / total
    filled_length = int(bar_length * fraction)
    bar = '█' * filled_length + '-' * (bar_length - filled_length)
    percent = round(100 * fraction, 1)
    return f'|{bar}| {percent}% ({current}/{total})'

def run_reconnaissance(domain, scan_config):
    """Run reconnaissance on a single domain"""
    print(colored(f"\n🎯 Starting reconnaissance on: {domain}", 'cyan', attrs=['bold']))
    print(colored("-" * 60, 'cyan'))
    
    start_time = time.time()
    
    try:
        if scan_config['mode'] == 'mock':
            # Quick mock scan
            recon_data = run_mock_recon(domain)
        else:
            # Full reconnaissance
            from .core import NeuroRecon
            recon = NeuroRecon(domain, 
                             threads=scan_config['threads'], 
                             timeout=scan_config['timeout'])
            recon_data = recon.run_full_recon()
        
        end_time = time.time()
        scan_time = round(end_time - start_time, 2)
        
        # Display results summary
        print(colored(f"\n✅ Reconnaissance completed in {scan_time} seconds", 'green'))
        print(colored(f"📊 Total subdomains found: {recon_data.get('total_subdomains_found', 0)}", 'green'))
        print(colored(f"🌐 Live subdomains: {recon_data.get('live_subdomains_count', 0)}", 'green'))
        
        # Save results if requested
        if scan_config['save_results']:
            save_results(domain, recon_data)
        
        return recon_data
        
    except KeyboardInterrupt:
        print(colored("\n⚠️  Scan interrupted by user", 'yellow'))
        return None
    except Exception as e:
        print(colored(f"\n❌ Error during reconnaissance: {e}", 'red'))
        return None

def save_results(domain, recon_data):
    """Save reconnaissance results to file"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"results_{domain}_{timestamp}.json"
    
    try:
        # Create results directory if it doesn't exist
        results_dir = "results"
        if not os.path.exists(results_dir):
            os.makedirs(results_dir)
        
        filepath = os.path.join(results_dir, filename)
        with open(filepath, 'w') as f:
            json.dump(recon_data, f, indent=2, default=str)
        
        print(colored(f"💾 Results saved to: {filepath}", 'green'))
    except Exception as e:
        print(colored(f"⚠️  Could not save results: {e}", 'yellow'))

def display_detailed_results(recon_data):
    """Display detailed reconnaissance results"""
    print(colored("\n📋 DETAILED RESULTS:", 'cyan', attrs=['bold']))
    print(colored("=" * 50, 'cyan'))
    
    # Live subdomains
    live_subs = recon_data.get('live_subdomains', [])
    if live_subs:
        print(colored("\n🌐 LIVE SUBDOMAINS:", 'green', attrs=['bold']))
        for i, sub in enumerate(live_subs[:10], 1):  # Show first 10
            status_color = 'green' if sub.get('status_code', 0) == 200 else 'yellow'
            print(f"{i:2d}. {colored(sub.get('subdomain', ''), 'white', attrs=['bold'])}")
            print(f"    Status: {colored(sub.get('status_code', 'Unknown'), status_color)}")
            print(f"    Server: {sub.get('server', 'Unknown')}")
            print(f"    Protocol: {sub.get('protocol', 'Unknown').upper()}")
            if sub.get('technology'):
                print(f"    Tech: {', '.join(sub['technology'][:3])}")  # Show first 3 technologies
            print()
    
    # Security issues
    security_issues = recon_data.get('summary', {}).get('security_issues', [])
    if security_issues:
        print(colored("⚠️  SECURITY ISSUES:", 'red', attrs=['bold']))
        for issue in security_issues[:5]:  # Show first 5
            print(f"• {colored(issue.get('subdomain', 'Unknown'), 'white')}")
            for problem in issue.get('issues', []):
                print(f"  - {colored(problem, 'red')}")
        print()

def spinner_animation(message="Processing"):
    """Spinner animation for loading"""
    def spin():
        for c in itertools.cycle(['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏']):
            if not loading:
                break
            sys.stdout.write(f'\r{colored(message, "cyan")} {c}')
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write('\r' + ' ' * (len(message) + 10) + '\r')
    
    global loading
    loading = True
    t = threading.Thread(target=spin)
    t.start()
    return t

def get_ai_analysis(prompts, model="phi"):
    """Get AI analysis from local Ollama instance"""
    print(colored("\n🧠 AI ANALYSIS:", 'cyan', attrs=['bold']))
    print(colored("-" * 30, 'cyan'))
    
    # Model selection
    available_models = ["phi", "mistral", "gemma", "llama3.2"]
    if model not in available_models:
        print(colored(f"Available models: {', '.join(available_models)}", 'yellow'))
        model = input(colored(f"Choose AI model (default: phi): ", 'green')).strip() or "phi"
    
    # Prepare complete prompt
    final_prompt = "\n\n".join(prompts)
    
    # Try to load base prompt from file
    try:
        prompt_path = os.path.join(os.path.dirname(__file__), "prompts", "analysis_prompt.txt")
        with open(prompt_path, "r") as f:
            base_prompt = f.read()
        complete_prompt = base_prompt + "\n\n" + final_prompt
    except FileNotFoundError:
        complete_prompt = final_prompt
        print(colored("⚠️  Base prompt file not found, using generated prompt only", 'yellow'))
    
    # Start spinner
    spinner_thread = spinner_animation("🧠 AI is analyzing the reconnaissance data")
    
    start_time = time.time()
    
    try:
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": model, 
                "prompt": complete_prompt, 
                "stream": False,
                "options": {
                    "temperature": 0.7,
                    "top_p": 0.9,
                    "max_tokens": 2000
                }
            },
            timeout=300  # 5 minutes timeout
        )
        
        global loading
        loading = False
        spinner_thread.join()
        
        end_time = time.time()
        analysis_time = round(end_time - start_time, 2)
        
        if response.status_code == 200:
            result = response.json()
            print(colored(f"✅ AI analysis completed in {analysis_time} seconds", 'green'))
            print(colored("🎯 AI RECOMMENDATIONS:", 'cyan', attrs=['bold']))
            print(colored("=" * 50, 'cyan'))
            print(result.get("response", "No response received"))
            return result.get("response")
        else:
            print(colored(f"❌ AI service error: {response.status_code}", 'red'))
            return None
            
    except requests.exceptions.ConnectionError:
        loading = False
        spinner_thread.join()
        print(colored("\n❌ Could not connect to Ollama. Make sure it's running:", 'red'))
        print(colored("   ollama serve", 'yellow'))
        return None
    except requests.exceptions.Timeout:
        loading = False
        spinner_thread.join()
        print(colored("\n⏰ AI analysis timed out", 'yellow'))
        return None
    except Exception as e:
        loading = False
        spinner_thread.join()
        print(colored(f"\n❌ Error during AI analysis: {e}", 'red'))
        return None

def main():
    """Main CLI function"""
    try:
        # Display banner
        print_banner()
        if not is_ollama_running():
            start_ollama_server()
        else:
            print("✅ Ollama already running.")
        
        mode = select_execution_mode()
        if mode == 'attack_surface':
            run_attack_surface_mode()
        else:
            run_recon_mode()
        
    except KeyboardInterrupt:
        print(colored("\n\n👋 Goodbye! Stay safe in the digital realm.", 'yellow'))
        sys.exit(0)
    except Exception as e:
        print(colored(f"\n❌ Unexpected error: {e}", 'red'))
        sys.exit(1)

def run_recon_mode():
    targets = get_targets()
    if not targets:
        print(colored("❌ No targets specified. Exiting.", 'red'))
        return
    
    scan_config = select_scan_mode()
    
    all_results = []
    all_prompts = []
    
    total_targets = len(targets)
    for i, domain in enumerate(targets, 1):
        print(colored(f"\n📊 Progress: {progress_bar(i-1, total_targets)}", 'cyan'))
        
        recon_data = run_reconnaissance(domain, scan_config)
        if recon_data:
            all_results.append(recon_data)
            
            if len(targets) == 1:
                display_detailed_results(recon_data)
            
            ai_prompt = build_ai_prompt(domain, recon_data)
            all_prompts.append(ai_prompt)
    
    print(colored(f"\n📊 Progress: {progress_bar(total_targets, total_targets)}", 'cyan'))
    
    if not all_prompts:
        print(colored("❌ No successful reconnaissance results. Exiting.", 'red'))
        return
    
    ai_choice = input(colored("\n🤖 Run AI analysis? (y/n, default: y): ", 'green')).strip().lower()
    if ai_choice != 'n':
        model = input(colored("Choose AI model [phi/mistral/gemma/llama3.2] (default: phi): ", 'green')).strip() or "phi"
        get_ai_analysis(all_prompts, model)
    
    print(colored("\n✅ NeuroSploit reconnaissance completed!", 'green', attrs=['bold']))



def run_attack_surface_mode():
    target = input(colored("\nEnter target URL or domain: ", 'green')).strip()
    if not target:
        print(colored("❌ No target provided.", 'red'))
        return
    print(colored("\n🚀 Running Attack Surface Engine...", 'cyan'))
    try:
        engine = AttackSurfaceEngine(target)
        result = engine.run_full_analysis()
        display_attack_surface_results(result)
    except Exception as exc:
        print(colored(f"❌ Attack surface analysis failed: {exc}", 'red'))


def display_attack_surface_results(result):
    print(colored("\n🧱 BACKEND FINGERPRINT:", 'yellow', attrs=['bold']))
    backend = result.backend_fingerprint
    print(f"Backend: {backend.get('backend', 'Unknown')} (confidence {backend.get('confidence')})")
    print(f"Signals: {', '.join(backend.get('detected_from', [])) or 'None'}")

    print(colored("\n🔍 ENDPOINTS DISCOVERED:", 'yellow', attrs=['bold']))
    for endpoint in result.endpoint_extraction['endpoints'][:10]:
        print(f" - {endpoint}")
    print(f"Total filtered: {result.endpoint_extraction['metadata']['filtered']}")

    print(colored("\n🔐 SENSITIVE PARAMETERS:", 'yellow', attrs=['bold']))
    for param in result.parameter_discovery['sensitive_params'][:5]:
        print(f" - {param['param']} (score {param['score']})")

    print(colored("\n🎯 ATTACK SURFACE SUMMARY:", 'yellow', attrs=['bold']))
    for category, count in result.attack_surface['summary']['counts'].items():
        print(f" - {category}: {count}")

    print(colored("\n🔥 TOP RISKY ENDPOINTS:", 'red', attrs=['bold']))
    for item in result.risk_scores[:5]:
        reasons = ', '.join(item['high_risk_reason']) or 'heuristics'
        print(f" - {item['endpoint']} -> {item['risk_score']} ({reasons})")


if __name__ == "__main__":
    main()
