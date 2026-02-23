# 🧠 NeuroSploit

> **AI-Powered Red Team Assistant for Recon & Attack Surface Analysis**

NeuroSploit is a CLI tool built for bug bounty hunters and red teamers. It uses local Large Language Models (LLMs) like **Mistral**, **Phi**, or any model supported by **Ollama** to analyze recon data and suggest possible vulnerabilities, attack vectors, and misconfigurations — offline and securely.

---

## 🚀 Features

- 🕵️ Recon data input (single domain or list)
- 🤖 LLM-based vulnerability analysis
- 🧠 Suggests IDOR, XSS, SSTI, backup leaks, misconfig, etc.
- 🧪 Streamlined recon flow built for real-world bug bounty testing
- 🔒 Offline, no OpenAI API key needed (uses Ollama & local models)
- ⚡️ Fast CLI interface with loading effects and ASCII banners

---

## 📸 Preview

> Startup banner:
(venv) [harishragavkamalinux] neurosploit$ neurosploit
```
    _   __                     _____       __      _ __
   / | / /__  __  ___________ / ___/____  / /___  (_) /_
  /  |/ / _ \/ / / / ___/ __ \\__ \/ __ \/ / __ \/ / __/
 / /|  /  __/ /_/ / /  / /_/ /__/ / /_/ / / /_/ / / /_  
/_/ |_/\___/\__,_/_/   \____/____/ .___/_/\____/_/\__/  
                                /_/
  ```
By Kamalesh  |  AI Recon Assistant
============================================================

---

## ⚙️ Installation

### 1. Clone the Repository 
``` bash
git clone https://github.com/iharishragav/neurosploit.git
cd neurosploit
```
### 2. Create a Virtual Environment(to avaoid package collapse)
```bash
python -m venv venv
source venv/bin/activate
```

### 3. Install Requirements
```bash
pip install -r requirements.txt
```
### 4. Run Ollama with Local LLM
Install and run a model:

```bash
ollama serve
ollama run phi
/*ollama run mistral
ollama run gemma        # choose alternate model if prefer higher accuracy 
ollama llama3.2*/
```
🧪 Usage
```bash
python cli.py
```
### 5.build pkg and run
from root dir(..\neurospoit)
```
pip install .
neurosploit 

```

Then follow the prompt:

(1) Single domain or (2) List of domains?
It reads:

data/urls.txt → recon inputs

prompts/analysis_prompt.txt → AI instruction

And sends the combined prompt to your local LLM API at http://localhost:11434.

📦 Directory Structure:
------------ -----------  

neurosploit/
├── cli.py
├── __init__.py
├── core.py
├── prompts/
│   └── analysis_prompt.txt
├── data/
│   └── urls.txt
├── requirements.txt
└── README.md

🧠 Sample Prompt (LLM):
--------- -------------
You're a professional red team assistant. Based on the input recon data, provide possible vulnerabilities, misconfigurations, or attack strategies.

Analyze the input for security issues and suggest realistic attack techniques such as:
- IDOR
- SSTI
- XSS
- Misconfigurations
- Directory traversal
- Backup file exposure

Respond only with practical, legal advice for bug bounty hunters.

📌 Credits:
------------
Built by Kamalesh (iharishragav)

Inspired by real-world bug bounty recon paths

Powered by Ollama and open-source LLMs
