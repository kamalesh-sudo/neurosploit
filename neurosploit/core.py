import asyncio
import json
import re
import socket
import ssl
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import dns.resolver
import requests
import urllib3

# Disable SSL warnings for reconnaissance purposes.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


LogCallback = Callable[[str], Optional[Awaitable[None]]]
ProgressCallback = Callable[[str, int, int, str], Optional[Awaitable[None]]]


@dataclass
class ScanConfig:
    mode: str = "full"
    max_concurrency: int = 40
    timeout: int = 5
    enable_ct_logs: bool = True
    enable_dns_bruteforce: bool = True
    enable_http_probe: bool = True
    enable_deep_analysis: bool = True
    enable_nmap: bool = False
    nmap_top_ports: int = 100

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ReconState:
    found_subdomains: Set[Tuple[str, str]] = field(default_factory=set)
    live_subdomains: List[Dict[str, Any]] = field(default_factory=list)


class AsyncNeuroRecon:
    """Async-first reconnaissance engine with progress hooks for TUI integration."""

    COMMON_PORTS = [80, 443, 21, 22, 25, 53, 110, 143, 993, 995]

    DEFAULT_SUBDOMAIN_WORDLIST = [
        "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
        "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns",
        "blog", "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3", "mail2",
        "new", "mysql", "old", "www1", "email", "img", "www3", "help", "shop", "secure",
        "download", "demo", "api", "app", "stage", "staging", "beta", "development", "prod",
        "production", "testing", "lab", "sandbox", "portal", "dashboard", "panel", "login",
    ]

    def __init__(
        self,
        domain: str,
        config: Optional[ScanConfig] = None,
        log_callback: Optional[LogCallback] = None,
        progress_callback: Optional[ProgressCallback] = None,
    ):
        self.domain = domain.strip().lower()
        self.config = config or ScanConfig()
        self.log_callback = log_callback
        self.progress_callback = progress_callback
        self.state = ReconState()

    async def _emit_log(self, message: str) -> None:
        if not self.log_callback:
            return
        maybe_awaitable = self.log_callback(message)
        if maybe_awaitable:
            await maybe_awaitable

    async def _emit_progress(self, phase: str, current: int, total: int, message: str) -> None:
        if not self.progress_callback:
            return
        maybe_awaitable = self.progress_callback(phase, current, total, message)
        if maybe_awaitable:
            await maybe_awaitable

    def load_subdomain_wordlist(self) -> List[str]:
        packaged_path = Path(__file__).resolve().parent / "data" / "subdomains.txt"
        file_words: List[str] = []
        if packaged_path.exists():
            file_words = [line.strip() for line in packaged_path.read_text().splitlines() if line.strip()]
        deduped = {word.lower() for word in self.DEFAULT_SUBDOMAIN_WORDLIST + file_words}
        return sorted(deduped)

    def _dns_bruteforce_blocking(self, subdomain: str) -> Optional[Tuple[str, str]]:
        full_domain = f"{subdomain}.{self.domain}"
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = self.config.timeout
            resolver.lifetime = self.config.timeout
            answers = resolver.resolve(full_domain, "A")
            ip = str(answers[0])
            return full_domain, ip
        except Exception:
            return None

    async def dns_bruteforce(self, subdomain: str) -> Optional[Tuple[str, str]]:
        return await asyncio.to_thread(self._dns_bruteforce_blocking, subdomain)

    def _crt_sh_enum_blocking(self) -> Set[Tuple[str, str]]:
        discovered: Set[Tuple[str, str]] = set()
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        headers = {
            "User-Agent": "Mozilla/5.0 (NeuroSploit Async Recon)",
            "Accept": "application/json",
        }
        response = requests.get(url, headers=headers, timeout=20, verify=False)
        if response.status_code != 200:
            return discovered

        try:
            certificates = response.json()
        except ValueError:
            return discovered

        for cert in certificates:
            name_value = cert.get("name_value", "")
            if not name_value:
                continue
            for entry in name_value.splitlines():
                clean = entry.strip().lower().lstrip("*.")
                if clean.endswith(f".{self.domain}") and "*" not in clean:
                    discovered.add((clean, "Unknown"))
        return discovered

    async def crt_sh_enum(self) -> Set[Tuple[str, str]]:
        try:
            return await asyncio.to_thread(self._crt_sh_enum_blocking)
        except Exception as exc:
            await self._emit_log(f"[crt.sh] lookup failed: {exc}")
            return set()

    def _extract_title(self, html: str) -> str:
        match = re.search(r"<title>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        if not match:
            return "No Title"
        return " ".join(match.group(1).split())[:160]

    def _detect_technology(self, headers: Dict[str, str], body_text: str) -> List[str]:
        tech: List[str] = []
        server = headers.get("Server", "").lower()
        content = body_text.lower()

        if "nginx" in server:
            tech.append("Nginx")
        elif "apache" in server:
            tech.append("Apache")
        elif "iis" in server:
            tech.append("IIS")

        powered_by = headers.get("X-Powered-By")
        if powered_by:
            tech.append(f"Powered by: {powered_by}")

        if "react" in content or "react-dom" in content:
            tech.append("React")
        if "angular" in content:
            tech.append("Angular")
        if "vue" in content:
            tech.append("Vue.js")
        if "wordpress" in content or "wp-content" in content:
            tech.append("WordPress")
        if "drupal" in content:
            tech.append("Drupal")
        if "joomla" in content:
            tech.append("Joomla")

        security_headers = ["X-Frame-Options", "X-Content-Type-Options", "Content-Security-Policy"]
        missing = [header for header in security_headers if header not in headers]
        if missing:
            tech.append(f"Missing security headers: {', '.join(missing)}")

        return tech

    def _probe_subdomain_blocking(self, subdomain: str, ip: str) -> Optional[Dict[str, Any]]:
        session = requests.Session()
        session.verify = False
        session.headers.update({"User-Agent": "Mozilla/5.0 (NeuroSploit Async Probe)"})

        for protocol in ("https", "http"):
            try:
                response = session.get(
                    f"{protocol}://{subdomain}",
                    timeout=self.config.timeout,
                    allow_redirects=True,
                )
                headers = dict(response.headers)
                tech_info = self._detect_technology(headers, response.text)
                return {
                    "subdomain": subdomain,
                    "ip": ip,
                    "status_code": response.status_code,
                    "protocol": protocol,
                    "title": self._extract_title(response.text),
                    "server": headers.get("Server", "Unknown"),
                    "technology": tech_info,
                    "response_time": response.elapsed.total_seconds(),
                    "content_length": len(response.content),
                }
            except Exception:
                continue
        return None

    async def check_subdomain_alive(self, subdomain_info: Tuple[str, str]) -> Optional[Dict[str, Any]]:
        subdomain, ip = subdomain_info
        return await asyncio.to_thread(self._probe_subdomain_blocking, subdomain, ip)

    def _port_scan_blocking(self, ip: str, ports: Sequence[int]) -> List[int]:
        open_ports: List[int] = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.settimeout(1.5)
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
            except Exception:
                pass
            finally:
                sock.close()
        return open_ports

    def _check_ssl_cert_blocking(self, domain: str) -> Optional[Dict[str, Any]]:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                    cert = secure_sock.getpeercert()
                    if not cert:
                        return None
                    return {
                        "issuer": cert.get("issuer"),
                        "subject": cert.get("subject"),
                        "serialNumber": cert.get("serialNumber"),
                        "notBefore": cert.get("notBefore"),
                        "notAfter": cert.get("notAfter"),
                    }
        except Exception:
            return None

    def _run_nmap_blocking(self, ip: str) -> Optional[Dict[str, Any]]:
        try:
            process = subprocess.run(
                ["nmap", "-Pn", f"--top-ports={self.config.nmap_top_ports}", ip],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except FileNotFoundError:
            return {"error": "nmap not installed"}
        except Exception as exc:
            return {"error": str(exc)}

        output = process.stdout or ""
        open_ports = []
        for line in output.splitlines():
            match = re.search(r"(\d+)/tcp\s+open\s+([\w\-]+)", line)
            if match:
                open_ports.append({"port": int(match.group(1)), "service": match.group(2)})

        return {
            "exit_code": process.returncode,
            "open_ports": open_ports,
            "snippet": "\n".join(output.splitlines()[:18]),
        }

    async def _bounded_run(
        self,
        phase: str,
        items: Iterable[Any],
        worker: Callable[[Any], Awaitable[Any]],
        concurrency: int,
        progress_prefix: str,
    ) -> List[Any]:
        item_list = list(items)
        total = len(item_list)
        if not item_list:
            await self._emit_progress(phase, 0, 0, f"{progress_prefix}: no items")
            return []

        semaphore = asyncio.Semaphore(max(concurrency, 1))

        async def run_one(item: Any) -> Any:
            async with semaphore:
                return await worker(item)

        tasks = [asyncio.create_task(run_one(item)) for item in item_list]
        results: List[Any] = []

        for current, task in enumerate(asyncio.as_completed(tasks), start=1):
            result = await task
            results.append(result)
            await self._emit_progress(phase, current, total, f"{progress_prefix}: {current}/{total}")

        return results

    async def _enrich_live_subdomain(self, subdomain_data: Dict[str, Any]) -> Dict[str, Any]:
        enriched = dict(subdomain_data)
        ip = enriched.get("ip")

        if ip and ip != "Unknown":
            ports = await asyncio.to_thread(self._port_scan_blocking, ip, self.COMMON_PORTS)
            enriched["open_ports"] = ports

            if self.config.enable_nmap:
                enriched["nmap"] = await asyncio.to_thread(self._run_nmap_blocking, ip)

        if enriched.get("protocol") == "https":
            enriched["ssl_cert"] = await asyncio.to_thread(self._check_ssl_cert_blocking, enriched["subdomain"])

        return enriched

    def get_technology_summary(self, live_subdomains: Sequence[Dict[str, Any]]) -> Dict[str, int]:
        summary: Dict[str, int] = {}
        for subdomain in live_subdomains:
            for tech in subdomain.get("technology", []):
                summary[tech] = summary.get(tech, 0) + 1
        return summary

    def identify_security_issues(self, live_subdomains: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
        issues: List[Dict[str, Any]] = []
        for subdomain in live_subdomains:
            flags: List[str] = []

            technology = subdomain.get("technology", [])
            if any("Missing security headers" in item for item in technology):
                flags.append("Missing security headers")

            if subdomain.get("protocol") == "http":
                flags.append("Using HTTP instead of HTTPS")

            title = str(subdomain.get("title", "")).lower()
            if any(word in title for word in ["admin", "login", "dashboard", "panel"]):
                flags.append("Potential admin interface exposed")

            host = str(subdomain.get("subdomain", "")).lower()
            if any(word in host for word in ["dev", "test", "staging", "beta"]):
                flags.append("Development or staging environment exposed")

            if flags:
                issues.append({"subdomain": subdomain.get("subdomain"), "issues": flags})

        return issues

    def generate_recommendations(self) -> List[str]:
        return [
            "Enable strict security headers (CSP, X-Frame-Options, X-Content-Type-Options)",
            "Force HTTPS and redirect plain HTTP endpoints",
            "Hide or restrict non-production environments",
            "Harden and gate admin interfaces with MFA and allowlists",
            "Continuously monitor CT logs for rogue certificates",
            "Schedule recurring external attack-surface scans",
        ]

    async def run_full_recon(self) -> Dict[str, Any]:
        if not self.domain:
            raise ValueError("Domain cannot be empty")

        started = datetime.now(timezone.utc)
        await self._emit_log(f"Starting reconnaissance for {self.domain}")

        if self.config.mode == "mock":
            await self._emit_progress("mock", 1, 1, "Generated mock recon data")
            report = run_mock_recon(self.domain)
            await self._emit_log(f"Mock scan complete for {self.domain}")
            return report

        if self.config.enable_ct_logs:
            await self._emit_log("Step 1/4: Enumerating Certificate Transparency logs")
            ct_subdomains = await self.crt_sh_enum()
            self.state.found_subdomains.update(ct_subdomains)
            await self._emit_progress(
                "ct_logs",
                len(ct_subdomains),
                len(ct_subdomains),
                f"CT enumeration discovered {len(ct_subdomains)} entries",
            )

        if self.config.enable_dns_bruteforce:
            await self._emit_log("Step 2/4: Running DNS brute-force")
            wordlist = self.load_subdomain_wordlist()
            dns_results = await self._bounded_run(
                phase="dns_bruteforce",
                items=wordlist,
                worker=self.dns_bruteforce,
                concurrency=self.config.max_concurrency,
                progress_prefix="DNS brute-force",
            )
            self.state.found_subdomains.update(item for item in dns_results if item)

        await self._emit_log(f"Discovered {len(self.state.found_subdomains)} candidate subdomains")

        if self.config.enable_http_probe:
            await self._emit_log("Step 3/4: Probing discovered hosts for live HTTP services")
            probe_results = await self._bounded_run(
                phase="http_probe",
                items=sorted(self.state.found_subdomains),
                worker=self.check_subdomain_alive,
                concurrency=max(8, min(30, self.config.max_concurrency)),
                progress_prefix="HTTP probe",
            )
            self.state.live_subdomains = [item for item in probe_results if item]
        else:
            self.state.live_subdomains = []

        await self._emit_log(f"Detected {len(self.state.live_subdomains)} live hosts")

        if self.config.enable_deep_analysis and self.state.live_subdomains:
            await self._emit_log("Step 4/4: Running port, SSL, and optional nmap analysis")
            enriched = await self._bounded_run(
                phase="deep_analysis",
                items=self.state.live_subdomains,
                worker=self._enrich_live_subdomain,
                concurrency=max(4, min(12, self.config.max_concurrency)),
                progress_prefix="Deep analysis",
            )
            self.state.live_subdomains = [item for item in enriched if item]

        report = {
            "domain": self.domain,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "started_at": started.isoformat(),
            "duration_seconds": round((datetime.now(timezone.utc) - started).total_seconds(), 2),
            "scan_config": self.config.to_dict(),
            "total_subdomains_found": len(self.state.found_subdomains),
            "live_subdomains_count": len(self.state.live_subdomains),
            "subdomains": sorted(list(self.state.found_subdomains), key=lambda x: x[0]),
            "live_subdomains": self.state.live_subdomains,
            "summary": {
                "technologies": self.get_technology_summary(self.state.live_subdomains),
                "security_issues": self.identify_security_issues(self.state.live_subdomains),
                "recommendations": self.generate_recommendations(),
            },
        }

        await self._emit_progress("complete", 1, 1, f"Completed scan for {self.domain}")
        await self._emit_log(f"Reconnaissance complete for {self.domain}")
        return report


async def run_enhanced_recon_async(
    domain: str,
    config: Optional[ScanConfig] = None,
    log_callback: Optional[LogCallback] = None,
    progress_callback: Optional[ProgressCallback] = None,
) -> Dict[str, Any]:
    recon = AsyncNeuroRecon(
        domain=domain,
        config=config,
        log_callback=log_callback,
        progress_callback=progress_callback,
    )
    return await recon.run_full_recon()


def run_enhanced_recon(domain: str) -> Dict[str, Any]:
    """Backward-compatible sync wrapper around the async recon engine."""
    return asyncio.run(run_enhanced_recon_async(domain))


def run_mock_recon(domain: str) -> Dict[str, Any]:
    return {
        "domain": domain,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_subdomains_found": 15,
        "live_subdomains_count": 8,
        "subdomains": [
            (f"www.{domain}", "192.168.1.10"),
            (f"api.{domain}", "192.168.1.11"),
            (f"admin.{domain}", "192.168.1.12"),
            (f"staging.{domain}", "192.168.1.13"),
        ],
        "live_subdomains": [
            {
                "subdomain": f"www.{domain}",
                "ip": "192.168.1.10",
                "status_code": 200,
                "protocol": "https",
                "title": "Example App",
                "server": "nginx/1.24",
                "technology": ["Nginx", "React"],
                "open_ports": [80, 443],
            },
            {
                "subdomain": f"admin.{domain}",
                "ip": "192.168.1.12",
                "status_code": 302,
                "protocol": "http",
                "title": "Admin Login",
                "server": "Apache/2.4",
                "technology": ["Apache", "Missing security headers: Content-Security-Policy"],
                "open_ports": [80, 22],
            },
        ],
        "summary": {
            "technologies": {
                "Nginx": 3,
                "React": 2,
                "Apache": 1,
                "Missing security headers: Content-Security-Policy": 1,
            },
            "security_issues": [
                {
                    "subdomain": f"admin.{domain}",
                    "issues": ["Potential admin interface exposed", "Using HTTP instead of HTTPS"],
                }
            ],
            "recommendations": [
                "Force HTTPS and apply HSTS",
                "Add CSP and security headers",
                "Restrict admin access by source IP and MFA",
            ],
        },
    }


def build_ai_prompt(domain: str, recon_data: Dict[str, Any]) -> str:
    live_subs = recon_data.get("live_subdomains", [])
    security_issues = recon_data.get("summary", {}).get("security_issues", [])
    tech_summary = recon_data.get("summary", {}).get("technologies", {})

    subdomains_info = []
    for sub in live_subs[:10]:
        entry = f"  - {sub.get('subdomain', 'unknown')} [{sub.get('status_code', 'n/a')}]"
        if sub.get("server"):
            entry += f" - {sub['server']}"
        if sub.get("open_ports"):
            entry += f" (Ports: {', '.join(map(str, sub['open_ports']))})"
        subdomains_info.append(entry)

    issues_text = [
        f"  - {issue.get('subdomain', 'unknown')}: {', '.join(issue.get('issues', []))}"
        for issue in security_issues[:5]
    ]

    tech_text = [f"  - {tech}: {count} instances" for tech, count in tech_summary.items()]

    prompt = f"""
NEUROSPLOIT RECONNAISSANCE REPORT
=================================

Target Domain: {domain}
Total Subdomains Found: {recon_data.get('total_subdomains_found', 0)}
Live Subdomains: {recon_data.get('live_subdomains_count', 0)}

LIVE SUBDOMAINS:
{chr(10).join(subdomains_info) if subdomains_info else '  No live subdomains found'}

TECHNOLOGY STACK:
{chr(10).join(tech_text) if tech_text else '  No technologies detected'}

SECURITY ISSUES IDENTIFIED:
{chr(10).join(issues_text) if issues_text else '  No obvious security issues detected'}

AI ANALYSIS REQUEST:
1. Identify likely vulnerabilities in this external attack surface
2. Suggest possible attack paths and entry points
3. Prioritize targets by likely impact and exploitability
4. Recommend practical next-step validation strategies
5. Provide a concise risk summary
""".strip()

    return prompt


def export_report(report: Dict[str, Any], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2, default=str))
    return output_path
