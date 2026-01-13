#!/usr/bin/env python3
"""
Prompt Injection Scanner - Main Scanner Module
Inspired by Garak, DeepTeam, PyRIT, and Promptfoo

Author: Jai
"""

import asyncio
import httpx
import yaml
import json
import os
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from jinja2 import Template
from dotenv import load_dotenv
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from rich.panel import Panel

from .detector import VulnerabilityDetector
from .payloads import PayloadManager
from .reporter import ReportGenerator

# Import LLM Judge for hybrid detection
try:
    from .judge import LLMJudge, HybridDetector
    JUDGE_AVAILABLE = True
except ImportError:
    JUDGE_AVAILABLE = False

# Import Response Analyzer for leaked secrets detection
try:
    from .analyzer import ResponseAnalyzer, AnalysisResult
    ANALYZER_AVAILABLE = True
except ImportError:
    ANALYZER_AVAILABLE = False

# Import Verifier for reducing false positives
try:
    from .verifier import VulnerabilityVerifier, VerificationStatus
    VERIFIER_AVAILABLE = True
except ImportError:
    VERIFIER_AVAILABLE = False

load_dotenv()
console = Console()


@dataclass
class ScanResult:
    """Represents a single scan result"""
    payload_id: str
    payload_category: str
    payload_name: str
    payload_text: str
    response_text: str
    is_vulnerable: bool
    confidence: float
    indicators_found: List[str]
    response_time: float
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    error: Optional[str] = None
    # Response analysis fields
    sensitive_data_found: bool = False
    sensitive_data_summary: str = ""
    sensitive_findings: List[Dict] = field(default_factory=list)
    risk_score: float = 0.0
    # Verification fields (to reduce false positives)
    verified: bool = False
    verification_status: str = "unverified"
    verification_reason: str = ""


@dataclass
class ScanReport:
    """Complete scan report"""
    target_url: str
    scan_start: str
    scan_end: str
    total_payloads: int
    successful_injections: int
    failed_injections: int
    errors: int
    results: List[ScanResult]
    vulnerability_summary: Dict[str, int]
    # New fields for sensitive data analysis
    total_sensitive_findings: int = 0
    sensitive_data_severity: Dict[str, int] = field(default_factory=dict)


class PromptInjectionScanner:
    """
    Main scanner class for testing LLM endpoints against prompt injection attacks.
    
    Supports multiple attack categories:
    - Direct prompt injection
    - Jailbreaking attempts
    - Data leakage probes
    - Context manipulation
    - Role-play exploitation
    - System prompt extraction
    - Multi-turn attacks
    """
    
    def __init__(self, config_path: str = "config.yaml", proxy: str = None, enable_analyzer: bool = True):
        self.config = self._load_config(config_path)
        self.proxy = proxy
        self.detector = VulnerabilityDetector(self.config.get('detection', {}))
        self.payload_manager = PayloadManager()
        self.reporter = ReportGenerator()
        self.results: List[ScanResult] = []
        
        # Initialize Response Analyzer for leaked secrets detection
        self.analyzer = None
        if enable_analyzer and ANALYZER_AVAILABLE:
            self.analyzer = ResponseAnalyzer()
            console.print("[green]✓ Response analyzer enabled (detects leaked secrets/PII)[/green]")
        
        # Initialize Verifier for reducing false positives
        self.verifier = None
        if VERIFIER_AVAILABLE:
            self.verifier = VulnerabilityVerifier()
            console.print("[green]✓ Double verification enabled (reduces false positives)[/green]")
        
        # Initialize hybrid detector if available and configured
        self.hybrid_detector = None
        detection_mode = self.config.get('detection', {}).get('mode', 'keyword')
        
        if detection_mode in ('hybrid', 'llm_judge') and JUDGE_AVAILABLE:
            try:
                llm_judge = LLMJudge(self.config)
                self.hybrid_detector = HybridDetector(
                    self.config, 
                    self.detector, 
                    llm_judge
                )
                console.print(f"[green]✓ LLM Judge enabled ({detection_mode} mode)[/green]")
            except Exception as e:
                console.print(f"[yellow]⚠ LLM Judge unavailable: {e}, falling back to keyword mode[/yellow]")
        elif detection_mode in ('hybrid', 'llm_judge'):
            console.print("[yellow]⚠ judge.py not found, falling back to keyword mode[/yellow]")
        
        if self.proxy:
            console.print(f"[green]✓ Proxy configured: {self.proxy}[/green]")
    
    def _setup_client(self):
        """Reinitialize settings after config change (used with -r request file)"""
        # Reload detector with potentially new detection settings
        self.detector = VulnerabilityDetector(self.config.get('detection', {}))
        
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from YAML file"""
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        
        # Substitute environment variables
        config = self._substitute_env_vars(config)
        return config
    
    def _substitute_env_vars(self, obj: Any) -> Any:
        """Recursively substitute ${VAR} with environment variables"""
        if isinstance(obj, str):
            import re
            pattern = r'\$\{(\w+)\}'
            matches = re.findall(pattern, obj)
            for match in matches:
                env_value = os.getenv(match, '')
                obj = obj.replace(f'${{{match}}}', env_value)
            return obj
        elif isinstance(obj, dict):
            return {k: self._substitute_env_vars(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._substitute_env_vars(item) for item in obj]
        return obj
    
    def _render_body(self, prompt: str) -> str:
        """Render the request body using Jinja2 template"""
        template_str = self.config['target'].get('body_template', '{"prompt": "{{ prompt }}"}')
        template = Template(template_str)
        return template.render(prompt=prompt)
    
    async def _send_request(self, client: httpx.AsyncClient, payload: str) -> tuple[str, float, Optional[str]]:
        """Send a single request to the target endpoint"""
        target = self.config['target']
        timeout = self.config['scanner'].get('timeout', 30)
        
        try:
            body = self._render_body(payload)
            start_time = asyncio.get_event_loop().time()
            
            response = await client.request(
                method=target.get('method', 'POST'),
                url=target['url'],
                headers=target.get('headers', {}),
                content=body,
                timeout=timeout
            )
            
            end_time = asyncio.get_event_loop().time()
            response_time = end_time - start_time
            
            # Parse response
            try:
                response_data = response.json()
                # Extract response text using JSONPath-like syntax
                response_path = target.get('response_path', '')
                response_text = self._extract_response(response_data, response_path)
            except json.JSONDecodeError:
                response_text = response.text
                
            return response_text, response_time, None
            
        except httpx.TimeoutException:
            return "", 0, "Request timeout"
        except httpx.RequestError as e:
            return "", 0, f"Request error: {str(e)}"
        except Exception as e:
            return "", 0, f"Unexpected error: {str(e)}"
    
    def _extract_response(self, data: Any, path: str) -> str:
        """Extract response text from JSON using dot/bracket notation"""
        # Auto-detect common LLM response formats
        if not path or path == 'auto':
            # Try OpenAI format: choices[0].message.content
            try:
                content = data['choices'][0]['message']['content']
                if content:
                    return str(content)
            except (KeyError, IndexError, TypeError):
                pass
            
            # Try Anthropic format: content[0].text
            try:
                content = data['content'][0]['text']
                if content:
                    return str(content)
            except (KeyError, IndexError, TypeError):
                pass
            
            # Try simple response format: response or text
            for key in ['response', 'text', 'output', 'result', 'answer']:
                if key in data and data[key]:
                    return str(data[key])
            
            # Fall back to full JSON
            return str(data)
        
        import re
        # Parse path like "choices[0].message.content"
        parts = re.split(r'\.|\[|\]', path)
        parts = [p for p in parts if p]  # Remove empty strings
        
        current = data
        for part in parts:
            try:
                if part.isdigit():
                    current = current[int(part)]
                else:
                    current = current[part]
            except (KeyError, IndexError, TypeError):
                return str(data)
        
        return str(current)
    
    def _get_client_kwargs(self) -> dict:
        """Get httpx client kwargs including proxy if configured"""
        kwargs = {'verify': False}  # Disable SSL verification for proxy compatibility
        if self.proxy:
            kwargs['proxy'] = self.proxy
        return kwargs
    
    async def scan_single(self, payload_info: Dict) -> ScanResult:
        """Scan with a single payload"""
        async with httpx.AsyncClient(**self._get_client_kwargs()) as client:
            response_text, response_time, error = await self._send_request(
                client, payload_info['payload']
            )
            
            if error:
                return ScanResult(
                    payload_id=payload_info.get('id', 'unknown'),
                    payload_category=payload_info.get('category', 'unknown'),
                    payload_name=payload_info.get('name', 'unknown'),
                    payload_text=payload_info['payload'],
                    response_text="",
                    is_vulnerable=False,
                    confidence=0.0,
                    indicators_found=[],
                    response_time=response_time,
                    error=error
                )
            
            # Analyze response for vulnerabilities using hybrid or keyword detection
            if self.hybrid_detector:
                detection_result = await self.hybrid_detector.analyze(
                    payload_info['payload'],
                    response_text,
                    payload_info.get('category', 'unknown')
                )
            else:
                detection_result = self.detector.analyze(
                    payload_info['payload'],
                    response_text,
                    payload_info.get('category', 'unknown')
                )
            
            # Analyze response for leaked sensitive data
            sensitive_data_found = False
            sensitive_data_summary = ""
            sensitive_findings = []
            risk_score = 0.0
            
            if self.analyzer and response_text:
                analysis_result = self.analyzer.analyze(response_text, payload_info['payload'])
                risk_score = analysis_result.risk_score
                
                # Convert findings to dict for serialization
                # But use verifier to filter false positives
                for finding in analysis_result.findings:
                    # Use verifier to check if this sensitive data should be flagged
                    should_flag = True
                    flag_reason = "Detected"
                    
                    if self.verifier:
                        should_flag, flag_reason = self.verifier.should_verify_sensitive_data(
                            finding.data_type.value,
                            finding.severity,
                            response_text,
                            payload_info['payload']
                        )
                    
                    if should_flag:
                        sensitive_findings.append({
                            'type': finding.data_type.value,
                            'masked_value': finding.masked_value,
                            'severity': finding.severity,
                            'description': finding.description,
                            'verified': True,
                            'reason': flag_reason
                        })
                
                # Update sensitive_data_found based on verified findings only
                sensitive_data_found = len(sensitive_findings) > 0
                if sensitive_data_found:
                    sensitive_data_summary = f"Found {len(sensitive_findings)} verified sensitive data item(s)"
                else:
                    sensitive_data_summary = "No verified sensitive data detected"
                
                # Only mark as vulnerable if we have VERIFIED sensitive data
                if sensitive_data_found and not detection_result['is_vulnerable']:
                    # Only flag as vulnerable if severity is high or critical
                    high_severity_findings = [f for f in sensitive_findings if f['severity'] in ('critical', 'high')]
                    if high_severity_findings:
                        detection_result['is_vulnerable'] = True
                        detection_result['confidence'] = max(detection_result['confidence'], risk_score)
                        detection_result['indicators'].extend([f"LEAKED: {f['type']}" for f in high_severity_findings[:3]])
            
            # DOUBLE VERIFICATION: Use verifier to reduce false positives AND catch false negatives
            verified = False
            verification_status = "unverified"
            verification_reason = ""
            
            if self.verifier:
                # ALWAYS run verification - catches both false positives AND false negatives
                # (e.g., model that says "I won't do this but..." and then does it)
                verification_result = self.verifier.verify_detection(
                    payload=payload_info['payload'],
                    response=response_text,
                    initial_vulnerable=detection_result['is_vulnerable'],
                    initial_confidence=detection_result['confidence'],
                    initial_indicators=detection_result['indicators'],
                    category=payload_info.get('category', 'unknown')
                )
                
                # Update based on verification
                detection_result['is_vulnerable'] = verification_result.final_vulnerable
                detection_result['confidence'] = max(0.0, detection_result['confidence'] + verification_result.confidence_adjustment)
                verified = True
                verification_status = verification_result.verification_status.value
                verification_reason = verification_result.reason
                
                # Add verification indicator
                if verification_result.verification_status.value == "confirmed":
                    detection_result['indicators'].append(f"✓ Verified: {verification_reason}")
                elif verification_result.verification_status.value == "false_positive":
                    detection_result['indicators'] = [f"✗ False positive: {verification_reason}"]
                elif verification_result.verification_status.value == "jailbreak_with_disclaimer":
                    detection_result['indicators'].append(f"⚠ Jailbreak: {verification_reason}")
            
            return ScanResult(
                payload_id=payload_info.get('id', 'unknown'),
                payload_category=payload_info.get('category', 'unknown'),
                payload_name=payload_info.get('name', 'unknown'),
                payload_text=payload_info['payload'],
                response_text=response_text,
                is_vulnerable=detection_result['is_vulnerable'],
                confidence=detection_result['confidence'],
                indicators_found=detection_result['indicators'],
                response_time=response_time,
                sensitive_data_found=sensitive_data_found,
                sensitive_data_summary=sensitive_data_summary,
                sensitive_findings=sensitive_findings,
                risk_score=risk_score,
                verified=verified,
                verification_status=verification_status,
                verification_reason=verification_reason
            )
    
    async def scan_batch(self, payloads: List[Dict], progress_callback=None) -> List[ScanResult]:
        """Scan with multiple payloads concurrently"""
        max_concurrent = self.config['scanner'].get('max_concurrent', 5)
        delay = self.config['scanner'].get('delay_between_requests', 1.0)
        
        semaphore = asyncio.Semaphore(max_concurrent)
        results = []
        
        async def bounded_scan(payload_info: Dict, index: int):
            async with semaphore:
                result = await self.scan_single(payload_info)
                if progress_callback:
                    progress_callback(index + 1, len(payloads))
                await asyncio.sleep(delay)
                return result
        
        tasks = [bounded_scan(p, i) for i, p in enumerate(payloads)]
        results = await asyncio.gather(*tasks)
        
        return results
    
    async def run_full_scan(
        self,
        categories: Optional[List[str]] = None,
        custom_payloads: Optional[List[str]] = None,
        limit: Optional[int] = None,
        transform_name: Optional[str] = None
    ) -> ScanReport:
        """
        Run a comprehensive scan against the target.
        
        Args:
            categories: List of payload categories to test (None = all)
            custom_payloads: Additional custom payloads to test
            limit: Maximum number of payloads to test (None = all)
            transform_name: Name of transformation to apply to payloads (None = no transform)
        """
        scan_start = datetime.now().isoformat()
        
        # Initialize transformer if specified
        transformer = None
        if transform_name:
            try:
                from .transformers import PayloadTransformer
                transformer = PayloadTransformer()
            except ImportError:
                console.print("[yellow]⚠ Transformer module not available[/yellow]")
        
        console.print(Panel.fit(
            "[bold cyan]🗺️ promptmap[/bold cyan]\n"
            f"[dim]Target: {self.config['target']['url']}[/dim]" +
            (f"\n[dim]Transform: {transform_name}[/dim]" if transform_name else ""),
            title="LLM Security Scanner"
        ))
        
        # Load payloads
        payloads = self.payload_manager.get_payloads(categories)
        
        # Add custom payloads if provided
        if custom_payloads:
            for i, cp in enumerate(custom_payloads):
                payloads.append({
                    'id': f'custom_{i}',
                    'category': 'custom',
                    'name': f'Custom Payload {i+1}',
                    'payload': cp
                })
        
        # Apply transformation if specified
        if transformer and transform_name:
            console.print(f"[magenta]🔄 Transforming payloads with: {transform_name}[/magenta]")
            for p in payloads:
                original = p['payload']
                result = transformer.transform(original, transform_name)
                p['payload'] = result.transformed
                p['original_payload'] = original  # Keep original for reporting
        
        # Apply limit if specified
        if limit and limit > 0:
            payloads = payloads[:limit]
            console.print(f"\n[yellow]📦 Testing {len(payloads)} payload(s) (limited from {self.payload_manager.get_payloads(categories).__len__()} total)[/yellow]\n")
        else:
            console.print(f"\n[yellow]📦 Loaded {len(payloads)} payloads[/yellow]\n")
        
        # Run scan with progress bar
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console
        ) as progress:
            task = progress.add_task("[cyan]Scanning...", total=len(payloads))
            
            def update_progress(current, total):
                progress.update(task, completed=current)
            
            self.results = await self.scan_batch(payloads, update_progress)
        
        scan_end = datetime.now().isoformat()
        
        # Generate summary
        successful = sum(1 for r in self.results if r.is_vulnerable)
        failed = sum(1 for r in self.results if not r.is_vulnerable and not r.error)
        errors = sum(1 for r in self.results if r.error)
        
        # Category breakdown
        vuln_summary = {}
        for r in self.results:
            if r.is_vulnerable:
                vuln_summary[r.payload_category] = vuln_summary.get(r.payload_category, 0) + 1
        
        # Sensitive data statistics
        total_sensitive = 0
        sensitive_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for r in self.results:
            if r.sensitive_data_found:
                total_sensitive += len(r.sensitive_findings)
                for finding in r.sensitive_findings:
                    sev = finding.get('severity', 'low')
                    sensitive_severity[sev] = sensitive_severity.get(sev, 0) + 1
        
        report = ScanReport(
            target_url=self.config['target']['url'],
            scan_start=scan_start,
            scan_end=scan_end,
            total_payloads=len(payloads),
            successful_injections=successful,
            failed_injections=failed,
            errors=errors,
            results=self.results,
            vulnerability_summary=vuln_summary,
            total_sensitive_findings=total_sensitive,
            sensitive_data_severity=sensitive_severity
        )
        
        # Display results
        self._display_results(report)
        
        return report
    
    def _display_results(self, report: ScanReport):
        """Display scan results in a formatted table"""
        console.print("\n")
        
        # Summary table
        summary_table = Table(title="📊 Scan Summary", show_header=True)
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="green")
        
        summary_table.add_row("Total Payloads", str(report.total_payloads))
        summary_table.add_row("Successful Injections", f"[red]{report.successful_injections}[/red]")
        summary_table.add_row("Blocked/Failed", f"[green]{report.failed_injections}[/green]")
        summary_table.add_row("Errors", str(report.errors))
        
        console.print(summary_table)
        
        # Sensitive Data Findings (NEW)
        if report.total_sensitive_findings > 0:
            console.print("\n")
            sensitive_table = Table(title="🔐 Sensitive Data Leaked", show_header=True)
            sensitive_table.add_column("Severity", style="cyan")
            sensitive_table.add_column("Count", style="red")
            
            severity_icons = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}
            for sev in ['critical', 'high', 'medium', 'low']:
                count = report.sensitive_data_severity.get(sev, 0)
                if count > 0:
                    sensitive_table.add_row(f"{severity_icons[sev]} {sev.upper()}", str(count))
            
            sensitive_table.add_row("[bold]TOTAL[/bold]", f"[bold]{report.total_sensitive_findings}[/bold]")
            console.print(sensitive_table)
        
        # Vulnerability breakdown
        if report.vulnerability_summary:
            console.print("\n")
            vuln_table = Table(title="🎯 Vulnerabilities by Category", show_header=True)
            vuln_table.add_column("Category", style="yellow")
            vuln_table.add_column("Count", style="red")
            
            for category, count in sorted(report.vulnerability_summary.items(), key=lambda x: -x[1]):
                vuln_table.add_row(category, str(count))
            
            console.print(vuln_table)
        
        # Top vulnerable payloads
        vulnerable_results = [r for r in report.results if r.is_vulnerable]
        if vulnerable_results:
            console.print("\n")
            console.print("[bold red]⚠️  Successful Injection Payloads:[/bold red]\n")
            
            for r in sorted(vulnerable_results, key=lambda x: -x.confidence)[:10]:
                console.print(f"[red]• [{r.payload_category}][/red] {r.payload_name}")
                console.print(f"  [dim]Confidence: {r.confidence:.0%}[/dim]")
                console.print(f"  [dim]Indicators: {', '.join(r.indicators_found[:3])}[/dim]")
                
                # Show sensitive data findings if any
                if r.sensitive_data_found and r.sensitive_findings:
                    console.print(f"  [bold yellow]🔑 Leaked Data:[/bold yellow]")
                    for finding in r.sensitive_findings[:3]:
                        icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}.get(finding['severity'], '⚪')
                        console.print(f"    {icon} {finding['type']}: {finding['masked_value']}")
                console.print()
    
    def save_report(self, report: ScanReport, output_format: str = "json"):
        """Save scan report to file"""
        output_config = self.config.get('output', {})
        filename = output_config.get('file', f'scan_results.{output_format}')
        
        self.reporter.save(report, filename, output_format)
        console.print(f"\n[green]✅ Report saved to {filename}[/green]")


async def main():
    """Main entry point for standalone execution"""
    scanner = PromptInjectionScanner()
    report = await scanner.run_full_scan()
    scanner.save_report(report)


if __name__ == "__main__":
    asyncio.run(main())
