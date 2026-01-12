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

from detector import VulnerabilityDetector
from payloads import PayloadManager
from reporter import ReportGenerator

# Import LLM Judge for hybrid detection
try:
    from judge import LLMJudge, HybridDetector
    JUDGE_AVAILABLE = True
except ImportError:
    JUDGE_AVAILABLE = False

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
    
    def __init__(self, config_path: str = "config.yaml", proxy: str = None):
        self.config = self._load_config(config_path)
        self.proxy = proxy
        self.detector = VulnerabilityDetector(self.config.get('detection', {}))
        self.payload_manager = PayloadManager()
        self.reporter = ReportGenerator()
        self.results: List[ScanResult] = []
        
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
        if not path:
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
            
            return ScanResult(
                payload_id=payload_info.get('id', 'unknown'),
                payload_category=payload_info.get('category', 'unknown'),
                payload_name=payload_info.get('name', 'unknown'),
                payload_text=payload_info['payload'],
                response_text=response_text,
                is_vulnerable=detection_result['is_vulnerable'],
                confidence=detection_result['confidence'],
                indicators_found=detection_result['indicators'],
                response_time=response_time
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
        limit: Optional[int] = None
    ) -> ScanReport:
        """
        Run a comprehensive scan against the target.
        
        Args:
            categories: List of payload categories to test (None = all)
            custom_payloads: Additional custom payloads to test
            limit: Maximum number of payloads to test (None = all)
        """
        scan_start = datetime.now().isoformat()
        
        console.print(Panel.fit(
            "[bold cyan]�️ promptmap[/bold cyan]\n"
            f"[dim]Target: {self.config['target']['url']}[/dim]",
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
        
        report = ScanReport(
            target_url=self.config['target']['url'],
            scan_start=scan_start,
            scan_end=scan_end,
            total_payloads=len(payloads),
            successful_injections=successful,
            failed_injections=failed,
            errors=errors,
            results=self.results,
            vulnerability_summary=vuln_summary
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
