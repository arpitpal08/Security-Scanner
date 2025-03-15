#!/usr/bin/env python3
import asyncio
import click
from rich.console import Console
from rich.progress import Progress
import sys
from pathlib import Path

from src.scanner.core import SecurityScanner

console = Console()

@click.group()
def cli():
    """Security Scanner - Automated Vulnerability Assessment Tool"""
    pass

@cli.command()
@click.option("--target", required=True, help="Target URL or IP address")
@click.option("--scan-type", type=click.Choice(["basic", "full-audit", "api-scan"]),
              default="basic", help="Type of scan to perform")
@click.option("--report", type=click.Choice(["pdf", "html", "json"]),
              default="pdf", help="Report format")
@click.option("--output", help="Output file path")
def scan(target: str, scan_type: str, report: str, output: str):
    """Perform security scan on target."""
    try:
        scanner = SecurityScanner()
        
        with Progress() as progress:
            task = progress.add_task(f"[cyan]Scanning {target}...", total=100)
            
            # Run the scan
            results = asyncio.run(scanner.scan_target(target, scan_type))
            progress.update(task, advance=50)
            
            # Generate report
            report_path = scanner.generate_report(report, output)
            progress.update(task, advance=50)
        
        console.print(f"\n[green]Scan completed successfully!")
        console.print(f"Report generated: {report_path}")
        
        # Print summary
        console.print("\n[yellow]Scan Summary:")
        console.print(f"Target: {target}")
        console.print(f"Scan Type: {scan_type}")
        console.print(f"Vulnerabilities Found:")
        for severity in ["high", "medium", "low"]:
            count = len(results.get("vulnerabilities", {}).get(severity, []))
            color = {"high": "red", "medium": "yellow", "low": "green"}[severity]
            console.print(f"  {severity.title()}: [bold {color}]{count}[/]")
        
    except Exception as e:
        console.print(f"\n[red]Error: {str(e)}")
        sys.exit(1)

@cli.command()
@click.argument("report_path", type=click.Path(exists=True))
def view(report_path: str):
    """View an existing scan report."""
    try:
        # Implement report viewing logic here
        console.print(f"[yellow]Opening report: {report_path}")
        # For now, just print that this feature is coming soon
        console.print("[cyan]Report viewer coming soon!")
        
    except Exception as e:
        console.print(f"\n[red]Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    cli() 