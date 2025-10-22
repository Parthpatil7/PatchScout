"""
PatchScout - AI-Powered Vulnerability Detection Tool
Main entry point for the application
"""

import argparse
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

from .analyzers import CodeAnalyzer, LanguageDetector
from .reporting import ReportGenerator
from .utils import ConfigLoader

console = Console()


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="PatchScout - AI-Powered Vulnerability Detection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a single file
  python -m src.main -f path/to/code.java
  
  # Scan entire directory
  python -m src.main -d path/to/project
  
  # Generate detailed report
  python -m src.main -d path/to/project -o results.xlsx -v
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "-f", "--file",
        type=str,
        help="Path to a single source code file to analyze"
    )
    input_group.add_argument(
        "-d", "--directory",
        type=str,
        help="Path to directory containing source code to analyze"
    )
    
    # Analysis options
    parser.add_argument(
        "-l", "--language",
        type=str,
        choices=['java', 'python', 'c', 'cpp', 'php', 'ruby', 
                 'rust', 'kotlin', 'swift', 'html', 'javascript', 'go'],
        help="Programming language (auto-detected if not specified)"
    )
    
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="output/vulnerability_report.xlsx",
        help="Output file path (default: output/vulnerability_report.xlsx)"
    )
    
    parser.add_argument(
        "-r", "--recursive",
        action="store_true",
        default=True,
        help="Recursively scan directories (default: True)"
    )
    
    parser.add_argument(
        "--team-name",
        type=str,
        default="TeamName",
        help="Team name for competition report (default: TeamName)"
    )
    
    # Output options
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--format",
        type=str,
        choices=['excel', 'json', 'both'],
        default='excel',
        help="Output format (default: excel)"
    )
    
    return parser.parse_args()


def validate_inputs(args):
    """Validate input arguments"""
    if args.file:
        file_path = Path(args.file)
        if not file_path.exists():
            console.print(f"[red]Error: File not found: {args.file}[/red]")
            return False
        if not file_path.is_file():
            console.print(f"[red]Error: Path is not a file: {args.file}[/red]")
            return False
    
    if args.directory:
        dir_path = Path(args.directory)
        if not dir_path.exists():
            console.print(f"[red]Error: Directory not found: {args.directory}[/red]")
            return False
        if not dir_path.is_dir():
            console.print(f"[red]Error: Path is not a directory: {args.directory}[/red]")
            return False
    
    return True


def display_results_summary(results, verbose=False):
    """Display analysis results summary"""
    total_files = len(results)
    total_vulns = sum(r.get('vulnerability_count', 0) for r in results)
    
    # Create summary table
    summary_table = Table(title="Analysis Summary")
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="yellow", justify="right")
    
    summary_table.add_row("Files Analyzed", str(total_files))
    summary_table.add_row("Vulnerabilities Found", str(total_vulns))
    
    # Calculate severity breakdown
    severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
    for result in results:
        for vuln in result.get('vulnerabilities', []):
            severity = vuln.get('severity', 'Medium')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    summary_table.add_row("─" * 20, "─" * 10)
    summary_table.add_row("[red]Critical[/red]", str(severity_counts['Critical']))
    summary_table.add_row("[orange1]High[/orange1]", str(severity_counts['High']))
    summary_table.add_row("[yellow]Medium[/yellow]", str(severity_counts['Medium']))
    summary_table.add_row("[green]Low[/green]", str(severity_counts['Low']))
    
    console.print(summary_table)
    
    # Detailed results if verbose
    if verbose and total_vulns > 0:
        console.print("\n[bold cyan]Vulnerabilities by File:[/bold cyan]\n")
        for result in results:
            vulns = result.get('vulnerabilities', [])
            if vulns:
                file_path = result.get('file_path', 'Unknown')
                console.print(f"[yellow]📄 {file_path}[/yellow] - {len(vulns)} vulnerabilities")
                for vuln in vulns[:5]:  # Show first 5
                    severity_color = {
                        'Critical': 'red',
                        'High': 'orange1',
                        'Medium': 'yellow',
                        'Low': 'green'
                    }.get(vuln.get('severity', 'Medium'), 'white')
                    console.print(
                        f"  [{severity_color}]●[/{severity_color}] "
                        f"Line {vuln.get('line_number', '?')}: "
                        f"{vuln.get('type', 'Unknown')} "
                        f"({vuln.get('cwe', 'N/A')})"
                    )
                if len(vulns) > 5:
                    console.print(f"  [dim]... and {len(vulns) - 5} more[/dim]")
                console.print()


def main():
    """Main execution function"""
    # Display banner
    console.print(Panel.fit(
        "[bold cyan]PatchScout v1.0.0[/bold cyan]\n"
        "[dim]AI-Powered Vulnerability Detection Tool[/dim]\n"
        "[dim]For AI Grand Challenge - Problem Statement 01[/dim]",
        border_style="cyan"
    ))
    
    # Parse arguments
    args = parse_arguments()
    
    # Validate inputs
    if not validate_inputs(args):
        sys.exit(1)
    
    # Load configuration
    try:
        config_loader = ConfigLoader()
        config = config_loader.load_config()
    except Exception as e:
        console.print(f"[red]Error loading configuration: {str(e)}[/red]")
        sys.exit(1)
    
    # Display configuration
    if args.verbose:
        config_table = Table(title="Configuration")
        config_table.add_column("Parameter", style="cyan")
        config_table.add_column("Value", style="yellow")
        
        if args.file:
            config_table.add_row("Input File", args.file)
        if args.directory:
            config_table.add_row("Input Directory", args.directory)
        config_table.add_row("Output", args.output)
        config_table.add_row("Format", args.format)
        config_table.add_row("Recursive", str(args.recursive))
        config_table.add_row("Team Name", args.team_name)
        
        console.print(config_table)
    
    # Initialize analyzer
    try:
        analyzer = CodeAnalyzer(config)
    except Exception as e:
        console.print(f"[red]Error initializing analyzer: {str(e)}[/red]")
        sys.exit(1)
    
    # Perform analysis
    console.print("\n[yellow]🔍 Analyzing code for vulnerabilities...[/yellow]\n")
    
    results = []
    
    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console
        ) as progress:
            
            if args.file:
                # Analyze single file
                task = progress.add_task("Analyzing file...", total=1)
                result = analyzer.analyze_file(args.file, args.language)
                if result.get('success'):
                    results.append(result)
                progress.update(task, advance=1)
                
            elif args.directory:
                # Analyze directory
                task = progress.add_task("Scanning directory...", total=None)
                dir_results = analyzer.analyze_directory(args.directory, args.recursive)
                results.extend(dir_results)
                progress.update(task, completed=True)
    
    except Exception as e:
        console.print(f"[red]Error during analysis: {str(e)}[/red]")
        if args.verbose:
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
        sys.exit(1)
    
    # Display results
    console.print("\n[green]✓ Analysis complete![/green]\n")
    
    if not results:
        console.print("[yellow]No files were analyzed. Check input path and file types.[/yellow]")
        sys.exit(0)
    
    display_results_summary(results, args.verbose)
    
    # Generate report
    console.print("\n[yellow]📝 Generating competition report...[/yellow]")
    
    try:
        report_generator = ReportGenerator(config)
        
        # Prepare vulnerabilities list
        all_vulnerabilities = []
        for result in results:
            for vuln in result.get('vulnerabilities', []):
                vuln['file_name'] = result.get('file_path', '')
                vuln['language'] = result.get('language', 'Unknown')
                all_vulnerabilities.append(vuln)
        
        # Ensure output directory exists
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Generate reports based on format
        if args.format in ['excel', 'both']:
            excel_output = str(output_path) if args.format == 'excel' else str(output_path.with_suffix('.xlsx'))
            report_generator.generate_excel_report(
                all_vulnerabilities,
                excel_output,
                team_name=args.team_name
            )
            console.print(f"[cyan]📊 Excel report saved to: {excel_output}[/cyan]")
        
        if args.format in ['json', 'both']:
            json_output = str(output_path.with_suffix('.json'))
            report_generator.generate_json_report(all_vulnerabilities, json_output)
            console.print(f"[cyan]📄 JSON report saved to: {json_output}[/cyan]")
        
        console.print("\n[bold green]✨ PatchScout analysis completed successfully![/bold green]")
        console.print(f"[dim]Total vulnerabilities detected: {len(all_vulnerabilities)}[/dim]")
        
    except Exception as e:
        console.print(f"[red]Error generating report: {str(e)}[/red]")
        if args.verbose:
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")
        sys.exit(1)
    
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Analysis interrupted by user.[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Unexpected error: {str(e)}[/red]")
        sys.exit(1)
