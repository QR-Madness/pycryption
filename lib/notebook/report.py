# lib/notebook/report.py
"""
Report builder for styled Jupyter notebook output.

Provides a ReportBuilder class that renders tables, benchmark results,
and comparison reports with consistent styling using rich and tabulate.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Union

try:
    from IPython.display import display, HTML
    _HAS_IPYTHON = True
except ImportError:
    _HAS_IPYTHON = False

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    _HAS_RICH = True
except ImportError:
    _HAS_RICH = False

try:
    from tabulate import tabulate
    _HAS_TABULATE = True
except ImportError:
    _HAS_TABULATE = False


class ReportBuilder:
    """
    Styled report builder for Jupyter notebook output.

    Renders tables and benchmark results with consistent styling.
    Supports multiple output formats: rich (default), HTML, or plain text.

    Usage:
        report = ReportBuilder()

        # Render comparison table
        report.comparison_table(session.compare())

        # Render benchmark results
        report.benchmark_table(session.benchmark_all())

        # Render session report
        report.session_report(session.report())

        # Custom table
        report.table(
            data=[{"name": "AES", "speed": 100}, {"name": "XOR", "speed": 10}],
            columns=["name", "speed"],
            title="Algorithm Comparison"
        )
    """

    def __init__(
        self,
        format: str = "auto",
        theme: str = "default",
    ) -> None:
        """
        Initialize the report builder.

        Args:
            format: Output format - "auto", "rich", "html", or "plain"
            theme: Color theme - "default", "minimal", or "dark"
        """
        self.format = self._resolve_format(format)
        self.theme = theme
        self._console = Console() if _HAS_RICH else None

    def _resolve_format(self, format: str) -> str:
        """Resolve 'auto' format based on available libraries."""
        if format != "auto":
            return format
        if _HAS_RICH:
            return "rich"
        if _HAS_TABULATE:
            return "html" if _HAS_IPYTHON else "plain"
        return "plain"

    def _get_theme_colors(self) -> Dict[str, str]:
        """Get theme-specific colors for rich tables."""
        themes = {
            "default": {
                "header": "bold cyan",
                "row_even": "white",
                "row_odd": "dim white",
                "highlight": "bold green",
                "border": "blue",
            },
            "minimal": {
                "header": "bold",
                "row_even": "",
                "row_odd": "",
                "highlight": "bold",
                "border": "dim",
            },
            "dark": {
                "header": "bold magenta",
                "row_even": "white",
                "row_odd": "bright_black",
                "highlight": "bold yellow",
                "border": "magenta",
            },
        }
        return themes.get(self.theme, themes["default"])

    def table(
        self,
        data: List[Dict[str, Any]],
        columns: Optional[List[str]] = None,
        title: Optional[str] = None,
        column_labels: Optional[Dict[str, str]] = None,
    ) -> None:
        """
        Render a generic table from list of dicts.

        Args:
            data: List of row dictionaries
            columns: Column keys to display (defaults to all keys from first row)
            title: Optional table title
            column_labels: Optional mapping of column keys to display labels
        """
        if not data:
            print("(no data)")
            return

        columns = columns or list(data[0].keys())
        column_labels = column_labels or {}

        if self.format == "rich":
            self._table_rich(data, columns, title, column_labels)
        elif self.format == "html":
            self._table_html(data, columns, title, column_labels)
        else:
            self._table_plain(data, columns, title, column_labels)

    def _table_rich(
        self,
        data: List[Dict[str, Any]],
        columns: List[str],
        title: Optional[str],
        column_labels: Dict[str, str],
    ) -> None:
        """Render table using rich library."""
        colors = self._get_theme_colors()
        table = Table(title=title, border_style=colors["border"])

        for col in columns:
            label = column_labels.get(col, col)
            table.add_column(label, style=colors["header"])

        for i, row in enumerate(data):
            style = colors["row_even"] if i % 2 == 0 else colors["row_odd"]
            table.add_row(*[str(row.get(col, "")) for col in columns], style=style)

        self._console.print(table)

    def _table_html(
        self,
        data: List[Dict[str, Any]],
        columns: List[str],
        title: Optional[str],
        column_labels: Dict[str, str],
    ) -> None:
        """Render table as styled HTML."""
        rows = [[row.get(col, "") for col in columns] for row in data]
        headers = [column_labels.get(col, col) for col in columns]

        html = tabulate(rows, headers=headers, tablefmt="html")

        # Add minimal styling
        styled_html = f"""
        <style>
            .report-table {{ border-collapse: collapse; margin: 10px 0; }}
            .report-table th {{ background: #f0f0f0; padding: 8px 12px; text-align: left; border-bottom: 2px solid #ddd; }}
            .report-table td {{ padding: 8px 12px; border-bottom: 1px solid #eee; }}
            .report-table tr:hover {{ background: #f9f9f9; }}
        </style>
        """
        if title:
            styled_html += f"<h4 style='margin-bottom: 5px;'>{title}</h4>"
        styled_html += html.replace("<table>", "<table class='report-table'>")

        display(HTML(styled_html))

    def _table_plain(
        self,
        data: List[Dict[str, Any]],
        columns: List[str],
        title: Optional[str],
        column_labels: Dict[str, str],
    ) -> None:
        """Render table as plain text."""
        if title:
            print(f"\n{title}")
            print("=" * len(title))

        rows = [[row.get(col, "") for col in columns] for row in data]
        headers = [column_labels.get(col, col) for col in columns]

        if _HAS_TABULATE:
            print(tabulate(rows, headers=headers, tablefmt="simple"))
        else:
            # Fallback: manual column padding
            widths = [max(len(str(h)), max(len(str(r[i])) for r in rows)) for i, h in enumerate(headers)]
            header_line = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
            print(header_line)
            print("-" * len(header_line))
            for row in rows:
                print("  ".join(str(v).ljust(w) for v, w in zip(row, widths)))

    def comparison_table(
        self,
        comparison: List[Dict[str, Any]],
        title: str = "Algorithm Comparison",
    ) -> None:
        """
        Render a comparison table from ComposerSession.compare() output.

        Args:
            comparison: List of comparison dicts from session.compare()
            title: Table title
        """
        self.table(
            data=comparison,
            columns=["algorithm", "avg_encrypt_ms", "avg_decrypt_ms", "throughput_mbps"],
            title=title,
            column_labels={
                "algorithm": "Algorithm",
                "avg_encrypt_ms": "Encrypt (ms)",
                "avg_decrypt_ms": "Decrypt (ms)",
                "throughput_mbps": "Throughput (MB/s)",
            },
        )

    def benchmark_table(
        self,
        benchmarks: Dict[str, Dict[str, Any]],
        title: str = "Benchmark Results",
    ) -> None:
        """
        Render benchmark results from ComposerSession.benchmark_all() output.

        Args:
            benchmarks: Dict mapping algorithm names to benchmark results
            title: Table title
        """
        if self.format == "rich":
            self._benchmark_rich(benchmarks, title)
        else:
            # Flatten for other formats
            for algo_name, results in benchmarks.items():
                algo_title = f"{title}: {algo_name}"
                data = [
                    {
                        "size": f"{b['size_bytes']:,} B",
                        "avg_encrypt_ms": b["avg_encrypt_ms"],
                        "avg_decrypt_ms": b["avg_decrypt_ms"],
                        "throughput_mbps": f"{b['throughput_mbps']} MB/s",
                    }
                    for b in results["benchmarks"]
                ]
                self.table(
                    data=data,
                    columns=["size", "avg_encrypt_ms", "avg_decrypt_ms", "throughput_mbps"],
                    title=algo_title,
                    column_labels={
                        "size": "Size",
                        "avg_encrypt_ms": "Encrypt (ms)",
                        "avg_decrypt_ms": "Decrypt (ms)",
                        "throughput_mbps": "Throughput",
                    },
                )
                print()

    def _benchmark_rich(
        self,
        benchmarks: Dict[str, Dict[str, Any]],
        title: str,
    ) -> None:
        """Render benchmark results using rich with grouped sections."""
        colors = self._get_theme_colors()

        for algo_name, results in benchmarks.items():
            table = Table(title=f"{algo_name}", border_style=colors["border"])
            table.add_column("Size", style=colors["header"])
            table.add_column("Encrypt (ms)", justify="right")
            table.add_column("Decrypt (ms)", justify="right")
            table.add_column("Throughput", justify="right")

            for i, b in enumerate(results["benchmarks"]):
                style = colors["row_even"] if i % 2 == 0 else colors["row_odd"]
                table.add_row(
                    f"{b['size_bytes']:,} B",
                    str(b["avg_encrypt_ms"]),
                    str(b["avg_decrypt_ms"]),
                    f"{b['throughput_mbps']} MB/s",
                    style=style,
                )

            self._console.print(table)
            self._console.print()

    def session_report(
        self,
        report: Dict[str, Dict[str, Any]],
        title: str = "Session Report",
    ) -> None:
        """
        Render a session report from ComposerSession.report() output.

        Args:
            report: Dict mapping algorithm names to metrics
            title: Report title
        """
        data = [
            {
                "algorithm": name,
                "operations": f"{m['encrypt_calls']}E / {m['decrypt_calls']}D",
                "avg_encrypt_ms": f"{m['avg_encrypt_ms']:.3f}",
                "avg_decrypt_ms": f"{m['avg_decrypt_ms']:.3f}",
                "total_bytes": f"{m['total_bytes_processed']:,}",
                "errors": m["errors"] if m["errors"] > 0 else "-",
            }
            for name, m in report.items()
        ]

        self.table(
            data=data,
            columns=["algorithm", "operations", "avg_encrypt_ms", "avg_decrypt_ms", "total_bytes", "errors"],
            title=title,
            column_labels={
                "algorithm": "Algorithm",
                "operations": "Operations",
                "avg_encrypt_ms": "Avg Encrypt (ms)",
                "avg_decrypt_ms": "Avg Decrypt (ms)",
                "total_bytes": "Total Bytes",
                "errors": "Errors",
            },
        )

    def test_results(
        self,
        results: Dict[str, bool],
        title: str = "Round-trip Tests",
    ) -> None:
        """
        Render test results from ComposerSession.test_all() output.

        Args:
            results: Dict mapping algorithm names to pass/fail booleans
            title: Report title
        """
        if self.format == "rich":
            colors = self._get_theme_colors()
            table = Table(title=title, border_style=colors["border"])
            table.add_column("Algorithm", style=colors["header"])
            table.add_column("Status", justify="center")

            for name, passed in results.items():
                status = Text("✓ PASS", style="bold green") if passed else Text("✗ FAIL", style="bold red")
                table.add_row(name, status)

            self._console.print(table)
        else:
            data = [
                {"algorithm": name, "status": "PASS" if passed else "FAIL"}
                for name, passed in results.items()
            ]
            self.table(data, columns=["algorithm", "status"], title=title)

    def heading(self, text: str, level: int = 1) -> None:
        """Print a styled heading."""
        if self.format == "rich":
            styles = {1: "bold cyan", 2: "bold", 3: "dim bold"}
            style = styles.get(level, "")
            self._console.print(Text(text, style=style))
            if level == 1:
                self._console.print("─" * len(text), style="dim")
        elif self.format == "html" and _HAS_IPYTHON:
            tag = f"h{min(level + 2, 6)}"
            display(HTML(f"<{tag}>{text}</{tag}>"))
        else:
            print(f"\n{text}")
            if level == 1:
                print("=" * len(text))
            elif level == 2:
                print("-" * len(text))

    def success(self, message: str) -> None:
        """Print a success message."""
        if self.format == "rich":
            self._console.print(f"[bold green]✓[/bold green] {message}")
        else:
            print(f"✓ {message}")

    def error(self, message: str) -> None:
        """Print an error message."""
        if self.format == "rich":
            self._console.print(f"[bold red]✗[/bold red] {message}")
        else:
            print(f"✗ {message}")

    def info(self, message: str) -> None:
        """Print an info message."""
        if self.format == "rich":
            self._console.print(f"[dim]ℹ[/dim] {message}")
        else:
            print(f"ℹ {message}")
