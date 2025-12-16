#!/usr/bin/env python3
"""
Simple CLI wrapper around the rebuilt analyzer.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .services.analyzer import JavaScriptAnalyzer


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="JavaScript Security Analyzer (server-side)")
    parser.add_argument("urls", nargs="+", help="URL(s) to JavaScript files")
    args = parser.parse_args(argv)

    analyzer = JavaScriptAnalyzer()
    results = []
    for url in args.urls:
        print(f"[+] Analyzing {url} ...")
        results.append(analyzer.analyze(url))

    for result in results:
        print("=" * 80)
        print(f"URL: {result.url}")
        print(f"File size: {result.file_size} bytes")
        if result.errors:
            print("Errors:")
            for err in result.errors:
                print(f"  - {err}")
        print(f"API Keys: {len(result.api_keys)} | Credentials: {len(result.credentials)} | XSS: {len(result.xss_vulnerabilities)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

