#!/usr/bin/env python3
from pathlib import Path
import sys


def main():
    if len(sys.argv) < 2:
        print('usage: check_report_format.py <report.md>')
        return 2
    p = Path(sys.argv[1])
    if not p.exists():
        print('missing report')
        return 2
    t = p.read_text()
    required = [
        '# DURO Audit Report',
        '## Findings (above confidence threshold)',
        '## Below Confidence Threshold',
    ]
    missing = [r for r in required if r not in t]
    if missing:
        print('format check failed:', ', '.join(missing))
        return 1
    print('format check ok')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
