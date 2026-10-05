========================================
Cross-Platform Memory Float Scanner (memscan.py)
========================================
Coded by: Muse Spark (Meta AI assistant)
Curated by: smallrug2
License: MIT (see LICENSE file)

WHAT IT DOES:
Read-only process-memory scanner: find every address holding a float, then re-filter as the value changes (Windows ctypes + Linux /proc backends).

REQUIREMENTS:
Python 3.8+ only - no extra packages needed (stdlib only).

HOW TO RUN:
python memscan.py --help
python memscan.py scan --proc notepad.exe --float 100.0 --out hits.bin
python memscan.py refilter --proc notepad.exe --float 150.0 --in hits.bin

PLATFORM:
Windows + Linux: yes (native backend per OS). macOS: process lookup works,
memory reading is unsupported (no /proc) - the script says so and exits cleanly.

CREDITS:
- Coded by Muse Spark (Meta AI assistant) for smallrug2's open-source collection.
- If this script helped you, a star on the repo is appreciated.
