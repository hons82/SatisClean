# SatisClean - Go Duplicate File Scanner

[![CI Build & Test](https://github.com/hons82/SatisClean/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/hons82/SatisClean/actions/workflows/ci.yml)
[![Build and Release](https://github.com/hons82/SatisClean/actions/workflows/release.yml/badge.svg)](https://github.com/hons82/SatisClean/actions/workflows/release.yml)

A fast and efficient Go program to **find and manage duplicate files** on your system.  
It supports recursive scanning, hash-based duplicate detection, interactive deletion, and automatic handling of numbered duplicates in the same folder.

---

## Features

- Scan folders recursively for duplicate files
- Detect duplicates by **file hash** (MD5)
- Automatically handle files with numbered suffixes (e.g., `_1`, `(1)`, `_copy`)
- Keep original/base filenames and delete duplicates in the same folder
- Interactive mode for manual selection
- Dry-run mode to preview deletions
- Save a detailed JSON report
- Rich summary including:
  - Total duplicate files
  - Files deleted
  - Files kept
  - Potential and actual space reclaimed
  - Average size per duplicate
  - Largest duplicate file
- Concurrent hashing for speed
- Supports configurable file extensions

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/hons82/SatisClean.git
cd SatisClean
```
Build the binary:

```bash
go build -o satisclean ./cmd
```

Or run directly using Go:

```bash
go run main.go scan -p /path/to/folder
```

Usage

```bash
satisclean scan --path <folder> [options]
```

## Options
| Flag                     | Description |
|---------------------------|-------------|
| `--path, -p`              | Root folder to scan (required) |
| `--ext, -e`               | File extensions to include (default: `.jpg,.jpeg,.png`) |
| `--delete, -d`            | Delete duplicate files automatically (keep one copy) |
| `--dry-run, -n`           | Simulate deletion without removing files |
| `--interactive, -i`       | Ask which duplicates to delete interactively |
| `--global-choice`         | Apply choice to all groups (`k`=keep, `a`=auto delete, `s`=select manually, `q`=quit) |
| `--workers, -w`           | Number of concurrent hashing workers (default: number of CPU cores) |
| `--report`                | Path to save JSON report |
| `--prefer-base-name`      | Keep base filename and delete numbered copies in the same folder (default: true) |


## Examples

Interactive scan:

```bash
satisclean scan -p ~/Pictures --interactive
```

Automatic deletion with JSON report:

```bash
satisclean scan -p ~/Downloads --delete --prefer-base-name --report report.json
```

Dry-run simulation:

```bash
satisclean scan -p ~/Documents --dry-run --report dupreport.json
```

Keep all duplicates automatically (no prompts):

```bash
satisclean scan -p ~/Downloads --global-choice k
```
# License

This project is licensed under the MIT License. See LICENSE.md for details.
