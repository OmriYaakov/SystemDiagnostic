# System Diagnostic Tool

A comprehensive system health diagnostic tool that generates beautiful HTML reports with actionable recommendations. Available for both **Windows** and **macOS**.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20macOS-lightgrey.svg)

## Features

- **One-click diagnostics** - Run a single script to analyze your entire system
- **Beautiful HTML reports** - Dark-themed, responsive reports that open in your browser
- **Health scoring** - Overall system health rated as Good/Warning/Critical
- **Actionable recommendations** - Specific steps to fix identified issues
- **No installation required** - Just download and run

### What's Analyzed

| Category | Windows | macOS |
|----------|---------|-------|
| System Information | ✅ | ✅ |
| CPU Usage & Top Processes | ✅ | ✅ |
| Memory/RAM Usage | ✅ | ✅ |
| Disk Space & Health (SMART) | ✅ | ✅ |
| Network Connections | ✅ | ✅ |
| Running Processes | ✅ | ✅ |
| Startup Programs | ✅ | ✅ |
| Thermal/Throttling | ✅ | ✅ |
| Battery Health (Laptops) | ✅ | ✅ |
| Security Status | ✅ | ✅ |
| Storage Cleanup | ✅ | ✅ |
| Pending Updates | ✅ | ✅ |
| Power Plan Settings | ✅ | - |
| Visual Effects | ✅ | - |
| Windows Services | ✅ | - |
| Bloatware Detection | ✅ | - |
| FileVault/SIP Status | - | ✅ |

## Screenshots

### Report Overview
```
┌─────────────────────────────────────────────────┐
│     macOS System Diagnostic Report              │
│     omri's MacBook Air - 2026-02-04             │
│                                                 │
│         ┌─────────────────────────┐             │
│         │ Overall Health: Good    │             │
│         └─────────────────────────┘             │
│                                                 │
│  ┌─ System Information ─────────── 0d 5h 12m ─┐ │
│  │ Computer: MacBook Air                      │ │
│  │ Chip: Apple M1 | Memory: 16 GB             │ │
│  │ macOS: 26.2 | Uptime: 5 hours              │ │
│  └────────────────────────────────────────────┘ │
│                                                 │
│  ┌─ CPU Diagnostics ──────────────────── 12% ─┐ │
│  │ ████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 12%  │ │
│  └────────────────────────────────────────────┘ │
│                                                 │
│  ┌─ Memory Diagnostics ───────────────── 45% ─┐ │
│  │ ██████████████████░░░░░░░░░░░░░░░░░░ 45%  │ │
│  └────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────┘
```

## Installation

### Windows

1. **Download** `SystemDiagnostic.ps1`
2. **Right-click** the file and select "Run with PowerShell"

   Or run from PowerShell:
   ```powershell
   .\SystemDiagnostic.ps1
   ```

3. **For full diagnostics** (SMART data, event logs), run as Administrator:
   ```powershell
   .\SystemDiagnostic.ps1 -Elevate
   ```

### macOS

1. **Download** `SystemDiagnostic.sh`

2. **Make executable** (first time only):
   ```bash
   chmod +x SystemDiagnostic.sh
   ```

3. **Run**:
   ```bash
   ./SystemDiagnostic.sh
   ```

   Or with bash:
   ```bash
   bash SystemDiagnostic.sh
   ```

4. **For full diagnostics** (thermal data), run with sudo:
   ```bash
   sudo ./SystemDiagnostic.sh
   ```

## Usage

### Windows PowerShell Options

```powershell
# Basic run - generates report and opens in browser
.\SystemDiagnostic.ps1

# Run with admin privileges for full diagnostics
.\SystemDiagnostic.ps1 -Elevate

# Custom output path
.\SystemDiagnostic.ps1 -OutputPath "C:\Reports\myreport.html"

# Don't open browser after generating
.\SystemDiagnostic.ps1 -SkipBrowserOpen

# Custom sampling duration (1-30 seconds)
.\SystemDiagnostic.ps1 -SampleDurationSeconds 5
```

### macOS Bash Options

```bash
# Basic run - generates report and opens in browser
./SystemDiagnostic.sh

# Custom output path
./SystemDiagnostic.sh -o ~/Reports/myreport.html

# Don't open browser after generating
./SystemDiagnostic.sh -s

# Show help
./SystemDiagnostic.sh -h
```

## Output

Reports are saved to your **Desktop** by default with the naming format:
```
SystemDiag_<ComputerName>_<Timestamp>.html
```

Example: `SystemDiag_MacBookAir_20260204_153045.html`

## Understanding the Report

### Severity Levels

| Color | Level | Meaning |
|-------|-------|---------|
| 🟢 Green | Good | No issues detected |
| 🟡 Yellow | Warning | Potential issues, optimization recommended |
| 🔴 Red | Critical | Issues requiring attention |

### Thresholds

| Metric | Yellow | Red |
|--------|--------|-----|
| CPU Usage | 60% | 85% |
| Memory Usage | 70% | 90% |
| Disk Space Used | 80% | 90% |
| System Uptime | 7 days | 30 days |
| Startup Items | 10 items | 20 items |
| Process Count | 200 | 400 |
| TCP Connections | 200 | 500 |

## Recommendations

The report includes actionable recommendations for each issue found:

### Example Recommendations

**High CPU Usage**
> CPU usage at 92%. Top process: chrome.
>
> *Action: Open Activity Monitor/Task Manager, sort by CPU, identify and close problematic apps.*

**Disk Space Low**
> Drive C: is 94% full (12 GB free).
>
> *Action: Run Disk Cleanup, clear temp files, uninstall unused programs.*

**Firewall Disabled**
> macOS Firewall is not enabled.
>
> *Action: System Settings > Network > Firewall > Turn On.*

## Requirements

### Windows
- Windows 10/11
- PowerShell 5.1 or later (included with Windows)
- No additional software required

### macOS
- macOS 10.14 (Mojave) or later
- Bash (included with macOS)
- No additional software required

## Privacy & Security

- **No data is sent anywhere** - Everything runs locally
- **No installation** - No changes to your system
- **Open source** - Review the code yourself
- **Read-only** - Only reads system information, never modifies anything

## Troubleshooting

### Windows

**"Running scripts is disabled on this system"**
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
.\SystemDiagnostic.ps1
```

**Some diagnostics show "Skipped"**

Run with `-Elevate` flag for full diagnostics:
```powershell
.\SystemDiagnostic.ps1 -Elevate
```

### macOS

**"Permission denied"**
```bash
chmod +x SystemDiagnostic.sh
```

**"command not found: bc"**

The `bc` calculator should be included with macOS. If missing:
```bash
brew install bc
```

**Some values show "Unknown"**

Run with `sudo` for additional diagnostics:
```bash
sudo ./SystemDiagnostic.sh
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Ideas for Contributions
- Linux support
- Additional diagnostic checks
- Localization/translations
- GUI wrapper application
- Scheduled/automated runs

## License

MIT License - feel free to use, modify, and distribute.

## Acknowledgments

- Inspired by various system information tools
- Built with native OS tools (PowerShell, Bash)
- No external dependencies

---

**Made with ❤️ for system administrators, developers, and power users**

*If this tool helped you, consider giving it a ⭐ on GitHub!*
