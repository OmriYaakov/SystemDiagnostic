# Windows System Diagnostic Tool

A comprehensive PowerShell script that analyzes your Windows PC's performance and generates a beautiful, self-contained HTML report with actionable recommendations.

![Dark Mode](https://img.shields.io/badge/theme-dark%20mode-0d1117?style=flat-square)
![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-blue?style=flat-square)
![Windows 10/11](https://img.shields.io/badge/Windows-10%20%7C%2011-0078D6?style=flat-square)

## Features

### 24 Diagnostic Categories
- **System Info** - OS version, hardware specs, uptime
- **CPU** - Usage, per-core stats, top processes, sustained high CPU detection
- **Memory** - RAM usage, page file, commit charge, top memory consumers
- **Disk I/O** - Volume space, read/write rates, latency, queue length
- **Disk Health** - SMART data, wear level, temperature (requires admin)
- **Network** - Adapters, throughput, TCP connections
- **Processes** - Top by CPU/memory, high handle counts
- **Startup Programs** - Registry run keys, startup folder, scheduled tasks
- **Event Log** - Critical/error events from last 24 hours (requires admin)
- **Thermal** - Throttling detection, thermal events
- **Power Plan** - Active plan, processor states, battery status
- **Visual Effects** - Windows animation settings
- **Services** - Disableable services with performance impact
- **Storage** - Temp files, recycle bin, Storage Sense status
- **Bloatware** - Preinstalled apps that can be removed
- **Background Apps** - Apps running in the background
- **Privacy/Telemetry** - Tracking features status
- **Game Mode** - Gaming optimizations, Game DVR, GPU scheduling
- **Browsers** - Installed browsers, memory usage
- **Drivers** - Problem devices, outdated drivers
- **Windows Update** - Pending updates, delivery optimization
- **Windows Search** - Indexing service status
- **Windows Defender** - Real-time protection, scan status
- **Virtual Memory** - Page file configuration

### Report Features
- **Self-contained HTML** - No external dependencies, works offline
- **Dark/Light mode** - Toggle between themes (dark mode default)
- **Severity indicators** - Green/yellow/red status badges
- **Collapsible sections** - Expand/collapse all with one click
- **Actionable recommendations** - Prioritized tips to improve performance
- **Print-friendly** - Optimized for printing/PDF export

## Installation

No installation required. Just download and run:

```powershell
# Download the script
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/YOUR_USERNAME/SystemDiagnostic/main/SystemDiagnostic.ps1" -OutFile "SystemDiagnostic.ps1"

# Run it
.\SystemDiagnostic.ps1
```

Or clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/SystemDiagnostic.git
cd SystemDiagnostic
```

## Usage

### Basic Usage (Standard User)
```powershell
.\SystemDiagnostic.ps1
```
Runs with standard user privileges. Some diagnostics will be skipped.

### Full Diagnostics (Administrator)
```powershell
.\SystemDiagnostic.ps1 -Elevate
```
Automatically elevates to administrator for full diagnostics including:
- Disk Health (SMART data)
- Event Log analysis
- Thermal events

### Custom Output Location
```powershell
.\SystemDiagnostic.ps1 -OutputPath "C:\Reports\MyDiagnostic.html"
```

### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-Elevate` | Switch | Re-launch script as Administrator |
| `-OutputPath` | String | Custom path for the HTML report (default: Desktop) |

## Screenshots

### Dashboard
The dashboard shows overall system health at a glance with color-coded cards.

### Dark Mode (Default)
Clean, modern dark theme that's easy on the eyes.

### Light Mode
Toggle to light mode with a single click.

### Recommendations
Prioritized, actionable recommendations sorted by severity.

## Requirements

- **OS**: Windows 10 / Windows 11
- **PowerShell**: 5.1 or later (pre-installed on Windows 10/11)
- **Permissions**: Standard user (limited) or Administrator (full)

## What Gets Analyzed

| Category | Standard User | Administrator |
|----------|:-------------:|:-------------:|
| System Info | ✅ | ✅ |
| CPU Usage | ✅ | ✅ |
| Memory | ✅ | ✅ |
| Disk I/O | ✅ | ✅ |
| Disk Health (SMART) | ❌ | ✅ |
| Network | ✅ | ✅ |
| Processes | ✅ | ✅ |
| Startup Programs | ✅ | ✅ |
| Event Logs | ❌ | ✅ |
| Thermal/Throttling | Partial | ✅ |
| Power Plan | ✅ | ✅ |
| Services | ✅ | ✅ |
| Storage/Temp Files | ✅ | ✅ |
| Bloatware Detection | ✅ | ✅ |
| Privacy Settings | ✅ | ✅ |
| Drivers | ✅ | ✅ |
| Windows Update | ✅ | ✅ |

## Privacy & Security

- **100% Local** - All analysis happens on your machine
- **No Data Collection** - Nothing is sent anywhere
- **No External Calls** - No internet required
- **Read-Only** - Script only reads system information, never modifies anything
- **Open Source** - Full source code available for review

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with PowerShell and vanilla HTML/CSS/JS
- Icons from [Feather Icons](https://feathericons.com/) (MIT License)
- Inspired by the need for a simple, comprehensive Windows diagnostic tool

---

**Note**: This tool is for diagnostic purposes only. Always backup your system before making any changes based on the recommendations.
