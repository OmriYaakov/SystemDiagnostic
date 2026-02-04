#!/bin/bash
#
# macOS System Diagnostic Tool
# Generates an HTML health report analyzing system performance
#
# Usage:
#   ./SystemDiagnostic.sh                    # Run and open report
#   ./SystemDiagnostic.sh -o /path/to/file   # Custom output path
#   ./SystemDiagnostic.sh -s                 # Skip opening browser
#
# Requires: macOS 10.14+
#

# Don't exit on errors - we want to continue even if some commands fail
set +e

# --- Configuration ---
OUTPUT_PATH=""
SKIP_BROWSER_OPEN=false
SCRIPT_START=$(date +%s)

# --- Parse Arguments ---
while getopts "o:sh" opt; do
    case $opt in
        o) OUTPUT_PATH="$OPTARG" ;;
        s) SKIP_BROWSER_OPEN=true ;;
        h)
            echo "Usage: $0 [-o output_path] [-s skip_browser]"
            exit 0
            ;;
        *) echo "Invalid option" >&2; exit 1 ;;
    esac
done

# Default output path
if [ -z "$OUTPUT_PATH" ]; then
    TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    OUTPUT_PATH="$HOME/Desktop/SystemDiag_$(hostname -s)_${TIMESTAMP}.html"
fi

# Check if running as root
IS_ROOT=false
if [ "$EUID" -eq 0 ] 2>/dev/null || [ "$(id -u)" -eq 0 ]; then
    IS_ROOT=true
fi

echo "Starting macOS System Diagnostics..."
echo "Output: $OUTPUT_PATH"

# --- Create temp directory ---
DIAG_TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$DIAG_TEMP_DIR"' EXIT

# Initialize severity tracking
echo "green" > "$DIAG_TEMP_DIR/overall_severity.txt"

update_overall_severity() {
    local new_sev="$1"
    local current=$(cat "$DIAG_TEMP_DIR/overall_severity.txt")

    if [ "$new_sev" = "red" ]; then
        echo "red" > "$DIAG_TEMP_DIR/overall_severity.txt"
    elif [ "$new_sev" = "yellow" ] && [ "$current" != "red" ]; then
        echo "yellow" > "$DIAG_TEMP_DIR/overall_severity.txt"
    fi
}

# --- Utility Functions ---

html_encode() {
    local text="$1"
    echo "$text" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g; s/"/\&quot;/g'
}

# ============================================================================
# COLLECT SYSTEM INFO
# ============================================================================

echo ""
echo "Running diagnostics..."
echo "  Collecting system information..."

# Get system profiler data (this is slow but comprehensive)
sp_hardware=$(system_profiler SPHardwareDataType 2>/dev/null || echo "")
sp_software=$(system_profiler SPSoftwareDataType 2>/dev/null || echo "")

# Parse hardware info
SYS_MODEL_NAME=$(echo "$sp_hardware" | grep "Model Name:" | cut -d: -f2 | xargs 2>/dev/null || echo "Unknown")
SYS_MODEL_ID=$(echo "$sp_hardware" | grep "Model Identifier:" | cut -d: -f2 | xargs 2>/dev/null || echo "Unknown")
SYS_CHIP=$(echo "$sp_hardware" | grep -E "Chip:|Processor Name:" | head -1 | cut -d: -f2 | xargs 2>/dev/null || echo "Unknown")
SYS_CPU_CORES=$(echo "$sp_hardware" | grep -E "Total Number of Cores:" | head -1 | cut -d: -f2 | xargs 2>/dev/null | cut -d' ' -f1 || echo "Unknown")
SYS_MEMORY=$(echo "$sp_hardware" | grep "Memory:" | cut -d: -f2 | xargs 2>/dev/null || echo "Unknown")

# Parse software info
SYS_OS_VERSION=$(echo "$sp_software" | grep "System Version:" | cut -d: -f2 | xargs 2>/dev/null || echo "Unknown")
SYS_KERNEL=$(echo "$sp_software" | grep "Kernel Version:" | cut -d: -f2 | xargs 2>/dev/null || echo "Unknown")
SYS_COMPUTER_NAME=$(echo "$sp_software" | grep "Computer Name:" | cut -d: -f2 | xargs 2>/dev/null || hostname -s)

# Calculate uptime - use the 'uptime' command which is more reliable
uptime_output=$(uptime 2>/dev/null || echo "")
if [ -n "$uptime_output" ]; then
    # Parse uptime output - handles formats like:
    # "23:35  up 2 days, 3:45, 2 users"
    # "23:35  up 45 mins, 2 users"
    # "23:35  up 3:45, 2 users"

    if echo "$uptime_output" | grep -q "day"; then
        # Has days
        SYS_UPTIME_DAYS=$(echo "$uptime_output" | sed -E 's/.*up ([0-9]+) day.*/\1/')
        time_part=$(echo "$uptime_output" | sed -E 's/.*day[s]?,? *([0-9:]+).*/\1/' | cut -d',' -f1)
        if echo "$time_part" | grep -q ":"; then
            uptime_hours=$(echo "$time_part" | cut -d: -f1)
            uptime_mins=$(echo "$time_part" | cut -d: -f2 | grep -o '[0-9]*')
        else
            uptime_hours=0
            uptime_mins=0
        fi
    elif echo "$uptime_output" | grep -q "hr\|hour"; then
        # Hours but no days
        SYS_UPTIME_DAYS=0
        uptime_hours=$(echo "$uptime_output" | sed -E 's/.*up ([0-9]+) (hr|hour).*/\1/')
        uptime_mins=0
    elif echo "$uptime_output" | grep -q "min"; then
        # Only minutes
        SYS_UPTIME_DAYS=0
        uptime_hours=0
        uptime_mins=$(echo "$uptime_output" | sed -E 's/.*up ([0-9]+) min.*/\1/')
    else
        # Format like "up 3:45" (hours:mins)
        SYS_UPTIME_DAYS=0
        time_part=$(echo "$uptime_output" | sed -E 's/.*up +([0-9]+:[0-9]+).*/\1/')
        if echo "$time_part" | grep -q ":"; then
            uptime_hours=$(echo "$time_part" | cut -d: -f1)
            uptime_mins=$(echo "$time_part" | cut -d: -f2 | grep -o '[0-9]*')
        else
            uptime_hours=0
            uptime_mins=0
        fi
    fi

    # Ensure values are numbers
    SYS_UPTIME_DAYS=${SYS_UPTIME_DAYS:-0}
    uptime_hours=${uptime_hours:-0}
    uptime_mins=${uptime_mins:-0}

    # Remove any non-numeric characters
    SYS_UPTIME_DAYS=$(echo "$SYS_UPTIME_DAYS" | grep -o '[0-9]*' | head -1)
    uptime_hours=$(echo "$uptime_hours" | grep -o '[0-9]*' | head -1)
    uptime_mins=$(echo "$uptime_mins" | grep -o '[0-9]*' | head -1)

    SYS_UPTIME_DAYS=${SYS_UPTIME_DAYS:-0}
    uptime_hours=${uptime_hours:-0}
    uptime_mins=${uptime_mins:-0}

    SYS_UPTIME_TEXT="${SYS_UPTIME_DAYS}d ${uptime_hours}h ${uptime_mins}m"
else
    SYS_UPTIME_DAYS=0
    SYS_UPTIME_TEXT="Unknown"
fi

# RAM in GB
total_ram_bytes=$(sysctl -n hw.memsize 2>/dev/null || echo "0")
if [ "$total_ram_bytes" -gt 0 ] 2>/dev/null; then
    SYS_TOTAL_RAM_GB=$(echo "scale=1; $total_ram_bytes / 1073741824" | bc 2>/dev/null || echo "Unknown")
else
    SYS_TOTAL_RAM_GB="Unknown"
fi

# System severity based on uptime
SYS_SEVERITY="green"
if [ "$SYS_UPTIME_DAYS" -ge 30 ] 2>/dev/null; then
    SYS_SEVERITY="red"
    update_overall_severity "red"
elif [ "$SYS_UPTIME_DAYS" -ge 7 ] 2>/dev/null; then
    SYS_SEVERITY="yellow"
    update_overall_severity "yellow"
fi

# ============================================================================
# COLLECT CPU INFO
# ============================================================================

echo "  Collecting CPU diagnostics..."

# Get CPU usage - simpler method that works reliably
CPU_IDLE=$(top -l 1 -n 0 2>/dev/null | grep "CPU usage" | awk '{print $7}' | tr -d '%' || echo "0")
if [ -n "$CPU_IDLE" ] && [ "$CPU_IDLE" != "0" ]; then
    CPU_USAGE=$(echo "100 - $CPU_IDLE" | bc 2>/dev/null || echo "0")
else
    # Fallback: sum all process CPU
    CPU_USAGE=$(ps -A -o %cpu 2>/dev/null | awk '{s+=$1} END {printf "%.0f", s}' || echo "0")
    # Cap at 100 per core, estimate
    if [ "$CPU_USAGE" -gt 100 ] 2>/dev/null; then
        num_cores=$(sysctl -n hw.ncpu 2>/dev/null || echo "1")
        CPU_USAGE=$(echo "$CPU_USAGE / $num_cores" | bc 2>/dev/null || echo "50")
    fi
fi

# Ensure CPU_USAGE is a number
CPU_USAGE=$(echo "$CPU_USAGE" | grep -o '[0-9]*' | head -1 || echo "0")
CPU_USAGE=${CPU_USAGE:-0}

# Get top processes by CPU
ps aux -r 2>/dev/null | head -11 | tail -10 > "$DIAG_TEMP_DIR/cpu_top_procs.txt" || echo "" > "$DIAG_TEMP_DIR/cpu_top_procs.txt"

# CPU severity
CPU_SEVERITY="green"
if [ "$CPU_USAGE" -ge 85 ] 2>/dev/null; then
    CPU_SEVERITY="red"
    update_overall_severity "red"
elif [ "$CPU_USAGE" -ge 60 ] 2>/dev/null; then
    CPU_SEVERITY="yellow"
    update_overall_severity "yellow"
fi

# ============================================================================
# COLLECT MEMORY INFO
# ============================================================================

echo "  Collecting memory diagnostics..."

# Get memory stats using vm_stat
vm_stat_output=$(vm_stat 2>/dev/null || echo "")
page_size=4096

if [ -n "$vm_stat_output" ]; then
    pages_free=$(echo "$vm_stat_output" | grep "Pages free:" | awk '{print $3}' | tr -d '.')
    pages_active=$(echo "$vm_stat_output" | grep "Pages active:" | awk '{print $3}' | tr -d '.')
    pages_inactive=$(echo "$vm_stat_output" | grep "Pages inactive:" | awk '{print $3}' | tr -d '.')
    pages_speculative=$(echo "$vm_stat_output" | grep "Pages speculative:" | awk '{print $3}' | tr -d '.')
    pages_wired=$(echo "$vm_stat_output" | grep "Pages wired down:" | awk '{print $4}' | tr -d '.')
    pages_compressed=$(echo "$vm_stat_output" | grep "Pages stored in compressor:" | awk '{print $5}' | tr -d '.')

    # Default to 0 if empty
    pages_free=${pages_free:-0}
    pages_active=${pages_active:-0}
    pages_inactive=${pages_inactive:-0}
    pages_speculative=${pages_speculative:-0}
    pages_wired=${pages_wired:-0}
    pages_compressed=${pages_compressed:-0}

    # Calculate used memory
    used_pages=$((pages_active + pages_wired + pages_compressed))
    MEM_USED_BYTES=$((used_pages * page_size))
    MEM_FREE_BYTES=$((pages_free * page_size))

    if [ "$total_ram_bytes" -gt 0 ] 2>/dev/null; then
        MEM_USED_PCT=$(echo "scale=1; $MEM_USED_BYTES * 100 / $total_ram_bytes" | bc 2>/dev/null || echo "0")
    else
        MEM_USED_PCT="0"
    fi
else
    MEM_USED_PCT="0"
    MEM_USED_BYTES="0"
    MEM_FREE_BYTES="0"
fi

MEM_TOTAL_BYTES="$total_ram_bytes"

# Swap usage
swap_info=$(sysctl -n vm.swapusage 2>/dev/null || echo "")
if [ -n "$swap_info" ]; then
    MEM_SWAP_USED=$(echo "$swap_info" | awk '{print $6}' | tr -d 'M' || echo "0")
else
    MEM_SWAP_USED="0"
fi
MEM_SWAP_USED=${MEM_SWAP_USED:-0}

# Get top processes by memory
ps aux -m 2>/dev/null | head -11 | tail -10 > "$DIAG_TEMP_DIR/memory_top_procs.txt" || echo "" > "$DIAG_TEMP_DIR/memory_top_procs.txt"

# Memory severity
MEM_SEVERITY="green"
mem_pct_int=$(echo "$MEM_USED_PCT" | cut -d. -f1)
mem_pct_int=${mem_pct_int:-0}

if [ "$mem_pct_int" -ge 90 ] 2>/dev/null; then
    MEM_SEVERITY="red"
    update_overall_severity "red"
elif [ "$mem_pct_int" -ge 70 ] 2>/dev/null; then
    MEM_SEVERITY="yellow"
    update_overall_severity "yellow"
fi

# ============================================================================
# COLLECT DISK INFO
# ============================================================================

echo "  Collecting disk diagnostics..."

# Get disk usage
> "$DIAG_TEMP_DIR/disk_volumes.txt"
DISK_SEVERITY="green"

df -h 2>/dev/null | grep "^/dev" | while read -r line; do
    device=$(echo "$line" | awk '{print $1}')
    size=$(echo "$line" | awk '{print $2}')
    used=$(echo "$line" | awk '{print $3}')
    avail=$(echo "$line" | awk '{print $4}')
    pct=$(echo "$line" | awk '{print $5}' | tr -d '%')
    mount=$(echo "$line" | awk '{for(i=9;i<=NF;i++) printf $i" "; print ""}' | xargs)

    # Volume name
    vol_name=$(diskutil info "$mount" 2>/dev/null | grep "Volume Name:" | cut -d: -f2 | xargs 2>/dev/null || echo "$mount")
    vol_name=${vol_name:-$mount}

    # Severity
    vol_sev="green"
    if [ "$pct" -ge 90 ] 2>/dev/null; then
        vol_sev="red"
    elif [ "$pct" -ge 80 ] 2>/dev/null; then
        vol_sev="yellow"
    fi

    echo "$device|$vol_name|$size|$used|$avail|$pct|$mount|$vol_sev" >> "$DIAG_TEMP_DIR/disk_volumes.txt"
done

# Update overall disk severity
while IFS='|' read -r device name size used avail pct mount vol_sev; do
    if [ "$vol_sev" = "red" ]; then
        DISK_SEVERITY="red"
        update_overall_severity "red"
    elif [ "$vol_sev" = "yellow" ] && [ "$DISK_SEVERITY" != "red" ]; then
        DISK_SEVERITY="yellow"
        update_overall_severity "yellow"
    fi
done < "$DIAG_TEMP_DIR/disk_volumes.txt"

# SMART status
SMART_STATUS="Unknown"
disk_info=$(diskutil info / 2>/dev/null || echo "")
if echo "$disk_info" | grep -q "SMART Status"; then
    smart_val=$(echo "$disk_info" | grep "SMART Status:" | cut -d: -f2 | xargs)
    if [ "$smart_val" = "Verified" ]; then
        SMART_STATUS="Healthy"
    elif [ "$smart_val" = "Failing" ]; then
        SMART_STATUS="Failing"
        update_overall_severity "red"
    else
        SMART_STATUS="$smart_val"
    fi
fi

DISKH_SEVERITY="green"
if [ "$SMART_STATUS" = "Failing" ]; then
    DISKH_SEVERITY="red"
fi

# ============================================================================
# COLLECT NETWORK INFO
# ============================================================================

echo "  Collecting network diagnostics..."

# Get active network interfaces
> "$DIAG_TEMP_DIR/network_adapters.txt"

for iface in $(ifconfig -l 2>/dev/null); do
    iface_info=$(ifconfig "$iface" 2>/dev/null || echo "")
    if echo "$iface_info" | grep -q "status: active"; then
        ip_addr=$(echo "$iface_info" | grep "inet " | head -1 | awk '{print $2}')
        echo "$iface|Network Interface|active|$ip_addr" >> "$DIAG_TEMP_DIR/network_adapters.txt"
    fi
done

# Connection counts
NET_ESTABLISHED=$(netstat -an 2>/dev/null | grep -c ESTABLISHED || echo "0")
NET_LISTENING=$(netstat -an 2>/dev/null | grep -c LISTEN || echo "0")
NET_TOTAL=$((NET_ESTABLISHED + NET_LISTENING))

NET_SEVERITY="green"
if [ "$NET_ESTABLISHED" -ge 500 ] 2>/dev/null; then
    NET_SEVERITY="red"
    update_overall_severity "red"
elif [ "$NET_ESTABLISHED" -ge 200 ] 2>/dev/null; then
    NET_SEVERITY="yellow"
    update_overall_severity "yellow"
fi

# ============================================================================
# COLLECT PROCESS INFO
# ============================================================================

echo "  Collecting process diagnostics..."

PROC_TOTAL_COUNT=$(ps aux 2>/dev/null | wc -l | xargs)
PROC_TOTAL_COUNT=$((PROC_TOTAL_COUNT - 1))  # Remove header

PROC_ZOMBIE_COUNT=$(ps aux 2>/dev/null | awk '$8 ~ /Z/' | wc -l | xargs || echo "0")

PROC_SEVERITY="green"
if [ "$PROC_TOTAL_COUNT" -ge 400 ] 2>/dev/null; then
    PROC_SEVERITY="red"
    update_overall_severity "red"
elif [ "$PROC_TOTAL_COUNT" -ge 200 ] 2>/dev/null; then
    PROC_SEVERITY="yellow"
    update_overall_severity "yellow"
fi

# ============================================================================
# COLLECT STARTUP ITEMS
# ============================================================================

echo "  Collecting startup items..."

> "$DIAG_TEMP_DIR/startup_items.txt"
STARTUP_COUNT=0

# User LaunchAgents
if [ -d "$HOME/Library/LaunchAgents" ]; then
    for plist in "$HOME/Library/LaunchAgents"/*.plist; do
        if [ -f "$plist" ]; then
            name=$(basename "$plist" .plist)
            echo "User LaunchAgent|$name|$plist" >> "$DIAG_TEMP_DIR/startup_items.txt"
            STARTUP_COUNT=$((STARTUP_COUNT + 1))
        fi
    done
fi

# System LaunchAgents
if [ -d "/Library/LaunchAgents" ]; then
    for plist in /Library/LaunchAgents/*.plist; do
        if [ -f "$plist" ]; then
            name=$(basename "$plist" .plist)
            echo "System LaunchAgent|$name|$plist" >> "$DIAG_TEMP_DIR/startup_items.txt"
            STARTUP_COUNT=$((STARTUP_COUNT + 1))
        fi
    done
fi

# LaunchDaemons
if [ -d "/Library/LaunchDaemons" ]; then
    for plist in /Library/LaunchDaemons/*.plist; do
        if [ -f "$plist" ]; then
            name=$(basename "$plist" .plist)
            echo "LaunchDaemon|$name|$plist" >> "$DIAG_TEMP_DIR/startup_items.txt"
            STARTUP_COUNT=$((STARTUP_COUNT + 1))
        fi
    done
fi

STARTUP_SEVERITY="green"
if [ "$STARTUP_COUNT" -ge 20 ] 2>/dev/null; then
    STARTUP_SEVERITY="red"
    update_overall_severity "red"
elif [ "$STARTUP_COUNT" -ge 10 ] 2>/dev/null; then
    STARTUP_SEVERITY="yellow"
    update_overall_severity "yellow"
fi

# ============================================================================
# COLLECT BATTERY INFO (if laptop)
# ============================================================================

echo "  Collecting battery diagnostics..."

BAT_IS_LAPTOP="false"
BAT_SEVERITY="green"

battery_info=$(system_profiler SPPowerDataType 2>/dev/null || echo "")
if echo "$battery_info" | grep -q "Battery Information"; then
    BAT_IS_LAPTOP="true"

    BAT_CHARGE_PCT=$(echo "$battery_info" | grep "State of Charge" | awk '{print $5}' | tr -d '%' || echo "N/A")
    BAT_HEALTH=$(echo "$battery_info" | grep "Condition:" | cut -d: -f2 | xargs 2>/dev/null || echo "N/A")
    BAT_CYCLE_COUNT=$(echo "$battery_info" | grep "Cycle Count:" | awk '{print $3}' || echo "N/A")
    BAT_MAX_CAPACITY=$(echo "$battery_info" | grep "Maximum Capacity:" | awk '{print $3}' | tr -d '%' || echo "N/A")

    if [ "$BAT_HEALTH" = "Replace Soon" ] || [ "$BAT_HEALTH" = "Replace Now" ] || [ "$BAT_HEALTH" = "Service Battery" ]; then
        BAT_SEVERITY="red"
        update_overall_severity "red"
    fi
fi

# ============================================================================
# COLLECT SECURITY INFO
# ============================================================================

echo "  Collecting security diagnostics..."

SEC_FIREWALL=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null | grep -o "enabled\|disabled" || echo "unknown")
SEC_FILEVAULT=$(fdesetup status 2>/dev/null | grep -o "On\|Off" || echo "unknown")
SEC_SIP=$(csrutil status 2>/dev/null | grep -o "enabled\|disabled" || echo "unknown")
SEC_GATEKEEPER=$(spctl --status 2>/dev/null | grep -o "enabled\|disabled" || echo "unknown")

SEC_SEVERITY="green"
if [ "$SEC_SIP" = "disabled" ]; then
    SEC_SEVERITY="red"
    update_overall_severity "red"
elif [ "$SEC_FIREWALL" != "enabled" ] || [ "$SEC_FILEVAULT" != "On" ]; then
    SEC_SEVERITY="yellow"
    update_overall_severity "yellow"
fi

# ============================================================================
# COLLECT STORAGE CLEANUP INFO
# ============================================================================

echo "  Collecting storage cleanup info..."

# Calculate cleanable space
user_cache_kb=0
if [ -d "$HOME/Library/Caches" ]; then
    user_cache_kb=$(du -sk "$HOME/Library/Caches" 2>/dev/null | awk '{print $1}' || echo "0")
fi

trash_kb=0
if [ -d "$HOME/.Trash" ]; then
    trash_kb=$(du -sk "$HOME/.Trash" 2>/dev/null | awk '{print $1}' || echo "0")
fi

user_logs_kb=0
if [ -d "$HOME/Library/Logs" ]; then
    user_logs_kb=$(du -sk "$HOME/Library/Logs" 2>/dev/null | awk '{print $1}' || echo "0")
fi

total_cleanable_kb=$((user_cache_kb + trash_kb + user_logs_kb))
STORAGE_TOTAL_MB=$((total_cleanable_kb / 1024))
STORAGE_TOTAL_GB=$(echo "scale=2; $STORAGE_TOTAL_MB / 1024" | bc 2>/dev/null || echo "0")
STORAGE_TRASH_MB=$((trash_kb / 1024))

STORAGE_SEVERITY="green"
storage_gb_int=$(echo "$STORAGE_TOTAL_GB" | cut -d. -f1)
storage_gb_int=${storage_gb_int:-0}

if [ "$storage_gb_int" -ge 5 ] 2>/dev/null; then
    STORAGE_SEVERITY="red"
    update_overall_severity "red"
elif [ "$storage_gb_int" -ge 2 ] 2>/dev/null; then
    STORAGE_SEVERITY="yellow"
    update_overall_severity "yellow"
fi

# ============================================================================
# COLLECT SOFTWARE UPDATE INFO
# ============================================================================

echo "  Checking for software updates..."

# This can be slow, so we'll just check if updates are available
UPD_UPDATE_COUNT=0
update_check=$(softwareupdate -l 2>&1 || echo "")
if echo "$update_check" | grep -q "Label:"; then
    UPD_UPDATE_COUNT=$(echo "$update_check" | grep -c "Label:" || echo "0")
fi

UPD_SEVERITY="green"
if [ "$UPD_UPDATE_COUNT" -gt 0 ] 2>/dev/null; then
    UPD_SEVERITY="yellow"
    update_overall_severity "yellow"
fi

# ============================================================================
# GET OVERALL SEVERITY
# ============================================================================

OVERALL_SEVERITY=$(cat "$DIAG_TEMP_DIR/overall_severity.txt")

case "$OVERALL_SEVERITY" in
    green) OVERALL_LABEL="Good" ;;
    yellow) OVERALL_LABEL="Warning" ;;
    red) OVERALL_LABEL="Critical" ;;
    *) OVERALL_LABEL="Unknown" ;;
esac

# ============================================================================
# GENERATE HTML REPORT
# ============================================================================

echo ""
echo "Generating HTML report..."

TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
SCRIPT_END=$(date +%s)
DURATION=$((SCRIPT_END - SCRIPT_START))

# Helper function for progress bar
progress_bar() {
    local pct="$1"
    local pct_int=$(echo "$pct" | cut -d. -f1)
    pct_int=${pct_int:-0}

    local color="var(--green)"
    if [ "$pct_int" -ge 90 ] 2>/dev/null; then
        color="var(--red)"
    elif [ "$pct_int" -ge 70 ] 2>/dev/null; then
        color="var(--yellow)"
    fi

    echo "<div class='progress'><div class='progress-fill' style='width:${pct_int}%;background:$color'></div><span class='progress-text'>${pct}%</span></div>"
}

# Start HTML
cat > "$OUTPUT_PATH" << 'HTMLSTART'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>macOS System Diagnostic Report</title>
    <style>
        :root {
            --green: #22c55e;
            --yellow: #eab308;
            --red: #ef4444;
            --bg: #0f172a;
            --card-bg: #1e293b;
            --text: #e2e8f0;
            --text-muted: #94a3b8;
            --border: #334155;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 20px;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        header {
            text-align: center;
            padding: 30px 0;
            border-bottom: 1px solid var(--border);
            margin-bottom: 30px;
        }
        h1 { font-size: 2.5rem; margin-bottom: 10px; }
        .subtitle { color: var(--text-muted); font-size: 1.1rem; }
        .overall-status {
            display: inline-flex;
            align-items: center;
            gap: 10px;
            padding: 15px 30px;
            border-radius: 50px;
            font-size: 1.3rem;
            font-weight: 600;
            margin: 20px 0;
        }
        .status-green { background: rgba(34, 197, 94, 0.2); border: 2px solid var(--green); color: var(--green); }
        .status-yellow { background: rgba(234, 179, 8, 0.2); border: 2px solid var(--yellow); color: var(--yellow); }
        .status-red { background: rgba(239, 68, 68, 0.2); border: 2px solid var(--red); color: var(--red); }
        .section {
            background: var(--card-bg);
            border-radius: 12px;
            margin-bottom: 20px;
            border: 1px solid var(--border);
            overflow: hidden;
        }
        .section summary {
            padding: 15px 20px;
            cursor: pointer;
            font-weight: 600;
            font-size: 1.1rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: rgba(255,255,255,0.02);
        }
        .section summary:hover { background: rgba(255,255,255,0.05); }
        .section-body { padding: 20px; }
        .badge {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 500;
        }
        .badge-green { background: rgba(34, 197, 94, 0.2); color: var(--green); }
        .badge-yellow { background: rgba(234, 179, 8, 0.2); color: var(--yellow); }
        .badge-red { background: rgba(239, 68, 68, 0.2); color: var(--red); }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }
        th, td {
            padding: 10px 15px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        th { background: rgba(255,255,255,0.05); font-weight: 600; }
        tr:hover { background: rgba(255,255,255,0.02); }
        .kv-table th { width: 20%; color: var(--text-muted); font-weight: normal; }
        .kv-table td { width: 30%; }
        .progress {
            background: rgba(255,255,255,0.1);
            border-radius: 10px;
            height: 24px;
            overflow: hidden;
            position: relative;
        }
        .progress-fill {
            height: 100%;
            border-radius: 10px;
            transition: width 0.3s ease;
        }
        .progress-text {
            position: absolute;
            left: 50%;
            top: 50%;
            transform: translate(-50%, -50%);
            font-weight: 600;
            font-size: 0.85rem;
            text-shadow: 0 1px 2px rgba(0,0,0,0.5);
        }
        .metric-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin: 15px 0;
        }
        .metric-card {
            background: rgba(255,255,255,0.03);
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }
        .metric-value { font-size: 1.8rem; font-weight: 700; }
        .metric-label { color: var(--text-muted); font-size: 0.9rem; margin-top: 5px; }
        .rec {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 10px;
            border-left: 4px solid;
        }
        .rec-green { background: rgba(34, 197, 94, 0.1); border-color: var(--green); }
        .rec-yellow { background: rgba(234, 179, 8, 0.1); border-color: var(--yellow); }
        .rec-red { background: rgba(239, 68, 68, 0.1); border-color: var(--red); }
        .rec strong { display: block; margin-bottom: 5px; }
        .rec em { color: var(--text-muted); font-size: 0.9rem; }
        h4 { margin: 20px 0 10px; color: var(--text-muted); }
        .muted { color: var(--text-muted); }
        footer {
            text-align: center;
            padding: 30px 0;
            color: var(--text-muted);
            border-top: 1px solid var(--border);
            margin-top: 30px;
        }
    </style>
</head>
<body>
<div class="container">
HTMLSTART

# Add header
cat >> "$OUTPUT_PATH" << EOF
<header>
    <h1>macOS System Diagnostic Report</h1>
    <p class="subtitle">$SYS_COMPUTER_NAME - $TIMESTAMP</p>
    <div class="overall-status status-$OVERALL_SEVERITY">
        <span>Overall Health:</span>
        <strong>$OVERALL_LABEL</strong>
    </div>
</header>
EOF

# System Info Section
cat >> "$OUTPUT_PATH" << EOF
<details class="section" open>
    <summary>System Information <span class="badge badge-$SYS_SEVERITY">$SYS_UPTIME_TEXT uptime</span></summary>
    <div class="section-body">
        <table class="kv-table">
            <tr><th>Computer Name</th><td>$SYS_COMPUTER_NAME</td><th>Model</th><td>$SYS_MODEL_NAME</td></tr>
            <tr><th>Model ID</th><td>$SYS_MODEL_ID</td><th>Chip/CPU</th><td>$SYS_CHIP</td></tr>
            <tr><th>CPU Cores</th><td>$SYS_CPU_CORES</td><th>Memory</th><td>$SYS_MEMORY</td></tr>
            <tr><th>macOS Version</th><td>$SYS_OS_VERSION</td><th>Kernel</th><td>$SYS_KERNEL</td></tr>
            <tr><th>Uptime</th><td><span class="badge badge-$SYS_SEVERITY">$SYS_UPTIME_TEXT</span></td><th>Total RAM</th><td>$SYS_TOTAL_RAM_GB GB</td></tr>
        </table>
    </div>
</details>
EOF

# CPU Section
cat >> "$OUTPUT_PATH" << EOF
<details class="section">
    <summary>CPU Diagnostics <span class="badge badge-$CPU_SEVERITY">${CPU_USAGE}%</span></summary>
    <div class="section-body">
        <h4>Overall CPU Usage</h4>
        $(progress_bar "$CPU_USAGE")
        <h4>Top Processes by CPU</h4>
        <table>
            <thead><tr><th>User</th><th>PID</th><th>%CPU</th><th>%MEM</th><th>Command</th></tr></thead>
            <tbody>
EOF

# Add top CPU processes
while IFS= read -r line; do
    if [ -n "$line" ]; then
        user=$(echo "$line" | awk '{print $1}')
        pid=$(echo "$line" | awk '{print $2}')
        cpu=$(echo "$line" | awk '{print $3}')
        mem=$(echo "$line" | awk '{print $4}')
        cmd=$(echo "$line" | awk '{print $11}' | xargs basename 2>/dev/null || echo "unknown")
        echo "<tr><td>$user</td><td>$pid</td><td>${cpu}%</td><td>${mem}%</td><td>$(html_encode "$cmd")</td></tr>" >> "$OUTPUT_PATH"
    fi
done < "$DIAG_TEMP_DIR/cpu_top_procs.txt"

cat >> "$OUTPUT_PATH" << EOF
            </tbody>
        </table>
    </div>
</details>
EOF

# Memory Section
mem_used_gb=$(echo "scale=2; $MEM_USED_BYTES / 1073741824" | bc 2>/dev/null || echo "0")
mem_total_gb=$(echo "scale=2; $MEM_TOTAL_BYTES / 1073741824" | bc 2>/dev/null || echo "0")

cat >> "$OUTPUT_PATH" << EOF
<details class="section">
    <summary>Memory Diagnostics <span class="badge badge-$MEM_SEVERITY">${MEM_USED_PCT}%</span></summary>
    <div class="section-body">
        <h4>RAM Usage</h4>
        $(progress_bar "$MEM_USED_PCT")
        <p class="muted">${mem_used_gb} GB used / ${mem_total_gb} GB total</p>
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-value">${MEM_USED_PCT}%</div>
                <div class="metric-label">RAM Used</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">${MEM_SWAP_USED} MB</div>
                <div class="metric-label">Swap Used</div>
            </div>
        </div>
        <h4>Top Processes by Memory</h4>
        <table>
            <thead><tr><th>User</th><th>PID</th><th>%MEM</th><th>RSS</th><th>Command</th></tr></thead>
            <tbody>
EOF

# Add top memory processes
while IFS= read -r line; do
    if [ -n "$line" ]; then
        user=$(echo "$line" | awk '{print $1}')
        pid=$(echo "$line" | awk '{print $2}')
        mem=$(echo "$line" | awk '{print $4}')
        rss=$(echo "$line" | awk '{print $6}')
        cmd=$(echo "$line" | awk '{print $11}' | xargs basename 2>/dev/null || echo "unknown")
        echo "<tr><td>$user</td><td>$pid</td><td>${mem}%</td><td>$rss</td><td>$(html_encode "$cmd")</td></tr>" >> "$OUTPUT_PATH"
    fi
done < "$DIAG_TEMP_DIR/memory_top_procs.txt"

cat >> "$OUTPUT_PATH" << EOF
            </tbody>
        </table>
    </div>
</details>
EOF

# Disk Section
vol_count=$(wc -l < "$DIAG_TEMP_DIR/disk_volumes.txt" | xargs)

cat >> "$OUTPUT_PATH" << EOF
<details class="section">
    <summary>Disk Diagnostics <span class="badge badge-$DISK_SEVERITY">${vol_count} volumes</span></summary>
    <div class="section-body">
        <h4>Volume Usage</h4>
        <table>
            <thead><tr><th>Volume</th><th>Mount</th><th>Size</th><th>Used</th><th>Available</th><th>Usage</th></tr></thead>
            <tbody>
EOF

while IFS='|' read -r device name size used avail pct mount vol_sev; do
    if [ -n "$device" ]; then
        echo "<tr><td>$name</td><td>$mount</td><td>$size</td><td>$used</td><td>$avail</td><td>$(progress_bar "$pct")</td></tr>" >> "$OUTPUT_PATH"
    fi
done < "$DIAG_TEMP_DIR/disk_volumes.txt"

cat >> "$OUTPUT_PATH" << EOF
            </tbody>
        </table>
        <h4>Disk Health</h4>
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-value"><span class="badge badge-$DISKH_SEVERITY">$SMART_STATUS</span></div>
                <div class="metric-label">SMART Status</div>
            </div>
        </div>
    </div>
</details>
EOF

# Network Section
cat >> "$OUTPUT_PATH" << EOF
<details class="section">
    <summary>Network Diagnostics <span class="badge badge-$NET_SEVERITY">${NET_ESTABLISHED} connections</span></summary>
    <div class="section-body">
        <h4>Active Network Interfaces</h4>
        <table>
            <thead><tr><th>Interface</th><th>Type</th><th>Status</th><th>IP Address</th></tr></thead>
            <tbody>
EOF

while IFS='|' read -r device port status ip; do
    if [ -n "$device" ]; then
        echo "<tr><td>$device</td><td>$port</td><td>$status</td><td>${ip:-N/A}</td></tr>" >> "$OUTPUT_PATH"
    fi
done < "$DIAG_TEMP_DIR/network_adapters.txt"

cat >> "$OUTPUT_PATH" << EOF
            </tbody>
        </table>
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-value">$NET_ESTABLISHED</div>
                <div class="metric-label">Established</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">$NET_LISTENING</div>
                <div class="metric-label">Listening</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">$NET_TOTAL</div>
                <div class="metric-label">Total</div>
            </div>
        </div>
    </div>
</details>
EOF

# Process Section
cat >> "$OUTPUT_PATH" << EOF
<details class="section">
    <summary>Process Diagnostics <span class="badge badge-$PROC_SEVERITY">${PROC_TOTAL_COUNT} processes</span></summary>
    <div class="section-body">
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-value">$PROC_TOTAL_COUNT</div>
                <div class="metric-label">Total Processes</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">$PROC_ZOMBIE_COUNT</div>
                <div class="metric-label">Zombie Processes</div>
            </div>
        </div>
    </div>
</details>
EOF

# Startup Section
cat >> "$OUTPUT_PATH" << EOF
<details class="section">
    <summary>Startup Items <span class="badge badge-$STARTUP_SEVERITY">${STARTUP_COUNT} items</span></summary>
    <div class="section-body">
        <table>
            <thead><tr><th>Type</th><th>Name</th><th>Location</th></tr></thead>
            <tbody>
EOF

head -20 "$DIAG_TEMP_DIR/startup_items.txt" | while IFS='|' read -r type name location; do
    if [ -n "$type" ]; then
        echo "<tr><td>$type</td><td>$(html_encode "$name")</td><td class='muted'>$(html_encode "$location")</td></tr>" >> "$OUTPUT_PATH"
    fi
done

cat >> "$OUTPUT_PATH" << EOF
            </tbody>
        </table>
    </div>
</details>
EOF

# Battery Section (if laptop)
if [ "$BAT_IS_LAPTOP" = "true" ]; then
cat >> "$OUTPUT_PATH" << EOF
<details class="section">
    <summary>Battery Diagnostics <span class="badge badge-$BAT_SEVERITY">${BAT_HEALTH}</span></summary>
    <div class="section-body">
        <h4>Battery Status</h4>
        $(progress_bar "${BAT_CHARGE_PCT:-0}")
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-value">${BAT_CHARGE_PCT:-N/A}%</div>
                <div class="metric-label">Current Charge</div>
            </div>
            <div class="metric-card">
                <div class="metric-value"><span class="badge badge-$BAT_SEVERITY">${BAT_HEALTH:-N/A}</span></div>
                <div class="metric-label">Condition</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">${BAT_CYCLE_COUNT:-N/A}</div>
                <div class="metric-label">Cycle Count</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">${BAT_MAX_CAPACITY:-N/A}%</div>
                <div class="metric-label">Max Capacity</div>
            </div>
        </div>
    </div>
</details>
EOF
fi

# Security Section
fw_badge="green"
[ "$SEC_FIREWALL" != "enabled" ] && fw_badge="yellow"
fv_badge="green"
[ "$SEC_FILEVAULT" != "On" ] && fv_badge="yellow"
sip_badge="green"
[ "$SEC_SIP" != "enabled" ] && sip_badge="red"
gk_badge="green"
[ "$SEC_GATEKEEPER" != "enabled" ] && gk_badge="yellow"

cat >> "$OUTPUT_PATH" << EOF
<details class="section">
    <summary>Security Status <span class="badge badge-$SEC_SEVERITY">Security</span></summary>
    <div class="section-body">
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-value"><span class="badge badge-$fw_badge">$SEC_FIREWALL</span></div>
                <div class="metric-label">Firewall</div>
            </div>
            <div class="metric-card">
                <div class="metric-value"><span class="badge badge-$fv_badge">$SEC_FILEVAULT</span></div>
                <div class="metric-label">FileVault</div>
            </div>
            <div class="metric-card">
                <div class="metric-value"><span class="badge badge-$sip_badge">$SEC_SIP</span></div>
                <div class="metric-label">SIP</div>
            </div>
            <div class="metric-card">
                <div class="metric-value"><span class="badge badge-$gk_badge">$SEC_GATEKEEPER</span></div>
                <div class="metric-label">Gatekeeper</div>
            </div>
        </div>
    </div>
</details>
EOF

# Storage Cleanup Section
cat >> "$OUTPUT_PATH" << EOF
<details class="section">
    <summary>Storage Cleanup <span class="badge badge-$STORAGE_SEVERITY">${STORAGE_TOTAL_GB} GB cleanable</span></summary>
    <div class="section-body">
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-value">${STORAGE_TOTAL_GB} GB</div>
                <div class="metric-label">Total Cleanable</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">${STORAGE_TRASH_MB} MB</div>
                <div class="metric-label">Trash</div>
            </div>
        </div>
    </div>
</details>
EOF

# Updates Section
cat >> "$OUTPUT_PATH" << EOF
<details class="section">
    <summary>Software Updates <span class="badge badge-$UPD_SEVERITY">${UPD_UPDATE_COUNT} available</span></summary>
    <div class="section-body">
        <div class="metric-grid">
            <div class="metric-card">
                <div class="metric-value">$UPD_UPDATE_COUNT</div>
                <div class="metric-label">Updates Available</div>
            </div>
        </div>
    </div>
</details>
EOF

# Recommendations Section
cat >> "$OUTPUT_PATH" << EOF
<details class="section" open>
    <summary>Recommendations & Actions</summary>
    <div class="section-body">
EOF

# Generate recommendations based on collected data
if [ "$CPU_USAGE" -ge 85 ] 2>/dev/null; then
    echo "<div class='rec rec-red'><strong>High CPU Usage</strong><br>CPU usage at ${CPU_USAGE}%.<br><em>Action: Open Activity Monitor > CPU tab, sort by %CPU to identify resource-heavy processes.</em></div>" >> "$OUTPUT_PATH"
elif [ "$CPU_USAGE" -ge 60 ] 2>/dev/null; then
    echo "<div class='rec rec-yellow'><strong>Elevated CPU Usage</strong><br>CPU usage at ${CPU_USAGE}%.<br><em>Action: Monitor for sustained high usage in Activity Monitor.</em></div>" >> "$OUTPUT_PATH"
fi

if [ "$mem_pct_int" -ge 90 ] 2>/dev/null; then
    echo "<div class='rec rec-red'><strong>Critical Memory Usage</strong><br>RAM at ${MEM_USED_PCT}%.<br><em>Action: Close unused apps, especially browsers with many tabs.</em></div>" >> "$OUTPUT_PATH"
elif [ "$mem_pct_int" -ge 70 ] 2>/dev/null; then
    echo "<div class='rec rec-yellow'><strong>Elevated Memory Usage</strong><br>RAM at ${MEM_USED_PCT}%.<br><em>Action: Close unnecessary applications and browser tabs.</em></div>" >> "$OUTPUT_PATH"
fi

if [ "$SYS_UPTIME_DAYS" -ge 30 ] 2>/dev/null; then
    echo "<div class='rec rec-red'><strong>Very Long Uptime</strong><br>System running for ${SYS_UPTIME_DAYS} days.<br><em>Action: Restart to apply updates and clear accumulated state.</em></div>" >> "$OUTPUT_PATH"
elif [ "$SYS_UPTIME_DAYS" -ge 7 ] 2>/dev/null; then
    echo "<div class='rec rec-yellow'><strong>Extended Uptime</strong><br>System running for ${SYS_UPTIME_DAYS} days.<br><em>Action: Consider restarting to apply pending updates.</em></div>" >> "$OUTPUT_PATH"
fi

if [ "$STARTUP_COUNT" -ge 15 ] 2>/dev/null; then
    echo "<div class='rec rec-yellow'><strong>Many Startup Items</strong><br>${STARTUP_COUNT} items run at startup.<br><em>Action: System Settings > General > Login Items. Remove unnecessary items.</em></div>" >> "$OUTPUT_PATH"
fi

if [ "$SEC_FIREWALL" != "enabled" ]; then
    echo "<div class='rec rec-yellow'><strong>Firewall Disabled</strong><br>macOS Firewall is not enabled.<br><em>Action: System Settings > Network > Firewall > Turn On.</em></div>" >> "$OUTPUT_PATH"
fi

if [ "$SEC_FILEVAULT" != "On" ]; then
    echo "<div class='rec rec-yellow'><strong>FileVault Disabled</strong><br>Disk encryption is not enabled.<br><em>Action: System Settings > Privacy & Security > FileVault > Turn On.</em></div>" >> "$OUTPUT_PATH"
fi

if [ "$SEC_SIP" = "disabled" ]; then
    echo "<div class='rec rec-red'><strong>SIP Disabled</strong><br>System Integrity Protection is disabled.<br><em>Action: Boot to Recovery > Terminal > csrutil enable</em></div>" >> "$OUTPUT_PATH"
fi

if [ "$UPD_UPDATE_COUNT" -gt 0 ] 2>/dev/null; then
    echo "<div class='rec rec-yellow'><strong>Updates Available</strong><br>${UPD_UPDATE_COUNT} software update(s) pending.<br><em>Action: System Settings > General > Software Update.</em></div>" >> "$OUTPUT_PATH"
fi

if [ "$storage_gb_int" -ge 2 ] 2>/dev/null; then
    echo "<div class='rec rec-yellow'><strong>Storage Cleanup</strong><br>${STORAGE_TOTAL_GB} GB of cleanable files.<br><em>Action: Apple Menu > About This Mac > Storage > Manage.</em></div>" >> "$OUTPUT_PATH"
fi

# Always add tips
cat >> "$OUTPUT_PATH" << 'TIPS'
<div class='rec rec-green'><strong>Tip: Regular Maintenance</strong><br>Keep your Mac healthy.<br><em>Action: Restart weekly, keep software updated, monitor storage space.</em></div>
<div class='rec rec-green'><strong>Tip: Activity Monitor</strong><br>Use Activity Monitor to investigate issues.<br><em>Action: Applications > Utilities > Activity Monitor.</em></div>
<div class='rec rec-green'><strong>Tip: Storage Management</strong><br>Use built-in storage optimization.<br><em>Action: Apple Menu > About This Mac > Storage > Manage.</em></div>
TIPS

cat >> "$OUTPUT_PATH" << EOF
    </div>
</details>
EOF

# Footer
cat >> "$OUTPUT_PATH" << EOF
<footer>
    <p>Generated on $TIMESTAMP | Collection time: ${DURATION}s</p>
    <p>macOS System Diagnostic Tool</p>
</footer>
</div>
</body>
</html>
EOF

echo ""
echo "Report generated: $OUTPUT_PATH"
echo "Collection time: ${DURATION}s"

# Open in browser
if [ "$SKIP_BROWSER_OPEN" != "true" ]; then
    echo "Opening report in browser..."
    open "$OUTPUT_PATH"
fi

echo ""
echo "Done!"
