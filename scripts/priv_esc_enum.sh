#!/usr/bin/env bash
# ============================================================
# Project: PrivEsc Enumerator
# Author: 0xander
# Watermark: created and maintained by 0xander
# Description: Safe Linux privilege-escalation triage for CTFs.
# Notes: Recon + vector identification + CVE triage guidance only.
# No automatic exploitation is performed.
# ============================================================
set -u

MODE="${1:-enum}"
OUTPUT_DIR="${2:-$(pwd)/reports}"
VALID_MODES=(enum suggest exploit triage cve)

usage() {
  printf 'Usage: %s [enum|suggest|exploit|triage|cve] [output_dir]\n' "$(basename "$0")" >&2
  printf 'Modes:\n' >&2
  printf '  enum    - collect reconnaissance data and create a report\n' >&2
  printf '  suggest - show likely privilege-escalation vectors from the report\n' >&2
  printf '  exploit - alias for suggest (education-only guidance)\n' >&2
  printf '  triage  - suggest likely vectors, including local CVE matching\n' >&2
  printf '  cve     - match kernel version to known CVE categories and hint at likely vectors\n' >&2
  exit 1
}

if [[ ! " ${VALID_MODES[*]} " =~ " ${MODE} " ]]; then
  usage
fi

mkdir -p "$OUTPUT_DIR"
TS=$(date +%Y%m%d_%H%M%S)
REPORT="$OUTPUT_DIR/priv_esc_report_${TS}.txt"
LOG="$OUTPUT_DIR/priv_esc_log_${TS}.log"
exec > >(tee -a "$LOG") 2>&1

ASCII_ART=' 
    ____ _ _ ____  ____      _ ___      _   _ _ _   _ ___ _   _
   |  _ \| | |  _ \/ ___| ___| | _ \ ___| |_| | | | | _ \ | | |
   | |_) | | | |_) \___ \/ _ \ |  _/ / _ \ __| | |_| |  _/ |_| |
   |  __/| |_|  __/ ___) | __/ | | | \__  | |_|_   _| | |  _  _ |
   |_|   |____|_|   |____/ \___|_|_|  \___|_\_\|_| |_|_| |_| |_|
       0xander // ctf privilege escalation triage // cyber security
 '

printf '%s\n' "$ASCII_ART"
printf '\n[%s] Starting privilege escalation triage (mode: %s)...\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$MODE"
printf '[*] Output dir: %s\n' "$OUTPUT_DIR"
printf '[*] Report: %s\n' "$REPORT"
printf '[*] Safety: no automatic exploitation. This is a CTF and educational workflow.\n'

append_section() {
  local title="$1"
  printf '\n============================================================\n' | tee -a "$REPORT"
  printf '%s\n' "$title" | tee -a "$REPORT"
  printf '============================================================\n\n' | tee -a "$REPORT"
}

run_cmd() {
  local label="$1"
  shift
  printf '\n[%s] %s\n' "$(date '+%H:%M:%S')" "$label" | tee -a "$REPORT"
  "$@" 2>&1 | tee -a "$REPORT" | head -n 80
}

append_section "IDENTITY"
run_cmd "whoami" whoami
run_cmd "id" id
run_cmd "groups" groups
run_cmd "users" getent passwd | cut -d: -f1 | sort | sed -n '1,80p'
run_cmd "env" env | sort | sed -n '1,80p'

append_section "SYSTEM / KERNEL"
run_cmd "uname -a" uname -a
run_cmd "kernel release" uname -r
run_cmd "os-release" cat /etc/os-release 2>/dev/null || echo 'No /etc/os-release'
run_cmd "/proc/version" cat /proc/version 2>/dev/null || echo 'No /proc/version'

append_section "SUDO POLICIES"
run_cmd "sudo -l" sudo -l 2>&1 || echo 'No sudo access / password required / sudo unavailable'
run_cmd "sudoers files" ls -l /etc/sudoers /etc/sudoers.d 2>/dev/null || true
run_cmd "sudoers content" grep -RIn 'NOPASSWD\|ALL\|sudo' /etc/sudoers /etc/sudoers.d 2>/dev/null || true

append_section "SUID / SGID ENUMERATION"
run_cmd "suid-sgid binaries" find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort | head -n 80
run_cmd "common exploitable suid" find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | grep -E 'python|perl|ruby|php|bash|sh|awk|vim|nano|find|ed|less|more|tar|cp|mv|nmap|ssh|scp|sudo|systemctl|docker|git' | head -n 80 || true

append_section "CAPABILITIES"
run_cmd "getcap" getcap -r / 2>/dev/null | head -n 80 || echo 'No capabilities found or getcap unavailable'
run_cmd "capsh" capsh --print 2>/dev/null || true

append_section "CRON / JOBS"
run_cmd "crontab -l" crontab -l 2>/dev/null || echo 'No user crontab'
run_cmd "cron dirs" ls -ld /etc/cron* /var/spool/cron /var/spool/cron/crontabs 2>/dev/null || true
run_cmd "cron files" grep -RInE '(^|[[:space:]])(\*|[0-9]|@)([^#]*)(\$\(|/bin/sh|python|bash|perl|php)' /etc/cron* /var/spool/cron /var/spool/cron/crontabs 2>/dev/null | head -n 80 || true

append_section "SYSTEMD SERVICES"
run_cmd "systemctl list-unit-files" systemctl list-unit-files --type=service --state=enabled 2>/dev/null | head -n 80 || echo 'systemctl unavailable'
run_cmd "systemctl list-units" systemctl list-units --type=service --state=running --all 2>/dev/null | head -n 80 || echo 'systemctl unavailable'
run_cmd "root processes" ps -eo user,uid,pid,ppid,comm --sort=user | grep -E '^root|UID' | head -n 80 || true

append_section "WRITABLE PATHS"
run_cmd "writable dirs" find /etc /opt /srv /tmp /var/tmp /home -xdev \( -type d -perm -0002 -o -type d -perm -0022 \) 2>/dev/null | sort | head -n 80
run_cmd "writable files" find /etc /opt /srv /tmp /var/tmp /home -xdev -type f -perm -0002 2>/dev/null | sort | head -n 80
run_cmd "common writable locations" find /home /tmp /var/tmp /opt /srv /etc -xdev -type f 2>/dev/null | head -n 80 || true

append_section "TRIAGE NOTES"
{
  printf '\n[!] Privilege escalation paths to prioritize:\n'
  printf '  1. sudo -l / sudoers misconfiguration\n'
  printf '  2. SUID/SGID binaries with GTFOBins or writable paths\n'
  printf '  3. cron jobs and scripts writable by low-priv users\n'
  printf '  4. systemd service / timer / .service file writable by the user\n'
  printf '  5. capabilities and permission misconfigs\n'
  printf '  6. local kernel version plus known CVE triage\n'
  printf '  7. writable config / scripts in /etc, /opt, /srv, /tmp, /var/tmp\n'
  printf '\n[!] Typical next steps:\n'
  printf '  - review GTFOBins for any SUID binary found\n'
  printf '  - inspect sudoers and sudo -l for NOPASSWD or ALL\n'
  printf '  - read scripts in cron/systemd for root execution\n'
  printf '  - confirm whether a writable file is executed as root\n'
  printf '  - cross-check the kernel version against the local CVE database\n'
  printf '\n[!] Safety notice:\n'
  printf '  - This workflow only enumerates and suggests vectors.\n'
  printf '  - It does not execute exploit code or escalate privileges automatically.\n'
  printf '  - All real exploitation must be performed manually in an isolated CTF or lab environment.\n'
} | tee -a "$REPORT"

if [[ "$MODE" == "exploit" || "$MODE" == "suggest" || "$MODE" == "triage" || "$MODE" == "cve" ]]; then
  printf '\n[%s] Running safe CTF triage engine...\n' "$(date '+%H:%M:%S')" | tee -a "$REPORT"
  python3 "$(dirname "$0")/priv_esc_exploit.py" --report "$REPORT" --log "$LOG" --mode "$MODE" --cve-db "$(dirname "$0")/cve_kernel_map.json"
fi

printf '\n[OK] Enumeration complete. Report: %s\n' "$REPORT"
printf '[OK] Log: %s\n' "$LOG"

printf '\n--- QUICK SUMMARY ---\n' | tee -a "$REPORT"
printf 'User: %s\n' "$(whoami)" | tee -a "$REPORT"
printf 'Groups: %s\n' "$(groups)" | tee -a "$REPORT"
printf 'Kernel: %s\n' "$(uname -r)" | tee -a "$REPORT"
printf 'sudo -l: %s\n' "$(sudo -l 2>/dev/null || echo 'no sudo access / not allowed')" | tee -a "$REPORT"
printf 'SUID count: %s\n' "$(find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | wc -l)" | tee -a "$REPORT"
