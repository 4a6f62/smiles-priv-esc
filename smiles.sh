#!/usr/bin/env bash
# smiles.sh
# Pentest quick-check script (English)
# Checks for unusual top-level directories, executable files the current user can run,
# and SUID/SGID files that may lead to privilege escalation.

RED='\033[0;31m'
YEL='\033[0;33m'
GRN='\033[0;32m'
NC='\033[0m'

REPORT="/tmp/pentest_check_$(whoami)_$(date +%s).txt"
SAVE=0

usage(){
  cat <<EOF
Usage: $0 [--save]
  --save    Save the report to ${REPORT}

This script is best run as a normal user; some checks will show more info if you run it with sudo.
EOF
}

if [[ "$1" == "--help" || "$1" == "-h" ]]; then
  usage; exit 0
fi
if [[ "$1" == "--save" ]]; then
  SAVE=1
fi

echo -e "${GRN}Pentest quick-check for: $(whoami) on host: $(hostname) - $(date)${NC}\n"

# Helper to print to stdout and optionally to report file
out(){
  echo -e "$@"
  if [[ $SAVE -eq 1 ]]; then
    echo -e "$@" >> "$REPORT"
  fi
}

# 1) Unusual top-level directories in /
out "${YEL}1) Unusual top-level directories in /${NC}"
STANDARD=(bin boot dev etc home lib lib32 lib64 libx32 media mnt opt proc root run sbin srv sys tmp usr var)
mapfile -t TOP < <(ls -1 / 2>/dev/null)
for d in "${TOP[@]}"; do
  if [[ -d "/$d" ]]; then
    skip=0
    for s in "${STANDARD[@]}"; do
      if [[ "$d" == "$s" ]]; then skip=1; break; fi
    done
    if [[ $skip -eq 0 ]]; then
      info=$(ls -ld "/$d" 2>/dev/null)
      out "${RED}POTENTIAL: /$d -> $info${NC}"
    else
      info=$(ls -ld "/$d" 2>/dev/null)
      out "    /$d -> $info"
    fi
  fi
done

out "\n${YEL}World-writable directories (without sticky bit) under / (note: some are normal like /tmp):${NC}"
# world-writable dirs excluding /tmp (but list them)
find / -xdev -type d -perm -0002 -print 2>/dev/null | while read -r dir; do
  st=$(stat -c "%A %U %G %n" "$dir" 2>/dev/null)
  # mark /tmp as normal, others as potential
  if [[ "$dir" == "/tmp" || "$dir" == "/var/tmp" ]]; then
    out "    normal: $st"
  else
    out "${RED}POTENTIAL: $st${NC}"
  fi
done

# 2) Unusual executable files for the current user
USER=$(whoami)
out "\n${YEL}2) Executable files that $USER can run outside standard system paths (potentially interesting):${NC}"
# search executable files where current user has execute bit, excluding common locations
EXCLUDE=("/bin" "/sbin" "/usr" "/lib" "/lib64" "/proc" "/sys" "/dev" "/run")
find / -type f -executable -xdev 2>/dev/null | while read -r f; do
  skip=0
  for e in "${EXCLUDE[@]}"; do
    if [[ "$f" == "$e"* ]]; then skip=1; break; fi
  done
  if [[ $skip -eq 0 ]]; then
    # check if current user can execute it
    if [[ -x "$f" ]]; then
      info=$(ls -l "$f" 2>/dev/null)
      out "${RED}POTENTIAL: $info${NC}"
    fi
  fi
done

# 3) SUID / SGID files (can grant elevated privileges)
out "\n${YEL}3) SUID (setuid) files (may run with elevated privileges)${NC}"
find / -xdev -type f -perm -4000 -ls 2>/dev/null | while read -r line; do
  out "${RED}$line${NC}"
done

out "\n${YEL}4) SGID files (may grant group privileges)${NC}"
find / -xdev -type f -perm -2000 -ls 2>/dev/null | while read -r line; do
  out "${RED}$line${NC}"
done

# 4) Files owned by root but writable by current user (dangerous)
out "\n${YEL}5) Files owned by root but writable by the current user (dangerous)${NC}"
# Quick heuristic: find files owned by root that are writable
find / -xdev -type f -user root -writable -ls 2>/dev/null | while read -r line; do
  out "${RED}$line${NC}"
done

# 5) Short recommendations
out "\n${GRN}Recommendations:${NC}"
out "- Manually inspect POTENTIAL items highlighted in red first."
out "- Review SUID/SGID binaries and remove or restrict ones not required."
out "- Check unusual top-level directories for cronjobs, binaries, or config files."
out "- Running this script as root (sudo) will reveal more (e.g., /root)."

if [[ $SAVE -eq 1 ]]; then
  out "\n${GRN}Saved report: $REPORT${NC}"
else
  out "\nUse --save to write the report to $REPORT"
fi
