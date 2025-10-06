#!/usr/bin/env bash
# smiles.sh
# Pentest quick-check script (English)
# Checks for unusual top-level directories, executable files the current user can run,
# and SUID/SGID files that may lead to privilege escalation.

# Ensure script is executed with bash (not sh/dash)
if [ -z "${BASH_VERSION:-}" ]; then
  cat <<EOF
ERROR: This script requires bash. Please run it with:
  bash "$0"

If you used 'sh smiles.sh' or ran it in a shell that links /bin/sh to dash, you'll see syntax errors.
EOF
  exit 1
fi

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
Make sure to run with bash: 'bash $0' or make it executable and run './$0' (which uses the shebang).
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
# find world-writable directories but exclude those with the sticky bit (e.g. /tmp and its normal subdirs)
find / -xdev -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | while read -r dir; do
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
# directories to exclude from the "executable outside standard paths" scan
# add config/cache/package-info locations that commonly contain many packaged scripts
EXCLUDE=("/bin" "/sbin" "/usr" "/lib" "/lib64" "/proc" "/sys" "/dev" "/run" "/etc" "/usr/share" "/var/lib" "/var/lib/dpkg" "/var/cache")
find / -type f -executable -xdev 2>/dev/null | while read -r f; do
  skip=0
  for e in "${EXCLUDE[@]}"; do
    if [[ "$f" == "$e"* ]]; then skip=1; break; fi
  done
  if [[ $skip -eq 0 ]]; then
    # avoid noise: skip files owned by root:root (most packaged root-owned executables)
    owner=$(stat -c "%U" "$f" 2>/dev/null || echo "")
    group=$(stat -c "%G" "$f" 2>/dev/null || echo "")
    if [[ "$owner" == "root" && "$group" == "root" ]]; then
      continue
    fi

    # only flag items that are likely to be unusual: files not under the excludes
    # and that are executable by the current user
    if [[ -x "$f" ]]; then
      info=$(ls -l "$f" 2>/dev/null)
      out "${RED}POTENTIAL: $info${NC}"
    fi
  fi
done

# 3) SUID / SGID files (can grant elevated privileges)
out "\n${YEL}3) SUID (setuid) files (may run with elevated privileges)${NC}"

# Whitelist of common SUID binaries (adjust as needed)
SUID_WHITELIST=(
  "/bin/mount" "/bin/ping" "/bin/su" "/bin/ping6" "/bin/umount"
  "/usr/bin/at" "/usr/bin/chsh" "/usr/bin/passwd" "/usr/bin/newgrp" "/usr/bin/chfn"
  "/usr/bin/gpasswd" "/usr/bin/procmail" "/usr/bin/find" "/usr/sbin/exim4"
  "/usr/lib/pt_chown" "/usr/lib/openssh/ssh-keysign" "/usr/lib/eject/dmcrypt-get-device"
  "/usr/lib/dbus-1.0/dbus-daemon-launch-helper" "/sbin/mount.nfs" "/usr/bin/sudo" "/usr/bin/sudoedit"
)

# Use the exact find you requested
while IFS= read -r f; do
  # skip if empty
  [[ -z "$f" ]] && continue
  ok=0
  for w in "${SUID_WHITELIST[@]}"; do
    if [[ "$f" == "$w" ]]; then ok=1; break; fi
  done
  line=$(ls -l "$f" 2>/dev/null)
  if [[ $ok -eq 1 ]]; then
    out "    ok: $line"
  else
    out "${RED}POTENTIAL: $line${NC}"
  fi
done < <(find / -perm -u=s -type f 2>/dev/null)

out "\n${YEL}4) SGID files (may grant group privileges)${NC}"
# Whitelist of common SGID binaries (adjust as needed)
SGID_WHITELIST=(
  "/usr/bin/newgrp" "/usr/bin/at" "/usr/lib/openssh/ssh-keysign" "/usr/bin/locate"
)
while IFS= read -r f; do
  [[ -z "$f" ]] && continue
  ok=0
  for w in "${SGID_WHITELIST[@]}"; do
    if [[ "$f" == "$w" ]]; then ok=1; break; fi
  done
  line=$(ls -l "$f" 2>/dev/null)
  if [[ $ok -eq 1 ]]; then
    out "    ok: $line"
  else
    out "${RED}POTENTIAL: $line${NC}"
  fi
done < <(find / -perm -g=s -type f 2>/dev/null)

# 3b) Check sudo privileges for current user
out "\n${YEL}6) sudo -l (list allowed commands)${NC}"
SUDO_OUT=$(sudo -l 2>&1)
SUDO_RC=$?
if [[ $SUDO_RC -ne 0 && -z "$SUDO_OUT" ]]; then
  out "    sudo -l could not run (may require password or sudo not installed). Run 'sudo -l' interactively to check."
else
  echo "$SUDO_OUT" | while IFS= read -r line; do
    # highlight risky entries
    if echo "$line" | grep -qi "NOPASSWD" || echo "$line" | grep -qi "ALL"; then
      out "${RED}$line${NC}"
    else
      out "    $line"
    fi
  done
fi

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
