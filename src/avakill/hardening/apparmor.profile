# AvaKill AppArmor Profile
#
# Path-based mandatory access control profile for the AvaKill firewall.
# Denies write access to policy files and source directories.
#
# Install:
#   sudo cp avakill.profile /etc/apparmor.d/usr.bin.avakill
#   sudo apparmor_parser -r /etc/apparmor.d/usr.bin.avakill
#
# Verify:
#   sudo aa-status | grep avakill

#include <tunables/global>

profile avakill /usr/bin/avakill flags=(enforce) {
  #include <abstractions/base>
  #include <abstractions/python>
  #include <abstractions/nameservice>

  # Allow reading AvaKill policy files
  /etc/avakill/             r,
  /etc/avakill/avakill.yaml r,
  /etc/avakill/*.sig        r,

  # Deny all write/modify access to policy directory
  deny /etc/avakill/**      w,
  deny /etc/avakill/**      l,  # no hardlinks

  # Deny write access to AvaKill source/installed directories
  deny /usr/lib/python*/site-packages/avakill/** w,
  deny /usr/local/lib/python*/site-packages/avakill/** w,

  # Allow reading Python runtime
  /usr/bin/python*          rix,
  /usr/lib/python*/**       r,
  /usr/local/lib/python*/** r,

  # Allow network access (MCP proxy, API interceptors)
  network tcp,
  network udp,

  # Allow logging
  /var/log/avakill/         rw,
  /var/log/avakill/**       rw,

  # Allow reading /proc and /sys for system info
  @{PROC}/@{pid}/status    r,
  @{PROC}/@{pid}/environ   r,

  # Allow temporary files
  /tmp/avakill-*            rw,
  owner /tmp/**             rw,
}
