#!/system/bin/sh
# Magisk late_start service for the tanke per-app MITM.
#
# v2 (2026-11-17): the previous version set a SYSTEM-WIDE http_proxy, which sent
# every app on the phone through the local proxy and made the whole device lose
# internet whenever the proxy hiccupped. That is gone for good.
# Now: iptables REDIRECT of  uid(com.lptiyu.tanke) -> api2/pre-api:443  only.
#
# v2.2: boot no longer waits for DNS before installing rules (the app may be
# opened while the radio is still coming up), and the watchdog ticks every 25s
# instead of 300s - a dead proxy used to mean up to five minutes of hard failures
# on every API call.
MODDIR=${0%/*}
. "$MODDIR/common.sh"

log "service.sh start (v2.2 per-app, watchdog 25s)"

wait_boot || { log "boot_completed timeout, continuing anyway"; }
sleep 2

# Never let a stale global proxy survive - it is the v1 failure mode.
ensure_no_global_proxy

# ---- 1) usable state from CACHED targets, before touching the network --------
# If targets.env survived from the last boot this installs working rules within
# a second, so opening the app during the boot window still works.
if [ -s "$TARGETS" ]; then
  log "boot: cached targets present -> installing rules first"
  apply_iptables && log "boot: rules installed from cache ($(rule_count) rules)"
else
  log "boot: no cached targets, waiting for network"
  net_ready || log "boot: network not ready after 40s, will keep retrying"
fi

# ---- 2) full bring-up with retries -----------------------------------------
ok=0
i=0
while [ $i -lt 10 ]; do
  if refresh_targets && start_proxy && apply_iptables; then
    ok=1; health_set degraded no; mark_ok; break
  fi
  i=$((i+1))
  log "boot attempt $i failed, retry in 6s"
  sleep 6
done

if [ "$ok" = "1" ]; then
  log "service.sh READY uid=$(tanke_uid) ver=$(cat "$PROXY_DIR/.proxy.version" 2>/dev/null) targets=$(tr '\n' ' ' < "$TARGETS" 2>/dev/null)"
else
  log "service.sh FAILED to become ready"
  # Do not leave the phone pointing at a dead port: heal() will keep trying and
  # the reverse protection drops the jump if it stays broken.
fi

# ---- 3) watchdog -----------------------------------------------------------
# Same watchdog that common.sh::up() starts - defined once, in common.sh, so a
# manual `tanke-proxy.sh start` also gets one. See self_heal/watchdog_loop.
ensure_watchdog
log "service.sh: watchdog pid $(watchdog_pid)"
