#!/system/bin/sh
# Runs when the module is removed in Magisk. Leaves the phone as if the module had
# never been installed: no iptables rules, no proxy process, no global proxy.
#
# Deliberately KEPT (both are needed for a later reinstall to work at all):
#   $PROXY_DIR/ca.crt.pem, ca.key.pem, leafs/   - the CA is already trusted by the
#     phone (/data/misc/user/0/cacerts-added/labca.0). Wiping it would force a new
#     CA on the next install, and every certificate the phone already accepted
#     would stop validating.
#   $CFGDIR (logs) is removed; the certificate files are copied out first.
MODDIR=${0%/*}
. "$MODDIR/common.sh"

log "uninstall.sh: tearing down"

# 1) rules + jump
flush_iptables
# 2) proxy process
stop_proxy

# 3) global proxy must end up as "null", not ":0" (the v1 leftover value)
settings delete global http_proxy >/dev/null 2>&1
settings delete global global_http_proxy_host >/dev/null 2>&1
settings delete global global_http_proxy_port >/dev/null 2>&1
settings delete global global_http_proxy_exclusion_list >/dev/null 2>&1

# 4) preserve the identity material (outside $CFGDIR - that dir is about to be
#    deleted), then wipe runtime state
KEEP=/data/adb/.tanke_certs_keep
rm -rf "$KEEP" 2>/dev/null
mkdir -p "$KEEP/leafs" 2>/dev/null
for f in ca.crt.pem ca.key.pem; do
  [ -f "$PROXY_DIR/$f" ] && cp -f "$PROXY_DIR/$f" "$KEEP/$f" 2>/dev/null
done
[ -d "$LEAF_DIR" ] && cp -f "$LEAF_DIR"/*.pem "$KEEP/leafs/" 2>/dev/null

hp=$(settings get global http_proxy)
log "uninstall.sh: teardown complete (http_proxy=$hp)"

rm -rf "$CFGDIR" 2>/dev/null
# $PROXY_DIR == $CFGDIR in v3, so restore the kept certificates afterwards.
mkdir -p "$PROXY_DIR/leafs" 2>/dev/null
cp -f "$KEEP/ca.crt.pem" "$KEEP/ca.key.pem" "$PROXY_DIR/" 2>/dev/null
cp -f "$KEEP/leafs/"*.pem "$PROXY_DIR/leafs/" 2>/dev/null
chmod 644 "$PROXY_DIR/ca.crt.pem" 2>/dev/null
chmod 600 "$PROXY_DIR/ca.key.pem" 2>/dev/null
rm -rf "$KEEP" 2>/dev/null

# v2 leftovers in Termux' home, if any survived from the old architecture
for f in proxy.mjs proxy.out.log capture.jsonl .proxy.version .heartbeat targets.env;
do
  rm -f "$LEGACY_PROXY_DIR/$f" 2>/dev/null
done
rm -f /data/adb/tanke-proxy/v1-global-proxy.flag 2>/dev/null
rm -f /sdcard/adapt-probe-report.txt 2>/dev/null

# nothing left to log into: $CFGDIR is gone on purpose
exit 0
