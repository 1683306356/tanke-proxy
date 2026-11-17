#!/system/bin/sh
# Manual installer / repair tool for the tanke per-app MITM module.
#
#   su -c 'sh deploy.sh'          # from inside the extracted package folder
#   su -c 'sh /data/adb/modules/tanke_proxy/deploy.sh'   # or from the installed module
#
# What it does, in order, and why:
#   1. copies the package files into /data/adb/modules/tanke_proxy
#   2. fixes execute bits (a zip extracted by hand or by an app loses them)
#   3. makes the certificates exist: keeps an existing CA byte-for-byte, only
#      creates one when it is missing, and signs one leaf per intercept host
#   4. publishes the CA into the user store (only if it is not there yet)
#   5. checks every dependency and prints exactly what is missing, if anything
#   6. (re)starts the redirect and runs selftest
#
# It never overwrites an existing ca.key.pem / ca.crt.pem: the CA is already
# trusted by the phone, and replacing it would break every certificate that was
# already accepted.
#
# Exit codes: 0 installed and healthy, 1 installed but not healthy, 2 cannot install.

SRC=$(cd "$(dirname "$0")" && pwd)
MD=/data/adb/modules/tanke_proxy

say() { echo "$*"; }
die() { echo ""; echo "FAILED: $*"; echo ""; exit 2; }

[ -f "$SRC/module.prop" ] || die "module.prop not found in $SRC - run this from the folder the package was extracted to"

# ---------------------------------------------------------------- 1) files
mkdir -p "$MD"
for f in module.prop service.sh uninstall.sh common.sh resolve4.mjs proxy.mjs proxy.version \
         gencert.mjs targets.env adapt-probe.mjs adapt-probe.sh deploy.sh tanke-proxy.sh; do
  [ -f "$SRC/$f" ] && cp -f "$SRC/$f" "$MD/$f"
done

# bundled node runtime (present in the "full" package only)
if [ -d "$SRC/bin" ]; then
  mkdir -p "$MD/bin"
  cp -f "$SRC/bin/"* "$MD/bin/" 2>/dev/null
fi
if [ -d "$SRC/lib" ]; then
  mkdir -p "$MD/lib"
  cp -f "$SRC/lib/"* "$MD/lib/" 2>/dev/null
fi

# ---------------------------------------------------------------- 2) modes
chmod 755 "$MD/service.sh" "$MD/uninstall.sh" "$MD/common.sh" "$MD/adapt-probe.sh" \
          "$MD/deploy.sh" "$MD/tanke-proxy.sh" 2>/dev/null
chmod 644 "$MD/module.prop" "$MD/resolve4.mjs" "$MD/proxy.mjs" "$MD/proxy.version" \
          "$MD/gencert.mjs" "$MD/targets.env" "$MD/adapt-probe.mjs" 2>/dev/null
if [ -d "$MD/bin" ]; then
  chmod 755 "$MD/bin/node" 2>/dev/null
fi
if [ -d "$MD/lib" ]; then
  chmod 755 "$MD/lib/"*.so* 2>/dev/null
  chmod 644 "$MD/lib/"*.so* 2>/dev/null
  chmod 755 "$MD/lib/"*.so "$MD/lib/"*.so.* 2>/dev/null
fi
rm -f "$MD/disable" "$MD/remove" 2>/dev/null

# ---------------------------------------------------------------- 3) runtime
MODDIR=$MD
. "$MD/common.sh"

say "=== deploy $(date '+%F %T') ==="
say "package: $SRC"
say "node   : $(node_source)"
if [ -z "$(node_bin)" ]; then
  die "no node runtime. Expected $MD/bin/node (full package) or $TERMUX_PREFIX/bin/node (Termux).
       Install tanke-proxy-full.zip, or install Termux + 'pkg install nodejs' and use the lite package."
fi
if ! node_ok; then
  die "node exists at $(node_bin) but cannot execute.
       Check that $MD/lib holds its shared libraries (full package), then retry."
fi
say "node ver: $("$(node_bin)" -v 2>/dev/null)"

# ---------------------------------------------------------------- 4) state migration
# v2 kept its mutable state in Termux' home. Carry it over once so the request
# history and the pinned API IPs survive the upgrade.
mkdir -p "$PROXY_DIR"
if [ -d "$LEGACY_PROXY_DIR" ]; then
  for f in targets.env capture.jsonl capture.jsonl.1; do
    if [ -f "$LEGACY_PROXY_DIR/$f" ] && [ ! -f "$PROXY_DIR/$f" ]; then
      cp -f "$LEGACY_PROXY_DIR/$f" "$PROXY_DIR/$f" 2>/dev/null \
        && say "migrated $f from $LEGACY_PROXY_DIR"
    fi
  done
  # v2 kept the CA in Termux' home as well. Adopt it here so the certificate that
  # the phone already trusts survives an upgrade of the module dir.
  for f in ca.crt.pem ca.key.pem; do
    if [ -f "$LEGACY_PROXY_DIR/$f" ] && [ ! -f "$PROXY_DIR/$f" ]; then
      cp -f "$LEGACY_PROXY_DIR/$f" "$PROXY_DIR/$f" 2>/dev/null \
        && say "migrated $f from $LEGACY_PROXY_DIR (keeping the trusted CA)"
    fi
  done
fi
[ -f "$PROXY_DIR/targets.env" ] || cp -f "$MD/targets.env" "$PROXY_DIR/targets.env" 2>/dev/null
chmod 644 "$PROXY_DIR/targets.env" 2>/dev/null
# the control script is documented as living at $PROXY_DIR/tanke-proxy.sh
cp -f "$MD/tanke-proxy.sh" "$PROXY_DIR/tanke-proxy.sh" 2>/dev/null
chmod 755 "$PROXY_DIR/tanke-proxy.sh" 2>/dev/null

# ---------------------------------------------------------------- 5) certificates
say ""
# sync_assets copies proxy.mjs / gencert.mjs / adapt-probe into $PROXY_DIR; doing it
# before the checks below means the dependency report reflects the real runtime dir
# instead of "MISSING" for files that are about to be installed.
sync_assets
if ! ensure_certs; then
  die "certificate setup failed - see the messages above.
       Missing files would be $PROXY_DIR/ca.crt.pem / ca.key.pem and $LEAF_DIR/<host>.crt.pem"
fi
say ""
say "--- certificate chain ---"
cert_report || say "(chain check failed - run: sh $MD/tanke-proxy.sh verify-certs)"

# ---------------------------------------------------------------- 6) dependencies
say ""
if ! print_deps; then
  die "dependencies still incomplete (see MISSING lines above)"
fi

# ---------------------------------------------------------------- 7) start
say ""
say "--- starting ---"
sh "$PROXY_DIR/tanke-proxy.sh" start
say ""
sh "$PROXY_DIR/tanke-proxy.sh" selftest
rc=$?
say ""
if [ "$rc" = "0" ]; then
  say "OK: installed and healthy. Log: $LOG"
else
  say "INSTALLED but selftest reported failures. Log: $LOG"
fi
exit $rc
