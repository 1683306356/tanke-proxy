#!/system/bin/sh
# Shared helpers for the tanke per-app redirect module.
# Sourced by service.sh / uninstall.sh / tanke-proxy.sh.
#
# Architecture (v2): NO system-wide http_proxy anymore.
# Only  com.lptiyu.tanke  ->  api2/pre-api.lptiyu.com IPs  ->  tcp/443
# is redirected into the local transparent MITM. Everything else on the phone
# is untouched, which is the whole point: v1's global http_proxy sent every
# app's traffic through the proxy and took the whole device offline.
#
# v2.2 hardening (2026-11-17): see PHONE_ONLY.md "稳健性设计与故障恢复".
#   * watchdog every 25s instead of 300s (a dead proxy used to mean up to 5 min
#     of hard failures for every API call)
#   * liveness = listening socket AND a moving heartbeat file (a wedged process
#     keeps the port open, so the port alone lies)
#   * reverse protection: after FAIL_LIMIT consecutive failed restarts the
#     iptables jump is REMOVED so the app falls back to a direct connection
#     (shows "version too low" but still works) instead of talking to a dead port
#   * uid self-heal (reinstall changes the uid) and IP refresh with multi-A support

MODDIR="${MODDIR:-/data/adb/modules/tanke_proxy}"
CFGDIR=/data/adb/tanke-proxy
# ---- self-containment (v3) -------------------------------------------------
# v2 ran the proxy out of Termux' home directory and required Termux' node.
# v3 keeps EVERYTHING the module needs under $CFGDIR and ships its own node, so a
# phone without Termux works. Termux is now only a fallback for the "lite" package
# (which deliberately does not carry the ~100 MB runtime).
PROXY_DIR=$CFGDIR
LOG=$CFGDIR/boot.log
STATE=$CFGDIR/state.env
HEALTH=$CFGDIR/health.env
PORT=8888
CHAIN=TANKE_PROXY
PKG=com.lptiyu.tanke
APPDATA=/data/data/$PKG
TARGETS=$PROXY_DIR/targets.env
MARK=tanke_proxy
HB=$PROXY_DIR/.heartbeat
OUTLOG=$PROXY_DIR/proxy.out.log
WDPID=$CFGDIR/watchdog.pid
CERT_DIR=$PROXY_DIR
LEAF_DIR=$PROXY_DIR/leafs
# hosts we terminate TLS for and therefore need a leaf certificate for
INTERCEPT_HOSTS="api2.lptiyu.com api.lptiyu.com pre-api.lptiyu.com"
# legacy v2 locations, only ever read once (asset/state migration)
TERMUX_HOME=/data/data/com.termux/files/home
TERMUX_PREFIX=/data/data/com.termux/files/usr
LEGACY_PROXY_DIR=$TERMUX_HOME/tanke-proxy
# health tuning (see the notes above)
HB_STALE=150          # heartbeat older than this = wedged
FAIL_LIMIT=6          # consecutive failed restarts before giving up the hijack
OUTLOG_MAX=$((4 * 1024 * 1024))
LOG_MAX_LINES=4000

mkdir -p "$CFGDIR" 2>/dev/null

log() {
  echo "[$(date '+%m-%d %H:%M:%S')] $*" >> "$LOG"
  # keep the boot log bounded.
  # The counter must stay function-local: callers legitimately use their own
  # counter and call log() from inside the loop. A global here silently clobbers
  # it - apply_iptables() writes `rules=` into state.env right after logging one
  # rule, so the field ended up recording the boot.log line count (820) instead
  # of the real rule count (2). Name it _logn as well so it cannot be confused
  # with a business variable.
  local _logn
  _logn=$(wc -l < "$LOG" 2>/dev/null || echo 0)
  if [ "$_logn" -gt "$LOG_MAX_LINES" ] 2>/dev/null; then
    tail -n $((LOG_MAX_LINES / 2)) "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
  fi
}

# ---- node runtime ----------------------------------------------------------
# Resolution order is fixed and printed by node_source() so a support question
# ("which node is it using?") has a one-command answer.
#   1. $MODDIR/bin/node      bundled runtime  -> works with no Termux at all
#   2. Termux node           fallback         -> the "lite" package
# Deliberately NOT $PATH: boot scripts inherit a minimal environment and a stray
# `node` from another app's payload would be a silent, wrong answer.
node_bin() {
  if [ -f "$MODDIR/bin/node" ]; then
    # Magisk's installer (and some file managers) drop the execute bit; a bundled
    # runtime that cannot be executed is a silent, confusing failure, so repair it
    # here. This runs only when the bit is actually missing.
    [ -x "$MODDIR/bin/node" ] || chmod 755 "$MODDIR/bin/node" 2>/dev/null
    if [ -x "$MODDIR/bin/node" ]; then echo "$MODDIR/bin/node"; return 0; fi
  fi
  if [ -x "$TERMUX_PREFIX/bin/node" ]; then echo "$TERMUX_PREFIX/bin/node"; return 0; fi
  echo ""
}

node_source() {
  if [ -x "$MODDIR/bin/node" ]; then echo "bundled($MODDIR/bin/node)"; return; fi
  if [ -x "$TERMUX_PREFIX/bin/node" ]; then echo "termux($TERMUX_PREFIX/bin/node)"; return; fi
  echo "missing"
}

node_env() {
  nb=$(node_bin)
  case "$nb" in
    "$MODDIR"/bin/node)
      # Bundled runtime: its non-bionic shared libraries live in $MODDIR/lib.
      # HOME/TMPDIR are kept inside the module so nothing depends on a user dir.
      export HOME=$CFGDIR
      export LD_LIBRARY_PATH="$MODDIR/lib"
      export TMPDIR=$CFGDIR/tmp
      export PATH="$MODDIR/bin:/system/bin:/system/xbin"
      ;;
    *)
      # Termux fallback (lite package). Its node is linked against $PREFIX/lib and
      # aborts with "CANNOT LINK EXECUTABLE" without LD_LIBRARY_PATH.
      export HOME=$TERMUX_HOME
      export PREFIX=$TERMUX_PREFIX
      export PATH=$TERMUX_PREFIX/bin:/system/bin:/system/xbin
      export LD_LIBRARY_PATH=$TERMUX_PREFIX/lib
      export TMPDIR=$TERMUX_PREFIX/tmp
      ;;
  esac
  mkdir -p "$TMPDIR" 2>/dev/null
}

# One-line probe: does the resolved runtime actually execute?
node_ok() {
  nb=$(node_bin)
  [ -n "$nb" ] || return 1
  node_env
  "$nb" -e 'process.exit(0)' >/dev/null 2>&1
}

# ---- dependency self-check -------------------------------------------------
# Prints every missing piece together with the exact path that was expected, so a
# broken deploy is diagnosable from the output alone. Returns 1 if anything is
# missing. Callers: deploy.sh (aborts), tanke-proxy.sh selftest (shows PASS/FAIL),
# start_proxy (logs it once before giving up).
deps_check() {
  _rc=0
  _miss() { echo "  MISSING  $1"; [ -n "$2" ] && echo "           expected: $2"; [ -n "$3" ] && echo "           fix: $3"; _rc=1; }

  nb=$(node_bin)
  if [ -z "$nb" ]; then
    _miss "node runtime (neither bundled nor Termux)" \
      "$MODDIR/bin/node  |  $TERMUX_PREFIX/bin/node" \
      "install tanke-proxy-full.zip (bundled node) or a Termux 'pkg install nodejs'"
  elif ! node_ok; then
    _miss "node runtime cannot execute" "$nb" \
      "check $MODDIR/lib (LD_LIBRARY_PATH) - run 'sh $MODDIR/tanke-proxy.sh deps'"
  fi

  [ -f "$PROXY_DIR/proxy.mjs" ] || [ -f "$MODDIR/proxy.mjs" ] \
    || _miss "proxy.mjs" "$PROXY_DIR/proxy.mjs" "re-run deploy.sh"

  [ -f "$PROXY_DIR/ca.crt.pem" ] || _miss "CA certificate" "$PROXY_DIR/ca.crt.pem" \
    "sh $MODDIR/deploy.sh  (regenerates it when missing)"
  [ -f "$PROXY_DIR/ca.key.pem" ] || _miss "CA private key" "$PROXY_DIR/ca.key.pem" \
    "sh $MODDIR/deploy.sh  (regenerates it when missing)"
  for h in $INTERCEPT_HOSTS; do
    [ -f "$LEAF_DIR/$h.crt.pem" ] && [ -f "$LEAF_DIR/$h.key.pem" ] \
      || _miss "leaf certificate for $h" "$LEAF_DIR/$h.crt.pem + .key.pem" \
             "sh $MODDIR/tanke-proxy.sh certs"
  done
  return $_rc
}

print_deps() {
  echo "=== dependencies ==="
  echo "  node:     $(node_source)"
  nb=$(node_bin)
  if [ -n "$nb" ] && node_ok; then
    echo "  node ver: $("$nb" -v 2>/dev/null)"
  else
    echo "  node ver: (cannot execute)"
  fi
  if [ -f "$PROXY_DIR/proxy.mjs" ]; then
    echo "  proxy:    $PROXY_DIR/proxy.mjs (present)"
  else
    echo "  proxy:    $PROXY_DIR/proxy.mjs (MISSING)"
  fi
  if [ -f "$PROXY_DIR/ca.crt.pem" ]; then
    echo "  ca:       $PROXY_DIR/ca.crt.pem (present)"
  else
    echo "  ca:       $PROXY_DIR/ca.crt.pem (MISSING)"
  fi
  local n=0
  [ -d "$LEAF_DIR" ] && n=$(ls "$LEAF_DIR"/*.crt.pem 2>/dev/null | wc -l)
  echo "  leaves:   $LEAF_DIR [$n crt]"
  echo "=== check ==="
  if deps_check; then echo "  ALL PRESENT"; return 0; fi
  return 1
}

md5_of() { md5sum "$1" 2>/dev/null | cut -c1-32; }

# ---------------------------------------------------------------- health state
health_get() { sed -n "s/^$1=//p" "$HEALTH" 2>/dev/null | head -1; }

# NOTE: the watchdog, a manual `tanke-proxy.sh heal` and service.sh can all touch
# this file at once. A shared temp name let two writers trample each other and
# produced a line with no "key=" in it. Per-process temp + atomic mv fixes that.
health_set() {
  k=$1; v=$2
  mkdir -p "$CFGDIR" 2>/dev/null
  tmp="$HEALTH.tmp.$$"
  if [ -f "$HEALTH" ]; then
    grep -v "^$k=" "$HEALTH" > "$tmp" 2>/dev/null
  else
    : > "$tmp"
  fi
  echo "$k=$v" >> "$tmp"
  mv "$tmp" "$HEALTH" 2>/dev/null || rm -f "$tmp"
}

fails_now() { f=$(health_get fails); [ -z "$f" ] && f=0; echo "$f"; }

mark_fail() {
  f=$(fails_now); f=$((f+1)); health_set fails "$f"
  health_set last_fail "$(date '+%F %T')"
  echo "$f"
}

mark_ok() { health_set fails 0; health_set last_ok "$(date '+%F %T')"; }

# ---------------------------------------------------------------- global proxy
# v1 wrote  settings put global http_proxy 127.0.0.1:8888  at every boot, which
# is exactly what blackholed every other app. It must never come back.
ensure_no_global_proxy() {
  cur=$(settings get global http_proxy 2>/dev/null)
  case "$cur" in
    ""|null|":0") : ;;
    *)
      settings delete global http_proxy >/dev/null 2>&1
      settings put global http_proxy :0 >/dev/null 2>&1
      log "cleared stale global http_proxy (was '$cur')"
      ;;
  esac
  settings delete global global_http_proxy_host >/dev/null 2>&1
  settings delete global global_http_proxy_port >/dev/null 2>&1
  settings delete global global_http_proxy_exclusion_list >/dev/null 2>&1
}

# ---------------------------------------------------------------- uid
# uid changes on reinstall, so it is always read fresh.
tanke_uid() {
  u=$(stat -c %u "$APPDATA" 2>/dev/null)
  [ -z "$u" ] && u=$(dumpsys package $PKG 2>/dev/null | sed -n 's/.*userId=\([0-9]*\).*/\1/p' | head -1)
  echo "$u"
}

# uid that the iptables rules were actually built with
rule_uid() { sed -n 's/^uid=//p' "$STATE" 2>/dev/null | head -1; }

# ---------------------------------------------------------------- network/DNS
dump_ns() {
  dumpsys connectivity 2>/dev/null \
    | sed -n 's/.*DnsAddresses: \[\([^]]*\)\].*/\1/p' \
    | head -1 | tr -d '/' | tr ',' ','
}

# Wait until the device can actually reach the internet. On this phone
# sys.boot_completed=1 lands well before Wi-Fi/data is usable, and resolving
# api2.lptiyu.com at that moment just fails.
net_ready() {
  i=0
  while [ $i -lt 20 ]; do
    if ping -c1 -W2 223.5.5.5 >/dev/null 2>&1 || ping -c1 -W2 114.114.114.114 >/dev/null 2>&1; then
      return 0
    fi
    i=$((i+1)); sleep 2
  done
  return 1
}

# Resolve api2.lptiyu.com (and friends) to pinned IPs, ALL A records.
# Order: direct UDP DNS (node, returns every A record) -> ping (1 record) ->
# keep the previous file. Never leaves the file empty on failure.
refresh_targets() {
  node_env
  hosts="api2.lptiyu.com pre-api.lptiyu.com"
  ns=$(dump_ns)
  tmp=$TARGETS.new

  attempt=0
  while [ $attempt -lt 3 ]; do
    attempt=$((attempt+1))
    : > "$tmp"

    if [ -n "$(node_bin)" ] && [ -f "$MODDIR/resolve4.mjs" ]; then
      out=$("$(node_bin)" "$MODDIR/resolve4.mjs" $hosts --ns "${ns:-192.168.1.1,114.114.114.114,223.5.5.5}" 2>/dev/null)
      [ -n "$out" ] && printf '%s\n' "$out" >> "$tmp"
    fi

    # ping fallback for anything still missing (single record only; the node
    # resolver above is what captures multiple A records)
    for h in $hosts; do
      grep -q "^$h=" "$tmp" 2>/dev/null && continue
      ip=""
      i=0
      while [ $i -lt 3 ]; do
        ip=$(ping -c1 -W2 "$h" 2>/dev/null | sed -n 's/^PING [^(]*(\([0-9.]*\)).*/\1/p')
        [ -n "$ip" ] && break
        i=$((i+1)); sleep 1
      done
      [ -n "$ip" ] && echo "$h=$ip" >> "$tmp"
    done

    # carry the previous value forward for any host still missing, and say so
    for h in $hosts; do
      if ! grep -q "^$h=" "$tmp" 2>/dev/null; then
        old=$(grep "^$h=" "$TARGETS" 2>/dev/null)
        if [ -n "$old" ]; then
          echo "$old" >> "$tmp"
          log "targets: $h unresolved, kept cached $old"
        else
          log "targets: WARN $h has NO ip and no cached value"
        fi
      fi
    done

    grep -q "=" "$tmp" 2>/dev/null && break
    [ $attempt -lt 3 ] && { log "targets: attempt $attempt empty, retry in 5s"; sleep 5; }
  done

  if grep -q "=" "$tmp" 2>/dev/null; then
    if cmp -s "$tmp" "$TARGETS" 2>/dev/null; then
      rm -f "$tmp"
      return 0
    fi
    mv "$tmp" "$TARGETS"
    chmod 644 "$TARGETS" 2>/dev/null
    log "targets: $(tr '\n' ' ' < "$TARGETS")"
    return 0
  fi
  rm -f "$tmp"
  log "targets: resolve FAILED, keeping $( [ -f "$TARGETS" ] && tr '\n' ' ' < "$TARGETS" || echo none )"
  return 1
}

target_ips() {
  [ -f "$TARGETS" ] || return 0
  sed -n 's/^[^=]*=//p' "$TARGETS" | tr ',' '\n' | sed '/^$/d' | sort -u
}

# ---------------------------------------------------------------- iptables
apply_iptables() {
  uid=$(tanke_uid)
  if [ -z "$uid" ]; then
    log "iptables: SKIP - $PKG not installed (no uid)"
    return 2
  fi
  ips=$(target_ips)
  if [ -z "$ips" ]; then
    log "iptables: SKIP - no target IPs"
    return 3
  fi

  iptables -t nat -N $CHAIN 2>/dev/null
  # full rebuild = idempotent: re-running never accumulates rules
  iptables -t nat -F $CHAIN 2>/dev/null

  # `local` on purpose: log() used to share the global `n` (see log()), so the
  # rule counter below was overwritten by log()'s line count and state.env got
  # `rules=<boot.log lines>`. Keep the counter private to this function.
  local n=0
  for ip in $ips; do
    iptables -t nat -A $CHAIN -p tcp -m owner --uid-owner "$uid" -d "$ip" --dport 443 \
      -m comment --comment $MARK -j REDIRECT --to-ports $PORT 2>/dev/null \
      && { n=$((n+1)); log "iptables: + uid $uid -> $ip:443 => 127.0.0.1:$PORT"; } \
      || log "iptables: FAILED to add rule for $ip"
  done

  # exactly one jump into the chain
  iptables -t nat -C OUTPUT -p tcp --dport 443 -m comment --comment $MARK -j $CHAIN 2>/dev/null || {
    # drop any duplicates first, then add one
    local k=0
    while [ $k -lt 8 ]; do
      iptables -t nat -D OUTPUT -p tcp --dport 443 -m comment --comment $MARK -j $CHAIN 2>/dev/null || break
      k=$((k+1))
    done
    iptables -t nat -A OUTPUT -p tcp --dport 443 -m comment --comment $MARK -j $CHAIN 2>/dev/null \
      && log "iptables: jump OUTPUT -> $CHAIN installed"
  }

  echo "uid=$uid" > "$STATE"
  echo "ips=$(echo $ips | tr ' ' ',')" >> "$STATE"
  echo "rules=$n" >> "$STATE"
  health_set hijack on
  return 0
}

# Remove ONLY the jump, keeping the chain contents. Used by the reverse
# protection path: the app goes back to a direct connection (works, but the
# version gate comes back) instead of being pointed at a dead port.
drop_jump() {
  local k=0
  while [ $k -lt 8 ]; do
    iptables -t nat -D OUTPUT -p tcp --dport 443 -m comment --comment $MARK -j $CHAIN 2>/dev/null || break
    k=$((k+1))
  done
  health_set hijack off
  log "iptables: jump REMOVED (fallback to direct connection)"
}

flush_iptables() {
  local k=0
  while [ $k -lt 8 ]; do
    iptables -t nat -D OUTPUT -p tcp --dport 443 -m comment --comment $MARK -j $CHAIN 2>/dev/null || break
    k=$((k+1))
  done
  iptables -t nat -F $CHAIN 2>/dev/null
  iptables -t nat -X $CHAIN 2>/dev/null
  # also sweep anything else tagged by this module
  for c in OUTPUT PREROUTING POSTROUTING; do
    local i=0
    while [ $i -lt 16 ]; do
      iptables -t nat -D $c -m comment --comment $MARK -j REDIRECT --to-ports $PORT 2>/dev/null || break
      i=$((i+1))
    done
  done
  health_set hijack off
  log "iptables: flushed"
}

show_iptables() {
  echo "--- nat $CHAIN ---"
  iptables -t nat -L $CHAIN -n -v --line-numbers 2>&1
  echo "--- nat OUTPUT (jump) ---"
  iptables -t nat -L OUTPUT -n -v 2>&1 | grep -F "$MARK" || echo "(no jump rule)"
}

rule_count() {
  iptables -t nat -S $CHAIN 2>/dev/null | grep -c -- "-A $CHAIN"
}

# ---------------------------------------------------------------- proxy
# Keep the running script and the CA in sync with what ships in the module, so
# updating the zip is enough - no manual copies onto the phone.
#
# Two copies of proxy.mjs exist (MODDIR = what the zip installed, PROXY_DIR =
# what actually runs). Only comparing proxy.version let a stale or hand-edited
# copy win silently once already; the md5 is compared too and a mismatch is
# forced back to the module copy AND reported in the log.
sync_assets() {
  if [ -f "$MODDIR/proxy.mjs" ]; then
    ver=$(cat "$MODDIR/proxy.version" 2>/dev/null || echo unknown)
    cur=$(cat "$PROXY_DIR/.proxy.version" 2>/dev/null || echo none)
    m_src=$(md5_of "$MODDIR/proxy.mjs")
    m_dst=$(md5_of "$PROXY_DIR/proxy.mjs")
    if [ "$ver" != "$cur" ] || [ ! -f "$PROXY_DIR/proxy.mjs" ] || [ "$m_src" != "$m_dst" ]; then
      mkdir -p "$PROXY_DIR" 2>/dev/null
      cp "$MODDIR/proxy.mjs" "$PROXY_DIR/proxy.mjs" 2>/dev/null \
        && chmod 644 "$PROXY_DIR/proxy.mjs" \
        && echo "$ver" > "$PROXY_DIR/.proxy.version" \
        && log "assets: proxy.mjs forced in sync (ver $cur->$ver md5 $m_dst->$m_src)"
    fi
  fi
  # The CA must stay identical to the one already trusted on the device,
  # otherwise the app rejects our leaf certs. Only fill it in when missing.
  for f in ca.crt.pem ca.key.pem; do
    if [ -f "$MODDIR/$f" ] && [ ! -f "$PROXY_DIR/$f" ]; then
      cp "$MODDIR/$f" "$PROXY_DIR/$f" 2>/dev/null && log "assets: installed $f"
    fi
  done
  # adapt-probe（版本适配探测器）。装两份：
  #   PROXY_DIR —— 挨着 capture.jsonl，探测器默认在日志同目录找日志/写报告
  #   CFGDIR    —— /data/adb/tanke-proxy，文档里引用的固定路径，root 直接可读
  # gencert.mjs 同样同步：证书要在设备上生成/复验，工具必须和脚本一起到位。
  # md5 相同就跳过，避免 watchdog 每次 tick 都往闪存写。
  #
  # ORDER MATTERS: this runs BEFORE install_ca_to_user_store below, because that
  # compares certificates using gencert.mjs. With a stale copy without the `same`
  # subcommand, the comparison fails and the trusted CA file gets rewritten for no
  # reason (observed once during the v3 upgrade test).
  mkdir -p "$CFGDIR" 2>/dev/null
  for f in adapt-probe.mjs adapt-probe.sh gencert.mjs; do
    [ -f "$MODDIR/$f" ] || continue
    m_probe=$(md5_of "$MODDIR/$f")
    for dst in "$PROXY_DIR" "$CFGDIR"; do
      if [ "$m_probe" != "$(md5_of "$dst/$f")" ]; then
        cp "$MODDIR/$f" "$dst/$f" 2>/dev/null && log "assets: installed $f -> $dst"
      fi
    done
  done
  for dst in "$PROXY_DIR" "$CFGDIR"; do
    [ -f "$dst/adapt-probe.sh" ] && chmod 755 "$dst/adapt-probe.sh" 2>/dev/null
    [ -f "$dst/adapt-probe.mjs" ] && chmod 644 "$dst/adapt-probe.mjs" 2>/dev/null
    [ -f "$dst/gencert.mjs" ] && chmod 644 "$dst/gencert.mjs" 2>/dev/null
  done
  # user CA store: makes the leaf certs trusted by apps that accept user CAs.
  # Last, so the certificate comparison can use the freshly synced gencert.mjs.
  install_ca_to_user_store
}

# ---- certificates ----------------------------------------------------------
# The publishable zip carries NO private key at all: the CA is created on the
# device the first time the module is deployed, and every leaf is signed from it
# right there. An existing CA is always kept byte-for-byte, so re-deploying (or
# upgrading) never invalidates the certificate that is already trusted in the
# user store - rebuilding it would break every app that pinned it.
install_ca_to_user_store() {
  [ -f "$PROXY_DIR/ca.crt.pem" ] || return 0
  dst=/data/misc/user/0/cacerts-added/labca.0
  # Already published and holding the SAME certificate -> leave the file exactly
  # as it is (the normal case on a redeploy, and the reason the trusted CA survives
  # upgrades). Compare certificate identity, not bytes: the same certificate can
  # legitimately sit on disk with different PEM line wrapping.
  if [ -f "$dst" ]; then
    if ca_same_cert "$dst" "$PROXY_DIR/ca.crt.pem"; then return 0; fi
    log "cert: published CA differs from $dst -> replacing it"
  fi
  mkdir -p /data/misc/user/0/cacerts-added 2>/dev/null
  cp -f "$PROXY_DIR/ca.crt.pem" "$dst" 2>/dev/null || return 1
  chown system:system "$dst" 2>/dev/null
  chmod 644 "$dst" 2>/dev/null
  if command -v restorecon >/dev/null 2>&1; then
    restorecon "$dst" 2>/dev/null
  fi
  log "cert: CA published to user store ($dst)"
  return 0
}

# Same X.509 certificate in both files? Falls back to a byte compare only when the
# node runtime is unavailable, in which case it can report a false "different".
ca_same_cert() {
  _a=$1; _b=$2
  [ -f "$_a" ] && [ -f "$_b" ] || return 1
  _nb=$(node_bin)
  _gen=""
  for c in "$PROXY_DIR/gencert.mjs" "$MODDIR/gencert.mjs" "$CFGDIR/gencert.mjs"; do
    [ -f "$c" ] && _gen="$c" && break
  done
  if [ -n "$_nb" ] && [ -n "$_gen" ]; then
    node_env
    "$_nb" "$_gen" same --a "$_a" --b "$_b" --quiet >/dev/null 2>&1
    return $?
  fi
  cmp -s "$_a" "$_b"
}

# Generates whatever is missing. Never regenerates what already exists, unless
# FORCE_CERTS=1. Each action is logged with the reason and the resulting path.
ensure_certs() {
  _quiet=${1:-}
  say() { [ "$_quiet" = "quiet" ] || echo "$@"; log "cert: $*"; }

  mkdir -p "$PROXY_DIR" "$LEAF_DIR" 2>/dev/null

  # 1) adopt a CA that came with a previous install (module dir first)
  for f in ca.crt.pem ca.key.pem; do
    if [ ! -f "$PROXY_DIR/$f" ] && [ -f "$MODDIR/$f" ]; then
      cp -f "$MODDIR/$f" "$PROXY_DIR/$f" 2>/dev/null && say "adopted existing $f from $MODDIR"
    fi
  done

  # 2) nothing to sign with and no node -> stop with an exact reason
  nb=$(node_bin)
  if [ -z "$nb" ]; then
    echo "cert: CANNOT generate certificates - no node runtime"
    echo "      expected: $MODDIR/bin/node (full package) or $TERMUX_PREFIX/bin/node (Termux)"
    return 1
  fi
  gen=""
  for c in "$PROXY_DIR/gencert.mjs" "$MODDIR/gencert.mjs" "$CFGDIR/gencert.mjs"; do
    [ -f "$c" ] && gen="$c" && break
  done
  if [ -z "$gen" ]; then
    echo "cert: CANNOT generate certificates - gencert.mjs not found"
    echo "      expected: $PROXY_DIR/gencert.mjs or $MODDIR/gencert.mjs"
    return 1
  fi
  node_env

  # 3) CA
  if [ ! -f "$PROXY_DIR/ca.crt.pem" ] || [ ! -f "$PROXY_DIR/ca.key.pem" ]; then
    say "CA missing -> generating a new one with $nb"
    if ! "$nb" "$gen" ca -d "$PROXY_DIR" --quiet; then
      echo "cert: FAILED to generate the CA ($PROXY_DIR/ca.crt.pem)"
      return 1
    fi
    say "CA created: $PROXY_DIR/ca.crt.pem"
  else
    say "CA present, kept unchanged: $PROXY_DIR/ca.crt.pem"
  fi

  # 4) leaves, one per intercept host
  for h in $INTERCEPT_HOSTS; do
    if [ -f "$LEAF_DIR/$h.crt.pem" ] && [ -f "$LEAF_DIR/$h.key.pem" ]; then
      continue
    fi
    if "$nb" "$gen" leaf -d "$PROXY_DIR" --host "$h" --quiet; then
      say "leaf created: $LEAF_DIR/$h.crt.pem"
    else
      echo "cert: FAILED to create leaf for $h ($LEAF_DIR/$h.crt.pem)"
      return 1
    fi
  done

  # 5) publish the CA into the user store
  install_ca_to_user_store
  # 6) permissions: private keys are root-only. The CA key can arrive from a v2
  #    install where it was written 0644, so enforce it here rather than trusting
  #    whatever the old deploy left behind.
  [ -f "$PROXY_DIR/ca.key.pem" ] && chmod 600 "$PROXY_DIR/ca.key.pem" 2>/dev/null
  [ -f "$PROXY_DIR/ca.crt.pem" ] && chmod 644 "$PROXY_DIR/ca.crt.pem" 2>/dev/null
  return 0
}

# Full chain verification: parses the CA, checks every leaf is issued by it, that
# the key pair matches and that a real TLS handshake for that hostname is accepted
# with the CA as the only trust anchor. ~1-2s; used by selftest and deploy.
cert_chain_ok() {
  nb=$(node_bin)
  gen=""
  for c in "$PROXY_DIR/gencert.mjs" "$MODDIR/gencert.mjs" "$CFGDIR/gencert.mjs"; do
    [ -f "$c" ] && gen="$c" && break
  done
  [ -n "$nb" ] && [ -n "$gen" ] || return 1
  node_env
  "$nb" "$gen" verify -d "$PROXY_DIR" --hosts "$(echo $INTERCEPT_HOSTS | tr ' ' ',')" --quiet >/dev/null 2>&1
}

cert_report() {
  nb=$(node_bin)
  gen=""
  for c in "$PROXY_DIR/gencert.mjs" "$MODDIR/gencert.mjs" "$CFGDIR/gencert.mjs"; do
    [ -f "$c" ] && gen="$c" && break
  done
  if [ -z "$nb" ] || [ -z "$gen" ]; then
    echo "cert: cannot verify - node=$( [ -n "$nb" ] && echo "$nb" || echo MISSING ) gencert=$( [ -n "$gen" ] && echo "$gen" || echo MISSING )"
    return 1
  fi
  node_env
  "$nb" "$gen" verify -d "$PROXY_DIR" --hosts "$(echo $INTERCEPT_HOSTS | tr ' ' ',')"
}

# Android's ps shows only the process comm ("node"), not argv, so scan
# /proc/*/cmdline to find the proxy reliably.
#
# PERF: the naive version forked `tr` once per PID on the whole phone and cost
# 18 SECONDS per call - which made every restart look like a 60s outage and
# slowed the watchdog badly. One grep pass over the files instead, then verify
# only the (1-2) candidates. argv[0] must be node, so a shell whose -c string
# merely mentions proxy.mjs is never mistaken for the proxy.
proxy_pids() {
  for d in $(grep -l -a 'proxy\.mjs' /proc/[0-9]*/cmdline 2>/dev/null); do
    p=${d#/proc/}
    p=${p%/cmdline}
    c=$(tr '\0' ' ' < "$d" 2>/dev/null)
    case "$c" in
      node\ *|*/node\ *) echo "$p" ;;
    esac
  done 2>/dev/null
}

# LISTEN on 127.0.0.1:8888 only. Matching the bare ":22B8" also hit established
# connections whose peer port happened to be 8888.
proxy_listening() {
  grep -qiE "^( *[0-9]+: )?[0-9A-F]{8}:22B8 00000000:0000 0A" /proc/net/tcp 2>/dev/null && return 0
  # fallback for kernels that pad differently
  grep -i ":22B8 00000000:0000 0A" /proc/net/tcp 2>/dev/null >/dev/null && return 0
  return 1
}

# Port open is not enough: a wedged process keeps the socket. Require a fresh
# heartbeat as well.
proxy_healthy() {
  proxy_listening || return 1
  [ -f "$HB" ] || return 1
  now=$(date +%s)
  mt=$(stat -c %Y "$HB" 2>/dev/null || echo 0)
  [ "$mt" -gt 0 ] 2>/dev/null || return 1
  [ $((now - mt)) -le $HB_STALE ] || return 1
  return 0
}

proxy_up() { proxy_healthy; }

# copytruncate: the proxy's stdout is this shell's `>>` fd, so renaming the file
# would strand that fd in the rotated inode and the live log would stay empty.
rotate_out_log() {
  [ -f "$OUTLOG" ] || return 0
  sz=$(stat -c %s "$OUTLOG" 2>/dev/null || echo 0)
  [ "$sz" -gt "$OUTLOG_MAX" ] 2>/dev/null || return 0
  cp "$OUTLOG" "$OUTLOG.1" 2>/dev/null && : > "$OUTLOG" 2>/dev/null \
    && log "log: proxy.out.log rotated at $sz bytes (copytruncate)"
}

start_proxy() {
  node_env
  sync_assets
  # Certificates are a hard startup dependency (no leaf = nothing is rewritten),
  # so make sure they exist NOW instead of failing as mysterious TLS errors later.
  ensure_certs quiet || log "proxy: cert setup incomplete - see ensure_certs output"
  rotate_out_log
  nb=$(node_bin)
  if [ -z "$nb" ]; then
    log "proxy: FAIL node missing (looked for $MODDIR/bin/node and $TERMUX_PREFIX/bin/node)"
    return 1
  fi
  if ! node_ok; then
    log "proxy: FAIL $nb cannot execute (LD_LIBRARY_PATH=$LD_LIBRARY_PATH)"
    return 1
  fi
  if [ ! -f "$PROXY_DIR/proxy.mjs" ]; then
    log "proxy: FAIL proxy.mjs missing ($PROXY_DIR/proxy.mjs, module copy $MODDIR/proxy.mjs)"
    return 1
  fi

  ver=$(cat "$PROXY_DIR/.proxy.version" 2>/dev/null || echo unknown)
  fp=$(md5_of "$PROXY_DIR/proxy.mjs" | cut -c1-8)
  log "proxy: starting ver=$ver md5=$fp node=$nb ($(node_source))"

  stop_proxy >/dev/null 2>&1
  # The old process may take a moment to release :8888; starting the new one
  # immediately produced  listen EADDRINUSE  (caught twice during the
  # robustness tests) which then needed a whole watchdog tick to recover.
  i=0
  while [ $i -lt 8 ]; do
    proxy_listening || break
    sleep 1; i=$((i+1))
  done
  cd "$PROXY_DIR" || return 1
  PORT=$PORT BIND=127.0.0.1 HEARTBEAT="$HB" CERT_DIR="$CERT_DIR" LEAF_DIR="$LEAF_DIR" \
    setsid "$nb" proxy.mjs >> "$OUTLOG" 2>&1 < /dev/null &
  # poll instead of a fixed sleep: a cold node start (JIT + TLS init) needs ~1-4s
  # on this phone, and a fixed wait either wastes time or declares failure early.
  # START_WAIT is overridable so tests can provoke a fast failure.
  wait_s=${START_WAIT:-24}
  i=0
  while [ $i -lt "$wait_s" ]; do
    sleep 1
    if proxy_healthy; then
      log "proxy: UP on 127.0.0.1:$PORT ver=$ver (pid $(proxy_pids | tr '\n' ' ') after $((i+1))s)"
      return 0
    fi
    i=$((i+1))
  done
  if proxy_listening; then
    log "proxy: port is open but heartbeat is stale -> treating as wedged"
  else
    log "proxy: FAILED to bind $PORT"
  fi
  return 1
}

stop_proxy() {
  # Only the node process is our proxy (see proxy_pids), so a `pkill -f proxy.mjs`
  # is both slower and riskier - it also matches a shell whose command line
  # merely mentions the file name.
  for p in $(proxy_pids); do kill "$p" 2>/dev/null; done
  sleep 1
  for p in $(proxy_pids); do kill -9 "$p" 2>/dev/null; done
  # a leftover heartbeat would make a dead proxy look alive for HB_STALE seconds
  rm -f "$HB" 2>/dev/null
  log "proxy: stopped"
}

wait_boot() {
  i=0
  while [ $i -lt 120 ]; do
    [ "$(getprop sys.boot_completed)" = "1" ] && return 0
    sleep 1; i=$((i+1))
  done
  return 1
}

# ---- self heal -------------------------------------------------------------
# Everything the watchdog re-checks on every tick. Cheap on purpose: it runs
# every 25s for the life of the device.
#   * proxy process alive and heartbeat fresh      -> restart if not
#   * iptables rules match the CURRENT uid and the CURRENT ip set
#   * app reinstalled (uid changed)                -> rebuild
#   * rules vanished (another VPN/firewall app)    -> rebuild
# Returns 0 when the system is in the desired state.
heal() {
  changed=0

  # 1) proxy liveness
  if ! proxy_healthy; then
    log "heal: proxy unhealthy (listen=$(proxy_listening && echo y || echo n)) -> restart"
    if start_proxy; then
      mark_ok
      changed=1
    else
      f=$(mark_fail)
      log "heal: restart failed ($f/$FAIL_LIMIT)"
      if [ "$f" -ge "$FAIL_LIMIT" ]; then
        # reverse protection: better a direct connection (version gate returns)
        # than every request being refused by a dead local port
        drop_jump
        health_set degraded yes
        log "heal: DEGRADED - hijack dropped after $f failures; app now connects directly"
      fi
      return 1
    fi
  fi

  # 2) uid / rule drift
  uid=$(tanke_uid)
  if [ -z "$uid" ]; then
    log "heal: WARN $PKG not installed (no uid) - rules cannot be validated"
    return 1
  fi
  ruid=$(rule_uid)
  ips=$(target_ips)
  want=$(echo "$ips" | sed '/^$/d' | wc -l)
  have=$(rule_count)
  hijack=$(health_get hijack)

  if [ "$uid" != "$ruid" ]; then
    log "heal: uid changed $ruid -> $uid (reinstall?) -> rebuilding rules"
    apply_iptables; changed=1
  elif [ "$hijack" = "degraded" ]; then
    : # stay degraded until an explicit up/restart clears it
  elif [ "$have" != "$want" ] || [ "$have" = "0" ]; then
    log "heal: rule drift (have=$have want=$want) -> rebuilding"
    apply_iptables; changed=1
  elif ! iptables -t nat -C OUTPUT -p tcp --dport 443 -m comment --comment $MARK -j $CHAIN 2>/dev/null; then
    log "heal: OUTPUT jump missing -> rebuilding"
    apply_iptables; changed=1
  fi

  if [ "$changed" = "1" ]; then mark_ok; fi
  return 0
}

# ---- watchdog ---------------------------------------------------------------
# Lives here (not only in service.sh) so that a manual `tanke-proxy.sh start`
# also leaves a watchdog behind. Before this, a phone that was brought up by
# hand had no watchdog at all until the next reboot.
#
# Tick = 25s. Each tick: rotate logs, heal (liveness + uid/rule drift). Every
# 12th tick (5 min): re-resolve the API IPs. The pid file is re-read every tick,
# so a newer watchdog supersedes an older one instead of both fighting over the
# proxy.
watchdog_loop() {
  mypid=$$
  echo "$mypid" > "$WDPID"
  log "watchdog: started (pid $mypid, tick 25s)"
  tick=0
  while true; do
    sleep 25
    cur=$(cat "$WDPID" 2>/dev/null)
    if [ "$cur" != "$mypid" ]; then
      log "watchdog: superseded by pid $cur, exiting"
      exit 0
    fi
    [ "$(getprop sys.boot_completed)" = "1" ] || continue
    tick=$((tick+1))

    ensure_no_global_proxy
    rotate_out_log
    heal

    if [ $((tick % 12)) -eq 0 ]; then
      before=$(cat "$TARGETS" 2>/dev/null)
      refresh_targets >/dev/null 2>&1
      after=$(cat "$TARGETS" 2>/dev/null)
      if [ "$before" != "$after" ]; then
        log "watchdog: target IP changed -> re-applying rules"
        apply_iptables
      fi
    fi
  done
}

watchdog_pid() {
  wp=$(cat "$WDPID" 2>/dev/null)
  [ -n "$wp" ] || { echo ""; return; }
  [ -d "/proc/$wp" ] && echo "$wp" || echo ""
}

# Idempotent: starts the watchdog only when no live one exists.
ensure_watchdog() {
  wp=$(watchdog_pid)
  if [ -n "$wp" ]; then return 0; fi
  log "watchdog: none running -> starting"
  setsid sh -c 'MODDIR="'"$MODDIR"'"; . "$MODDIR/common.sh"; watchdog_loop' \
    >> "$LOG" 2>&1 < /dev/null &
  sleep 1
  wp=$(watchdog_pid)
  [ -n "$wp" ] && log "watchdog: up (pid $wp)"
  return 0
}

stop_watchdog() {
  wp=$(watchdog_pid)
  if [ -n "$wp" ]; then
    kill "$wp" 2>/dev/null
    log "watchdog: stopped (pid $wp)"
  fi
  rm -f "$WDPID" 2>/dev/null
}

# ---- one full (re)apply ----------------------------------------------------
# Safe to call repeatedly. Order matters: get a usable rule set in place from
# the CACHED ip file first (boot window: the app may start before DNS works),
# then refresh and re-apply if the IP set actually changed.
up() {
  ensure_no_global_proxy
  rotate_out_log

  # bootstrap with whatever targets.env already holds
  if [ -s "$TARGETS" ]; then
    apply_iptables || log "up: bootstrap apply_iptables failed"
  fi

  if refresh_targets; then
    :
  else
    log "up: refresh_targets failed, continuing with cached targets"
  fi

  start_proxy || return 1
  apply_iptables || return 1
  health_set degraded no
  mark_ok
  ensure_watchdog
  return 0
}

down() {
  stop_watchdog
  flush_iptables
  stop_proxy
  ensure_no_global_proxy
}

status() {
  echo "=== global http_proxy ==="
  echo "  $(settings get global http_proxy)"
  echo "=== $PKG uid ==="
  echo "  current: $(tanke_uid)   rules: $(rule_uid)"
  echo "=== node ==="
  echo "  source: $(node_source)"
  echo "=== targets ($TARGETS) ==="
  sed 's/^/  /' "$TARGETS" 2>/dev/null || echo "  (none)"
  echo "=== certificates ==="
  echo "  ca: $( [ -f "$PROXY_DIR/ca.crt.pem" ] && echo "$PROXY_DIR/ca.crt.pem" || echo MISSING )"
  echo "  leaves: $(ls "$LEAF_DIR"/*.crt.pem 2>/dev/null | tr '\n' ' ' || echo none)"
  echo "=== proxy ==="
  echo "  listening: $(proxy_listening && echo YES || echo NO)  healthy: $(proxy_healthy && echo YES || echo NO)"
  echo "  pids: $(proxy_pids | tr '\n' ' ')"
  echo "  ver: $(cat "$PROXY_DIR/.proxy.version" 2>/dev/null || echo unknown)  md5: $(md5_of "$PROXY_DIR/proxy.mjs" | cut -c1-8)"
  echo "  watchdog pid: $(watchdog_pid)"
  echo "=== health ($HEALTH) ==="
  sed 's/^/  /' "$HEALTH" 2>/dev/null || echo "  (none)"
  echo "=== iptables ==="
  show_iptables
}
