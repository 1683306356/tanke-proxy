#!/system/bin/sh
# Manual control for the tanke per-app MITM.
#   sh /data/adb/tanke-proxy/tanke-proxy.sh {start|stop|restart|status|log|iptables|refresh|heal|selftest|up|down|adapt-probe|deps|certs|verify-certs}
#
# start/stop toggles the per-app redirect. The system-wide http_proxy is NEVER
# set - that was the v1 bug that took every other app offline.
#
# v3: the runtime (node) and the certificates now live inside this deployment, so
# 'deps' answers "is anything missing?" and 'certs' makes it exist.
MODDIR=/data/adb/modules/tanke_proxy
. "$MODDIR/common.sh"

cmd="${1:-status}"
shift 2>/dev/null

# Full consistency check: everything the watchdog cares about, printed as
# PASS/FAIL so a bad state is obvious without reading the code.
selftest() {
  rc=0
  chk() {
    if [ "$2" = "1" ]; then echo "  PASS  $1"; else echo "  FAIL  $1"; rc=1; fi
  }
  echo "=== selftest $(date '+%F %T') ==="
  echo "--- baseline ---"
  echo "  pkg uid: $(tanke_uid)   rules built with: $(rule_uid)"
  echo "  node: $(node_source)  $( [ -n "$(node_bin)" ] && node_ok && echo "runs: $("$(node_bin)" -v 2>/dev/null)" || echo 'DOES NOT RUN' )"
  echo "  version: $(cat "$PROXY_DIR/.proxy.version" 2>/dev/null || echo unknown)  md5: $(md5_of "$PROXY_DIR/proxy.mjs" | cut -c1-8)"
  echo "  module md5: $(md5_of "$MODDIR/proxy.mjs" | cut -c1-8)"
  echo "  ca: $(md5_of "$PROXY_DIR/ca.crt.pem" | cut -c1-12)  leaves: $(ls "$LEAF_DIR"/*.crt.pem 2>/dev/null | wc -l)"
  echo "  targets: $(tr '\n' ' ' < "$TARGETS" 2>/dev/null)"
  echo "--- dependencies ---"
  nd=0; [ -n "$(node_bin)" ] && node_ok && nd=1
  chk "node runtime executable (source: $(node_source))" "$nd"
  pm=0; [ -f "$PROXY_DIR/proxy.mjs" ] && pm=1
  chk "proxy.mjs present ($PROXY_DIR/proxy.mjs)" "$pm"
  cm=0; [ -f "$PROXY_DIR/ca.crt.pem" ] && [ -f "$PROXY_DIR/ca.key.pem" ] && cm=1
  chk "CA cert + key present ($PROXY_DIR/ca.crt.pem)" "$cm"
  lc=0; lm=""
  for h in $INTERCEPT_HOSTS; do
    if [ -f "$LEAF_DIR/$h.crt.pem" ] && [ -f "$LEAF_DIR/$h.key.pem" ]; then lc=$((lc+1)); else lm="$lm $h"; fi
  done
  lw=$(echo $INTERCEPT_HOSTS | wc -w)
  chk "leaf cert for every intercept host (have=$lc want=$lw${lm:+ missing:$lm})" "$([ "$lc" = "$lw" ] && echo 1 || echo 0)"
  ck=0; cert_chain_ok && ck=1
  chk "cert chain verifies against the CA (gencert verify)" "$ck"
  echo "--- checks ---"
  hp=$(settings get global http_proxy)
  g=0
  case "$hp" in null|""|":0") g=1 ;; esac
  chk "no system-wide http_proxy (got '$hp')" "$g"
  proxy_listening && p=1 || p=0
  chk "proxy listening on 127.0.0.1:$PORT" "$p"
  proxy_healthy && h=1 || h=0
  chk "proxy heartbeat fresh (< ${HB_STALE}s)" "$h"
  a=0; [ "$(md5_of "$MODDIR/proxy.mjs")" = "$(md5_of "$PROXY_DIR/proxy.mjs")" ] && a=1
  chk "MODDIR/PROXY_DIR proxy.mjs identical (no silent version rollback)" "$a"
  u=0; [ -n "$(tanke_uid)" ] && [ "$(tanke_uid)" = "$(rule_uid)" ] && u=1
  chk "iptables uid matches current app uid" "$u"
  want=$(target_ips | sed '/^$/d' | wc -l); have=$(rule_count)
  r=0; [ "$have" = "$want" ] && [ "$have" -gt 0 ] 2>/dev/null && r=1
  chk "rule count matches target IPs (have=$have want=$want)" "$r"
  j=0; iptables -t nat -C OUTPUT -p tcp --dport 443 -m comment --comment $MARK -j $CHAIN 2>/dev/null && j=1
  chk "exactly one OUTPUT jump present" "$j"
  w=0; [ -n "$(watchdog_pid)" ] && w=1
  chk "watchdog running (pid $(watchdog_pid))" "$w"
  echo "--- state ---"
  echo "  hijack: $(health_get hijack)   fails: $(fails_now)   last_ok: $(health_get last_ok)"
  echo "--- result: $( [ "$rc" = "0" ] && echo ALL PASS || echo HAS FAILURES ) ---"
  return $rc
}

case "$cmd" in
  start|up)
    if up; then echo "OK: per-app redirect active (uid $(tanke_uid) -> $(target_ips | tr '\n' ' '))"; else echo "FAILED, see $LOG"; fi
    ;;
  stop|down)
    down
    echo "OK: redirect removed, proxy stopped, http_proxy=$(settings get global http_proxy)"
    ;;
  restart)
    down; sleep 1
    if up; then echo "OK: restarted"; else echo "FAILED, see $LOG"; fi
    ;;
  status)   status ;;
  iptables) show_iptables ;;
  heal)
    # one watchdog tick, synchronously - safe to run any time
    if heal; then echo "OK: heal done (nothing to do or repaired)"; else echo "heal: still unhealthy, see $LOG"; fi
    ;;
  selftest) selftest; exit $? ;;
  deps|dep)
    print_deps
    exit $?
    ;;
  certs|gencert)
    if ensure_certs; then
      echo "OK: certificates in place ($PROXY_DIR/ca.crt.pem, $LEAF_DIR)"
      cert_chain_ok && echo "OK: chain verifies" || echo "FAILED: chain does not verify - run 'verify-certs' for details"
    else
      echo "FAILED: certificates incomplete, see the messages above"
      exit 1
    fi
    ;;
  verify-certs|certcheck)
    cert_report
    exit $?
    ;;
  # 版本适配自检：换 App 版本后先跑这个，确认 sign 规则还是不是同一套。
  # 退出码 0=一致（可直接用） 2=不一致（要重新逆向） 3=数据不足
  adapt-probe|probe|adapt)
    ap="$MODDIR/adapt-probe.sh"
    [ -f "$ap" ] || ap="$PROXY_DIR/adapt-probe.sh"
    if [ ! -f "$ap" ]; then echo "adapt-probe.sh 缺失（应在 $MODDIR/ 或 $PROXY_DIR/）"; exit 3; fi
    sh "$ap"
    exit $?
    ;;
  refresh)
    refresh_targets && apply_iptables && echo "OK: targets + rules refreshed" || echo "FAILED"
    cat "$TARGETS" 2>/dev/null
    ;;
  rotate)
    rotate_out_log
    echo "OK: out log size now $(stat -c %s "$OUTLOG" 2>/dev/null || echo 0)"
    ;;
  log)
    n="${1:-40}"
    echo "=== boot.log (tail $n) ==="
    tail -n "$n" "$LOG" 2>/dev/null
    echo "=== proxy.out.log (tail 20) ==="
    tail -n 20 "$OUTLOG" 2>/dev/null
    ;;
  uninstall)
    down; rm -f "$STATE" "$HEALTH"; echo "OK: torn down"
    ;;
  *)
    echo "usage: $0 {start|stop|restart|status|iptables|refresh|heal|selftest|deps|certs|verify-certs|adapt-probe|rotate|log [n]|uninstall}"
    ;;
esac
