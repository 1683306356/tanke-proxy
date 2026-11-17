#!/system/bin/sh
# ============================================================================
# adapt-probe.sh — 在手机上直接跑版本适配自检
#
#   su -c 'sh /data/adb/tanke-proxy/adapt-probe.sh'
#   su -c 'sh /data/adb/modules/tanke_proxy/tanke-proxy.sh adapt-probe'
#
# 做三件事：
#   1. 找到 node 运行时（优先模块内置）与代理日志
#   2. 跑 adapt-probe.mjs
#   3. 报告写到 $PROXY_DIR/adapt-probe-report.txt，并尽力复制一份到 /sdcard/
#      方便 `adb pull /sdcard/adapt-probe-report.txt` 取回
#
# 退出码沿用探测器：0=与 4.2.0 一致  2=不一致  3=数据不足
# ============================================================================

MODDIR="${MODDIR:-/data/adb/modules/tanke_proxy}"
CFGDIR=/data/adb/tanke-proxy
PROXY_DIR=$CFGDIR
REPORT=$PROXY_DIR/adapt-probe-report.txt
SDREPORT=/sdcard/adapt-probe-report.txt

# common.sh 里有 node_bin / node_env / PROXY_DIR 的定义；有就复用。
if [ -f "$MODDIR/common.sh" ]; then
  . "$MODDIR/common.sh" 2>/dev/null
fi

say() { echo "$@"; }

# ---------------------------------------------------------------- 环境自检
fail() {
  say ""
  say "[adapt-probe] 无法运行：$1"
  say ""
  exit 3
}

NODE=$(node_bin 2>/dev/null)
[ -n "$NODE" ] || NODE=/data/data/com.termux/files/usr/bin/node
[ -x "$NODE" ] || fail "找不到 node（试过 $MODDIR/bin/node 与 Termux 的 node）。装 full 包或装 Termux + node。"
# node_env 负责 LD_LIBRARY_PATH：内置运行时指向 $MODDIR/lib，Termux 指向 $PREFIX/lib。
node_env 2>/dev/null || {
  export HOME=$CFGDIR
  export PATH=$MODDIR/bin:/system/bin:/system/xbin
  export LD_LIBRARY_PATH=$MODDIR/lib
  export TMPDIR=$CFGDIR/tmp
  mkdir -p "$TMPDIR" 2>/dev/null
}
"$NODE" -e 'process.exit(0)' 2>/dev/null || fail "node 起不来（$NODE）。检查 $MODDIR/lib 是否完整。"

PROBE=""
for c in "$MODDIR/adapt-probe.mjs" "$CFGDIR/adapt-probe.mjs" "$PROXY_DIR/adapt-probe.mjs"; do
  [ -f "$c" ] && PROBE="$c" && break
done
[ -n "$PROBE" ] || fail "找不到 adapt-probe.mjs（应在 $MODDIR/ 或 $CFGDIR/）。"

# ---------------------------------------------------------------- 找日志
LOGS=""
for f in "$PROXY_DIR"/capture*.jsonl "$PROXY_DIR"/capture*.jsonl.[0-9]*; do
  [ -f "$f" ] && LOGS="$LOGS $f"
done
if [ -z "$LOGS" ]; then
  say ""
  say "[adapt-probe] 还没有日志：$PROXY_DIR/capture.jsonl 不存在或不含请求。"
  say "  下一步：先确保代理在跑（tanke-proxy.sh status），再用乐跑正常走一遍"
  say "          （登录 → 首页 → 跑步页 → 我的），然后重跑本命令。"
  say ""
  exit 3
fi

# 日志太旧也值得提醒 —— 用别的版本时，看到的是上一个版本留下的日志就白测了。
NEWEST=0
for f in $LOGS; do
  m=$(stat -c %Y "$f" 2>/dev/null || echo 0)
  [ "$m" -gt "$NEWEST" ] 2>/dev/null && NEWEST=$m
done
NOW=$(date +%s)
AGE=$((NOW - NEWEST))
if [ "$AGE" -gt 3600 ] 2>/dev/null; then
  say ""
  say "[adapt-probe] 注意：最新日志已经 $((AGE / 60)) 分钟没更新了。"
  say "  如果你刚换了 App 版本，请先让 App 走一遍（登录 → 首页 → 跑步页），再重跑本命令，"
  say "  否则测的还是旧版本的流量。"
fi

# ---------------------------------------------------------------- 运行
say ""
say "[adapt-probe] node=$NODE"
say "[adapt-probe] probe=$PROBE"
say "[adapt-probe] logs=$LOGS"
say ""

ADAPT_OUT="$REPORT" "$NODE" "$PROBE" $LOGS --out "$REPORT"
rc=$?

# 复制一份到 /sdcard（没有 sd 卡或没权限就跳过，不算失败）
if [ -f "$REPORT" ]; then
  cp "$REPORT" "$SDREPORT" 2>/dev/null && say "[adapt-probe] 报告副本: $SDREPORT"
  say "[adapt-probe] 报告: $REPORT"
  say "[adapt-probe] 取回电脑: adb pull $SDREPORT"
fi

say ""
case "$rc" in
  0) say "[adapt-probe] 结果：sign 规则与 4.2.0 一致 → 现有模块可以直接用。" ;;
  2) say "[adapt-probe] 结果：规则不一致 → 不要直接用，先看报告里的 [下一步]。" ;;
  *) say "[adapt-probe] 结果：数据不足，报告里写了缺什么。" ;;
esac

exit $rc
