#!/system/bin/sh
# Magisk runs this right after unpacking the module.
#
# It exists for one reason: Magisk's installer normalises every file to 0644,
# which would leave bin/node non-executable and the module unable to start at
# boot. Everything else (certificates, first start) happens in service.sh at
# boot, or immediately if the user runs deploy.sh.
chmod 755 "$MODPATH"/bin/node 2>/dev/null
chmod 755 "$MODPATH"/*.sh 2>/dev/null
chmod 755 "$MODPATH"/lib/*.so* 2>/dev/null
chmod 755 "$MODPATH/META-INF/com/google/android/update-binary" 2>/dev/null
ui_print "- tanke_proxy: file modes fixed"
ui_print "- tanke_proxy: certificates are generated on first boot"
