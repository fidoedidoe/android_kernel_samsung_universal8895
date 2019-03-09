#!/sbin/sh

. "$env";

cd "$tmp" && [ "$(ls)" ] || exit 0;

# Make init.d path if non-existent
print "Initializing init.d support...";
mkdir /system/etc/init.d;
chmod 755 /system/etc/init.d;

# Copy busybox into system
cp -f system/bin/busybox /system/bin/busybox;

# Change permissions
chmod 755 /system/bin/busybox;

print "Done!";
exit 0;
