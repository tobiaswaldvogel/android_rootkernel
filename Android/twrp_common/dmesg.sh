#!/vendor/bin/busybox ash
for i in 1 2 3 4 5 6; do
	/vendor/bin/busybox sleep 15
	/vendor/bin/busybox mkdir /log/twrp
	/vendor/bin/busybox dmesg >/log/twrp/dmesg$i.txt
done
/vendor/bin/busybox umount /log

