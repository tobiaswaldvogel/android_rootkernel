#!/bin/sh
TA_IMAGE=$1
FTF=$2
BOOTIMG=./bootimg
if [ "`which ls`" == "ls" ]; then
  BB=./busybox
fi

TMP_DIR=dk_tmp

perform() {
	if [ ! -z "$BB" ]; then
		"$BB" "$@"
	else
		"$@"
	fi
}

ui_print() {
	perform echo -n -e "$1\n"
}

if [ -z $TA_IMAGE ] || [ -z $FTF ]; then
  ui_print "Usage: flash_dk <ta image backup> <flash file>"
  exit 1
fi

ui_print "- Extracting device key"
DK=$("$BOOTIMG" readta -i $TA_IMAGE -u 0x1046b -h)
if [ $? -ne 0 ]; then
  ui_print "Could not find device key in $TA_IMAGE (Unit 0x1046B)"
  exit 1
fi

DEVICE=$("$BOOTIMG" readta -i $TA_IMAGE -u 0x8a2)
if [ $? -ne 0 ]; then
  ui_print "Could not identify device from $TA_IMAGE (Unit 0x8A2)"
  exit 1
fi

ui_print "- Creating FTF file for device $DEVICE"
perform rm -rf $TMP_DIR
perform mkdir -p $TMP_DIR/META-INF

perform echo  >$TMP_DIR/DK.ta "// Miscta ta partition"
perform echo >>$TMP_DIR/DK.ta "02"
perform echo >>$TMP_DIR/DK.ta ""
perform echo >>$TMP_DIR/DK.ta "// format: Unit, size, data:"
perform echo >>$TMP_DIR/DK.ta "000007EC 0020 C0 02 00 02 44 4B 00 00 00 00 00 00 00 00 00 00"
perform echo >>$TMP_DIR/DK.ta "              $DK"

perform echo  >$TMP_DIR/META-INF/MANIFEST.MF "Manifest-Version: 1.0"
perform echo >>$TMP_DIR/META-INF/MANIFEST.MF "branding: DeviceKey"
perform echo >>$TMP_DIR/META-INF/MANIFEST.MF "version: 1.0"
perform echo >>$TMP_DIR/META-INF/MANIFEST.MF "device: $DEVICE"

"$BOOTIMG" zip -i $TMP_DIR -o $FTF

ui_print "- Cleaning up"
perform rm -rf $TMP_DIR

ui_print "Done"
