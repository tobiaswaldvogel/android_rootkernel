#!/bin/sh
VERSION=V5.11
SOURCE=$1
TARGET=$2

TOOLS=Android
SUPERSU_DIR=supersu
RAMDISK=ramdisk
VENDOR_OVL=vendor
LIB=${RAMDISK}/lib

#Detect Windows
which winver >/dev/null 2>&1
if [ $? -eq 0 ]; then
	WINDOWS=1
	XZ=./xz
else
	WINDOWS=0
	XZ=xz
fi

BOOTIMG=./bootimg
BB=./busybox

ask() {
	local response
	local response_caption
	local __retval=$2
	local __retvar=$3

	local prompt
	[ "$2" == "1" ] && prompt="[Y/n]" || prompt="[y/N]"

# Busybox "read" does not have -s and does not return before a linefeed,
# so let's use "choice" on Windows
	if [ ${WINDOWS} -eq 1 ]; then
		choice /C:YN /N /M "$1 $prompt"
		[ $? -eq 1 ] && __retval=1 ||__retval=0
	else
		read -s -n 1 -r -p "$1 $prompt " response
		if [ "$response" == "y" ] || [ "$response" == "Y" ]; then
			__retval=1
		elif [ "$response" == "n" ] || [ "$response" == "n" ]; then
			__retval=0
		fi
		[ ${__retval} -eq 1 ] && echo y || echo n
	fi
	eval ${__retvar}=${__retval}
}

perform() {
	if [ ${WINDOWS} -eq 1 ]; then
		"$BB" "$@"
	else
		"$@"
	fi
}

ui_print() {
	perform echo -n -e "$1\n"
}

add_policy() {
	"$BOOTIMG" seinject -q -s $2 -t $3 -c $4 -p $5 -P $1 -o $1
}

make_permissive() {
	"$BOOTIMG" seinject -q -Z $2 -P $1 -o $1
}

find_file() {
	local f
	if [ -f $1 ]; then
		echo $1
		return
	fi
	for f in $1@????; do
		if [ -f  $f ]; then
			echo $f
			return
		fi
	done
	for f in $1@????__lnk__; do
		if [ -f  $f ]; then
			echo $f
			return
		fi
	done
	for f in $1__lnk__; do
		if [ -f  $f ]; then
			echo $f
			return
		fi
	done
}

detect_platform() {
	local bin

	for file in init init.bin sbin/adbd; do
		bin=$(find_file ${RAMDISK}/${file})
		if [ ! -z "${bin}" ]; then
			"${BOOTIMG}" getarch -q -i ${bin}
			PLATFORM=$?
			if [ ${PLATFORM} -ne 0 ]; then
				ui_print "- Detected platform: $PLATFORM-bit"
				return
			fi
		fi
	done
	ui_print "- Could not determine platfrom"
}

detect_device_from_dtb() {
	local dtb_props=$(${BOOTIMG} dtbinfo -q -i $1)

	[ 0 -eq ${#dtb_props} ] && return

	eval ${dtb_props}
	VENDOR=${DTB_compatible%%,*}
	DEVICE=${DTB_compatible#*,}
	MODEL=${DEVICE%%-*}
	VARIANT=${DEVICE##*-}
}

detect_android() {
	local props=$(find_file ${RAMDISK}/default.prop)
	local val=$(perform grep ro.bootimage.build.fingerprint ${props})

	[ -z "$val" ] && return

	val=${val##*=}
	val=${val#*/}
	val=${val#*/}
	val=${val%%/*}
	VERSION=${val#*:}
	
	if [ "${VERSION}" == "6" -o "${VERSION}" == "6.0.1" ]; then
		SDK=23
	elif [ "${VERSION}" == "5.1" ]; then
		SDK=22
	elif [ "${VERSION}" == "5.0" ]; then
		SDK=21
	fi
	
	local info="- Detected Android version: ${VERSION}"
	[ ! -z ${SDK} ] && info="${info} (sdk ${SDK})"
	
	ui_print "${info}"
}

unzip_with_timestamp() {
	perform unzip -q -d $2 $1
	#Fix timestamps as busybox unzip doesn't set them
	i=0
	for s in $(perform unzip -l $1 | perform awk '{
		if (length($2) == 8) {
			y = substr($2,7)
			y = y < 70 ? "20" y : "19" y
			printf y substr($2,1,2) substr($2,4,2) substr($3,1,2) substr($3,4,2) ".00 " $4 " "
		}
	}')
	do
		if [ $i -eq 0 ]; then
			t=$s
			i=1
		else
			TZ=UTC perform touch -t $t $2/$s
			i=0
		fi
	done
}

extract_kernel_info() {
	perform strings -n 3 $1 | perform awk -v model_known=$2 '{
		if (!version && $1 == "Linux" && $2 == "version") {
			match($0, "[34]\\.[0-9]+\\.[0-9]+\\-[^\\ ]*")
			if (RLENGTH > 0)
				version = substr($0,RSTART, RLENGTH)
			else {
				match($0, "[34]\\.[0-9]+\\.[0-9]+")
				if (RLENGTH > 0)
					version = substr($0,RSTART, RLENGTH)
			}
		} else if (!model_known) {
			if (next_is_build) {
				model = $0
				next_is_build = 0
			} else if (next_is_variant) {
				variant = $0
				next_is_variant = 0;
			} else if ($0 == "build_product") {
				next_is_build = 1
			} else if ($0 == "build_variant") {
				next_is_variant = 1
			}
		}
	} END {
		print "KERNEL_VERSION=" version
		if (!model_known && model) {
			print "VENDOR=somc"
			print "MODEL=" model
			print "VARIANT=" variant
		}
	}'
}

get_kernel_info() {
	local kernel=$1
	local header=$(perform od -N 4 -A n -t x1 $kernel)
	header=${header## }

	[ "$header" == "1f 8b 08 00" ] && {
		perform cp ${kernel} ${kernel}_tmp.gz
		perform gunzip ${kernel}_tmp.gz
		extract_kernel_info ${kernel}_tmp ${MODEL}
		perform rm ${kernel}_tmp
		return
	}
	
#	Check for LZO compression
	local off=$($BOOTIMG offsetof $kernel 89 4c 5a 4f 00 0d 0a 1a 0a)
	[ 0 -ne ${#off} ] && {
		local o
		local last_off

		for o in $off; do
			last_off=$o
		done
		perform dd if=$kernel of=${kernel}_tmp.lzo bs=$last_off skip=1 2>/dev/null
		perform unlzop -c ${kernel}_tmp.lzo >${kernel}_tmp
		perform rm ${kernel}_tmp.lzo
		extract_kernel_info ${kernel}_tmp $MODEL
		perform rm ${kernel}_tmp
		return
	}

	extract_kernel_info $kernel $MODEL
}

unpack_kernel() {
	ui_print "- Unpacking kernel"
	local vars=$("$BOOTIMG" unpackelf -i "$SOURCE" -k kernel -r rd.gz -d dtb -q)

	if [ 0 -ne ${#vars} ]; then
		ui_print "  Found elf boot image"
		eval $vars
	else
		vars=$("$BOOTIMG" unpackimg -i "$SOURCE" -k kernel -r rd.gz -d dtb)
		if [ 0 -ne ${#vars} ]; then
			ui_print "  Found android boot image"
			eval $vars
		else
			ui_print "Unknown boot image format"
			ui_print "Aborting"
			exit 1
		fi
	fi

	if [ -f dtb ]; then
		detect_device_from_dtb dtb
	else
		detect_device_from_dtb kernel
	fi

	eval $(get_kernel_info kernel $MODEL)
	ui_print "  Kernel version: $KERNEL_VERSION"

	if [ ! -z  "$BOARD_TAGS_OFFSET" ] && [ -z "$BOARD_QCDT" ]; then
		ui_print "  Found appended DTB"
		perform gzip kernel
		perform mv kernel.gz kernel
		perform cat dtb >> kernel
		perform rm dtb
		unset BOARD_TAGS_OFFSET
	fi

	[ -z $MODEL ] && return

	if [ "$MODEL" == "sumire" ]; then
		BRAND="Xperia Z5"
	elif [ "$MODEL" == "suzuran" ]; then
		BRAND="Xperia Z5 compact"
	elif [ "$MODEL" == "satsuki" ]; then
		BRAND="Xperia Z5 premium"
	elif [ "$MODEL" == "ivy" ]; then
		BRAND="Xperia Z3+/Z4"
	elif [ "$MODEL" == "leo" ]; then
		BRAND="Xperia Z3"
	elif [ "$MODEL" == "aries" ]; then
		BRAND="Xperia Z3 compact"
	elif [ "$MODEL" == "sirius" ]; then
		BRAND="Xperia Z2"
	elif [ "$MODEL" == "yuga" ]; then
		BRAND="Xperia Z"
	elif [ "$MODEL" == "castor" ]; then
		BRAND="Xperia Tablet Z2"
	fi

	local cap_vendor="$VENDOR"
	if [ "$VENDOR" == "somc" ]; then
		cap_vendor="$cap_vendor (Sony)"
	fi

	local cap_device="$MODEL"
	if [ ! -z "$BRAND" ]; then
		cap_device="$cap_device ($BRAND)"
	fi

	ui_print "- Detected vendor: $cap_vendor, device: $cap_device, variant: $VARIANT"
}

unpack_initfs() {
	ui_print "- Unpacking initramfs"
	perform rm -rf $RAMDISK
	perform mkdir -p $RAMDISK
	perform gunzip -c rd.gz | "$BOOTIMG" unpackinitfs -d $RAMDISK
}

make_bootimg() {
	ui_print "- Creating new initramfs"
	"$BOOTIMG" mkinitfs $RAMDISK | perform gzip -c >newrd.gz
	
	ui_print "- Creating boot image"
	mkimg_arg="--pagesize $BOARD_PAGE_SIZE --kernel kernel --ramdisk newrd.gz --base 0x00000000 --ramdisk_offset 0x$BOARD_RAMDISK_OFFSET"
	if [ ! -z $BOARD_TAGS_OFFSET ]; then
		mkimg_arg="$mkimg_arg --dt dtb --tags_offset 0x$BOARD_TAGS_OFFSET"
	fi
	"$BOOTIMG" mkimg -o "$TARGET" --cmdline "$BOARD_KERNEL_CMDLINE" $mkimg_arg
}

disable_dmverity() {
	local disable=0
	local fstab=$(find_file $RAMDISK/fstab.qcom)
	perform grep -q verify $fstab
	[ $? -ne 0 ] && return
	
	ask "- dm-verity is enabled. Disable? (Say yes if you modify /system)" 1 disable
	[ $disable -eq 0 ] && return
	ui_print "  Disabling dm-verity"
	perform sed -i -e "s!wait,verify!wait!" $fstab
}

disable_sonyric() {
	local disable=0
	local rcfile=$(find_file $RAMDISK/init.sony-platform.rc)
	local ric=$(perform awk -v out="$rcfile.tmp" '{
		if ($1 != "write" || $2 != "/sys/kernel/security/sony_ric/enable") {
			if ($1 == "service" && $2 == "ric") {
				c="#"
				print "fixed"
			} else if (c=="#" && length($0)==0) {
				c=""
			}
			print c $0 >out

			if ($1 == "mount" && $4 == "/sys/kernel/security") {
				print "    write /sys/kernel/security/sony_ric/enable 0" >out
				print "fixed"
			}
		}
	}' $rcfile)
	[ ! -z  "$ric" ] && ask "- Sony RIC is enabled. Disable?" 1 disable

	if [ $disable -ne 0 ]; then
		ui_print "  Disabling Sony RIC"
		perform mv $rcfile.tmp $rcfile
		local policy=$(find_file $RAMDISK/sepolicy)
		add_policy $policy init securityfs file write  
	else
		perform rm $rcfile.tmp
	fi
}

add_file_context() {
	local contexts=$(find_file $RAMDISK/file_contexts)
	[ ! -z "$conexts" ] && {
		perform grep -q -F "$1" $contexts
		[ $? -eq 0 ] && return

		perform echo -e >>$contexts ""
		perform echo -e >>$contexts "##########################"
		perform echo -e >>$contexts "#$3"
		perform echo -e >>$contexts "$1(/.*)?\t\tu:object_r:$2:s0"
	} || {
		contexts=$(find_file $RAMDISK/file_contexts.bin)
		$BOOTIMG fctxinject -q -i $contexts -c u:object_r:$2:s0 -p $1 -o $contexts
	}

	local policy=$(find_file $RAMDISK/sepolicy)
	add_policy $policy init rootfs dir      relabelfrom
	add_policy $policy init rootfs file     relabelfrom
	add_policy $policy init rootfs lnk_file relabelfrom
	add_policy $policy init $2     dir      relabelto
	add_policy $policy init $2     file     relabelto
	add_policy $policy init $2     lnk_file relabelto
}

# Since android 7 the linker is enforcing that libraries must be under the paths
#   /system/lib[64] and /vendor/lib[64]
# As softlinks are canolized links to /system/vendor/... do not work anymore
# Therefore links to lib and lib64 are pointing now to bind mount under /vendor
# RIC needs to be disabled temporarily in order to permit the bind mounts
add_vendor_overlay() {
	local initrc=$(find_file $RAMDISK/init.rc)
	perform grep -q -F "init.vendor_ovl.sh" $initrc
	[ $? -eq 0 ] && return
	
	add_file_context "/$VENDOR_OVL" "system_file" "/vendor overlay"

	local vendor=$(find_file $RAMDISK/vendor)
	[ ! -z $vendor ] && perform rm $vendor
	perform mkdir $RAMDISK/$VENDOR_OVL
	perform mkdir $RAMDISK/$VENDOR_OVL/lib
	perform mkdir $RAMDISK/$VENDOR_OVL/lib/bind_lib
	[ $PLATFORM -eq 64 ] && {
		perform mkdir $RAMDISK/$VENDOR_OVL/lib64
		perform mkdir $RAMDISK/$VENDOR_OVL/lib64/bind_lib64
	}
	perform echo -n >$RAMDISK/$VENDOR_OVL/etc__lnk__ /system/vendor/etc
	perform mkdir $RAMDISK/$VENDOR_OVL/bin
	perform cp -a $TOOLS/busybox $RAMDISK/$VENDOR_OVL/bin/busybox@0755
	perform cp -a $TOOLS/init.vendor_ovl.sh $RAMDISK/init.vendor_ovl.sh@0750

	perform echo -e >>$initrc ""
	perform echo -e >>$initrc "on vendor-ovl"
	perform echo -e >>$initrc "    mount securityfs securityfs /sys/kernel/security nosuid nodev noexec"
	perform echo -e >>$initrc "    chmod 0640 /sys/kernel/security/sony_ric/enable"
	perform echo -e >>$initrc "    write /sys/kernel/security/sony_ric/enable 0"
	perform echo -e >>$initrc "    mount none /system/vendor/lib /$VENDOR_OVL/lib/bind_lib bind"
	[ $PLATFORM -eq 64 ] && perform echo -e >>$initrc "    mount none /system/vendor/lib64 /$VENDOR_OVL/lib64/bind_lib64 bind"
	perform echo -e >>$initrc "    write /sys/kernel/security/sony_ric/enable 1"
	perform echo -e >>$initrc "    exec u:r:init:s0 -- /system/bin/sh /init.vendor_ovl.sh /$VENDOR_OVL"
	perform echo -e >>$initrc "    restorecon_recursive /$VENDOR_OVL"

	perform sed -i -e "s!\(.*\)\(trigger post-fs\)\$!\1trigger vendor-ovl\n\1\2!" $initrc

	local policy=$(find_file $RAMDISK/sepolicy)
	add_policy $policy init		shell_exec	file		execute_no_trans
	add_policy $policy init		rootfs		file		create,write,setattr,unlink,execute_no_trans
	add_policy $policy init		rootfs		dir			create,write,setattr,add_name,remove_name,rmdir
	add_policy $policy init		rootfs		lnk_file	create,write,setattr,unlink,rename
	add_policy $policy toolbox	toolbox		capability	sys_module
	add_policy $policy init		system_file	dir			setattr
	add_policy $policy init		securityfs	dir			mounton
	add_policy $policy init		securityfs	file		write
}

add_preload() {
	local pattern
	for rcfile in $RAMDISK/*.rc*; do
		pattern=$(perform grep -h "LD_PRELOAD" $rcfile 2>/dev/null)
		[ ! -z "$pattern" ] && perform sed -i -e "s!$pattern!$pattern:$1!" $rcfile && return
	done

	envrc=$(find_file $RAMDISK/init.environ.rc)
	perform echo >>$envrc "    export LD_PRELOAD $1"
}

adb_insecure_missing()
{
	local adbd=$(find_file $RAMDISK/sbin/adbd)
	[ -z ${adbd} ] && {
		echo 0
		return
	}

	perform grep -q ro.adb.secure ${adbd}
	echo $?
}

add_twrp()
{
	local TWRP_COMMON=$TOOLS/twrp_common
	local TWRP_KDIR=$TOOLS/twrp_common_kmodules/$KERNEL_VERSION
	local TWRP_DIR=$TOOLS/twrp_$MODEL
	local TWRP_WORK=twrp_root
	local install
	local kmodules

	if [ -f "$TWRP_DIR/kmodules.txt" ]; then
		local kmodule

		if [ ! -d "$TWRP_KDIR" ]; then
			ui_print "- Skipping TWRP recovery. No kernel modules for $KERNEL_VERSION available"
			return
		fi

		kmodules=$(perform cat "$TWRP_DIR/kmodules.txt")
		for kmodule in $kmodules; do
			if [ ! -f "$TWRP_KDIR/$kmodule" ]; then
				ui_print "- Skipping TWRP recovery. Module $kmodule for $KERNEL_VERSION not found"
				return
			fi
		done
	fi

	if [ ! -d "$TWRP_DIR" ]; then
		ask "- There is no TWRP template for $MODEL. Install anyway?" 0 install
	else
		ask "- Install TWRP recovery?" 1 install
	fi

	[ $install -ne 1 ] && return

	local initbin=$(find_file $RAMDISK/init.bin)
	if [ -z "$initbin" ]; then
		local init=$(find_file $RAMDISK/init)
		local initsize=$(perform wc -c <$init)
		if [ $initsize -le 20000 ]; then
			ui_print "  Skipping TWRP integration. Could not identify init binary"
			return
		fi
		perform mv $init $RAMDISK/init.bin@0750
		ui_print "  Installing TWRP"
	else
		ui_print "  Updating TWRP"
	fi
	perform cp -a $TOOLS/init $RAMDISK/init@0750

	add_vendor_overlay
	perform cp -a $TOOLS/bootimg $RAMDISK/$VENDOR_OVL/bin/bootimg@0755
	
	perform rm -rf $TWRP_WORK
	perform mkdir -p $TWRP_WORK
	perform cp -a $TWRP_COMMON/* $TWRP_WORK/

	if [ -d $TWRP_DIR ]; then
		perform cp -a $TWRP_DIR/root/* $TWRP_WORK/
	fi

	if [ ! -z "$kmodules" ]; then
		local kmodule
		
		perform mkdir -p $TWRP_WORK/sbin
		for kmodule in $kmodules; do
			perform cp -a $TWRP_KDIR/$kmodule $TWRP_WORK/sbin/
		done
	fi

	local insecure_missing=$(adb_insecure_missing)
	[ ${insecure_missing} -eq 1 ] && {
#		Copy adb pubkey for users with encrypted /data
		local adb_pubkey=${HOMEPATH}/.android/adbkey.pub
		[ -e ${adb_pubkey} ] && {
			local inst_pubkey
			ask "- This adbd requires authentication. Add your public key?" 1 inst_pubkey
			[ ${inst_pubkey} -eq 1 ] && {
				local adb_dir=/data/misc/adb
				perform mkdir -p ${TWRP_WORK}/${adb_dir}
				perform cp ${adb_pubkey} ${TWRP_WORK}/${adb_dir}/adb_keys
			}
		}
	}	

	ui_print "  Compressing TWRP image"
	"$BOOTIMG" mkinitfs $TWRP_WORK | $XZ -c >$RAMDISK/$VENDOR_OVL/twrp.xz
	perform rm -rf $TWRP_WORK
}

add_supersu()
{
	local file
	local SUPERSU
	local SUPERSU_PLATFORM_DIR
	local LIBDIR
	local preinstall
	
	for file in SuperSU*.zip; do SUPERSU=$file; done
	[ ! -f $SUPERSU ] && return

	if [ "${VERSION%%.*}" -lt "6" ]; then
		ui_print "  Skipping SuperSU integration. Only supported for Android 6+"
		return
	fi

	ask "- Found $SUPERSU. Install?" 1 preinstall
	[ $preinstall -ne 1 ] && return

	add_vendor_overlay

	perform rm -rf $SUPERSU_DIR
	perform mkdir -p $SUPERSU_DIR
	unzip_with_timestamp $SUPERSU $SUPERSU_DIR

	if [ $PLATFORM -eq 64 ]; then
		SUPERSU_PLATFORM_DIR=$SUPERSU_DIR/arm64
		LIBDIR=$VENDOR_OVL/lib64
	else
		SUPERSU_PLATFORM_DIR=$SUPERSU_DIR/armv7
		LIBDIR=$VENDOR_OVL/lib
	fi

	perform cp -a $SUPERSU_PLATFORM_DIR/su $RAMDISK/$VENDOR_OVL/bin/su@0755
	perform echo -n >$RAMDISK/$VENDOR_OVL/bin/daemonsu__lnk__ su
	perform cp -a $SUPERSU_PLATFORM_DIR/supolicy $RAMDISK/$VENDOR_OVL/bin/supolicy@0755
	perform cp -a $SUPERSU_PLATFORM_DIR/sukernel $RAMDISK/$VENDOR_OVL/bin/sukernel@0755
	perform cp -a $SUPERSU_PLATFORM_DIR/libsupol.so $RAMDISK/$LIBDIR/libsupol.so@0644
	perform echo -n >$RAMDISK/su__lnk__ /$VENDOR_OVL
	
	for file in $SUPERSU_DIR/common/*.apk; do
#		Strip assests (= the binaries) from SuperSU apk
#		As SuperSU is in the boot image it cannot be updated anyway
#		Without assets SuperSU also does not perform a check of the binaries
#		and 2.65 stable works as well
#		As the signature is on file level, removing files does not break the package signature
		ui_print "  Stripping SuperSU app"
		perform mkdir -p $SUPERSU_DIR/apktmp
		unzip_with_timestamp $file $SUPERSU_DIR/apktmp
		perform rm -rf $SUPERSU_DIR/apktmp/assets
		perform rm $file
		$BOOTIMG zip -i $SUPERSU_DIR/apktmp -o $file

		perform mkdir -p $RAMDISK/$VENDOR_OVL/app/SuperSU
		perform cp -a $file $RAMDISK/$VENDOR_OVL/app/SuperSU/SuperSU.apk
	done

	local initrc=$(find_file $RAMDISK/init.rc)
	perform grep -q '^service daemonsu' $initrc
	if [ $? -ne 0 ]; then
		ui_print "  Adding service entry for SuperSU"
		perform echo >>$initrc ""
		perform echo >>$initrc "# launch SuperSU daemon"
		perform echo >>$initrc "service daemonsu /$VENDOR_OVL/bin/daemonsu --auto-daemon"
		perform echo >>$initrc "    class late_start"
		perform echo >>$initrc "    user root"
		perform echo >>$initrc "    seclabel u:r:init:s0"
		perform echo >>$initrc "    oneshot"
	fi
	perform rm -rf $SUPERSU_DIR

	local policy=$(find_file $RAMDISK/sepolicy)
	add_policy $policy init		logd		dir     	search
	add_policy $policy init		logd		file   	 	read,open
	add_policy $policy init		system_file	file		execute_no_trans
	add_policy $policy init		kernel		security	read_policy,load_policy
	
#	For copying app_process to /vendor/bin
	add_policy $policy toolbox	zygote_exec	file		read,open
}

add_drmfix() {
	local supported=0
	local m

	for m in sumire suzuran satsuki ivy castor scorpion leo karin sirius aries; do
		[ "$m" == "$MODEL" ] && supported=1
	done

	if [ $supported -eq 0 ]; then
		ask "- DRM fix is unsuppported/untested for model $MODEL. Install anyway?" 0 supported
	else
		ask "- Install DRM fix?" 1 supported
	fi

	if [ $supported -eq 0 ]; then
		ui_print "  Skipping drmfix"
		return
	fi

	add_vendor_overlay
	local initrc=$(find_file $RAMDISK/init.rc)
	perform cp -a $TOOLS/libdrmfix32.so $RAMDISK/$VENDOR_OVL/lib/libdrmfix.so@0644
	perform sed -i -e "s!\(on early-init\)!\1\n    restorecon /$VENDOR_OVL/lib/libdrmfix.so!" $initrc
	[ $PLATFORM -eq 64 ] && {
		perform cp -a $TOOLS/libdrmfix64.so $RAMDISK/$VENDOR_OVL/lib64/libdrmfix.so@0644
		perform sed -i -e "s!\(on early-init\)!\1\n    restorecon /$VENDOR_OVL/lib64/libdrmfix.so!" $initrc
	}
	add_preload libdrmfix.so
}

add_with_xz() {
	perform cp $1 $2
	$XZ -9 $2
}

add_xposed()
{
	local file
	local LIBDIR
	local install
	local pattern
	local XPOSED
	local XPOSED_DIR=xposed
	
	[ $PLATFORM -eq 64 ] && pattern=xposed-*sdk${SDK}-arm64.zip || pattern=xposed-*sdk${SDK}-arm.zip
	
	for file in $pattern; do XPOSED=$file; done
	[ ! -f $XPOSED ] && return

	if [ "${VERSION%%.*}" != "6" ]; then
		ui_print "  Skipping xposed integration. Only supported for Android 6"
		return
	fi

	ask "- Found $XPOSED. Install?" 1 install
	[ $install -ne 1 ] && return

	perform rm -rf $XPOSED_DIR
	perform mkdir -p $XPOSED_DIR
	unzip_with_timestamp $XPOSED $XPOSED_DIR

	add_vendor_overlay

	local policy=$(find_file $RAMDISK/sepolicy)
	add_policy $policy dex2oat	apk_tmp_file	dir		 search
#	Avoid the LD_PRELOAD is removed on transition from installd to dex2oat
	add_policy $policy installd			dex2oat			process	 noatsecure
	add_policy $policy untrusted_app	dex2oat			process	 noatsecure
	
	perform mkdir -p $RAMDISK/$VENDOR_OVL/framework
	perform cp  $XPOSED_DIR/system/framework/XposedBridge.jar		$RAMDISK/$VENDOR_OVL/framework/XposedBridge.jar@0644
	perform cp  $XPOSED_DIR/system/xposed.prop						$RAMDISK/$VENDOR_OVL/xposed.prop@0644
	add_with_xz $XPOSED_DIR/system/lib/libart.so					$RAMDISK/$VENDOR_OVL/lib/libart.so
	add_with_xz $XPOSED_DIR/system/lib/libart-compiler.so			$RAMDISK/$VENDOR_OVL/lib/libart-compiler.so
	perform cp  $XPOSED_DIR/system/lib/libsigchain.so				$RAMDISK/$VENDOR_OVL/lib/libsigchain.so@0644
	perform cp  $XPOSED_DIR/system/lib/libxposed_art.so				$RAMDISK/$VENDOR_OVL/lib/libxposed_art.so@0644
	perform cp  $TOOLS/libxposed_preload32.so						$RAMDISK/$VENDOR_OVL/lib/libxposed_preload.so@0644
	perform cp  $TOOLS/libxposed32.so								$RAMDISK/$VENDOR_OVL/lib/libxposed.so@0644
	perform cp  $TOOLS/libxposed_safemap32.so						$RAMDISK/$VENDOR_OVL/lib/libxposed_safemap.so@0644

	if [ $PLATFORM -ne 64 ]; then
		perform cp  $XPOSED_DIR/system/lib/libart-disassembler.so		$RAMDISK/$VENDOR_OVL/lib/libart-disassembler.so@0644
	else
		perform cp  $XPOSED_DIR/system/lib64/libart-disassembler.so		$RAMDISK/$VENDOR_OVL/lib64/libart-disassembler.so@0644
		add_with_xz $XPOSED_DIR/system/lib64/libart.so					$RAMDISK/$VENDOR_OVL/lib64/libart.so
		perform cp  $XPOSED_DIR/system/lib64/libsigchain.so				$RAMDISK/$VENDOR_OVL/lib64/libsigchain.so@0644
		perform cp  $XPOSED_DIR/system/lib64/libxposed_art.so			$RAMDISK/$VENDOR_OVL/lib64/libxposed_art.so@0644
		perform cp  $TOOLS/libxposed_preload64.so  						$RAMDISK/$VENDOR_OVL/lib64/libxposed_preload.so@0644
		perform cp  $TOOLS/libxposed64.so								$RAMDISK/$VENDOR_OVL/lib64/libxposed.so@0644
		perform cp  $TOOLS/libxposed_safemap64.so						$RAMDISK/$VENDOR_OVL/lib64/libxposed_safemap.so@0644
	fi
	add_preload libxposed_preload.so

	perform rm -rf $XPOSED_DIR
}

add_additional()
{
	[ ! -d install ] && return

	local install
	ask "- Found install directory. Do you want to integrate the contents?" 1 install
	[ $install -ne 1 ] && return
	
	add_vendor_overlay
	
	ui_print "  Including contents from install directoy"
	perform cp -a install/* $RAMDISK/$VENDOR_OVL/
}

add_bb()
{
	local install
	ask "- Install busybox?" 1 install
	[ $install -ne 1 ] && return

	add_vendor_overlay
	perform touch $RAMDISK/$VENDOR_OVL/bin/busybox_keep@0644
}

sepolicy_fixes()
{
	local policy=$(find_file $RAMDISK/sepolicy)
	local source

	add_policy $policy ipacm			ipacm-diag		unix_dgram_socket	sendto
	add_policy $policy system_server	logd			dir					search
	add_policy $policy system_server	logd			file 		  	 	read,open
	add_policy $policy vold				logd			dir					search
	add_policy $policy vold				logd			file 		  	 	read,open
	for source in rild qcomsysd cnd netmgrd ims cnd thermal-engine mm-pp-daemon time_daemon dpmd ipacm-diag audioserver location bluetooth system_server imsqmidaemon dataservice_app; do
		add_policy $policy $source		diag_device		chr_file			write,read,open,ioctl
	done
	add_policy $policy toolbox			unlabeled		dir					getattr,open,read,write
}

cleanup() {
	ui_print "- Cleaning up"
	perform rm -rf $RAMDISK
	perform rm -f kernel rd.gz newrd.gz dtb
}

SCRIPT=$(basename $0 .sh)
if [ -z $1 ] && [ -z $2 ]; then
	ui_print "Usage: $SCRIPT <kernel image> <boot image>\n"
	ui_print "The kernel elf image can be extracted from the kernel.sin with Flashtool"
	ui_print "or you can extract from your phone from the boot partition by booting an existing recovery"
	exit 1
fi

ui_print "Rootkernel $VERSION\n"

#Make sure we run on bash in Linux
if [ $WINDOWS -eq 0 ]; then
	if [ -z "$BASH_VERSION" ]; then
		BASH=$(which bash 2>/dev/null)
		if [ -z "$BASH" ]; then
			ui_print "This script requires bash"
			exit 1
		fi
		exec $BASH $@
	fi
fi

if [ ! -f $1 ]; then
  ui_print "Kernel Image not found"
  exit 1
fi

unpack_kernel

[ -z "$VENDOR" ] && {
	ui_print "- Could not determine device"
	ui_print "Abort"
	exit 2
}

unpack_initfs
detect_platform
detect_android
disable_dmverity

[ "$VENDOR" == "somc" ] && disable_sonyric

add_twrp
add_supersu
add_xposed

[ "$VENDOR" == "somc" ] && add_drmfix

add_bb

add_additional
sepolicy_fixes

make_bootimg
cleanup

ui_print "Done"
