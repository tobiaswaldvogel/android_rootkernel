#!/bin/sh
VERSION=V5.23
SOURCE=$1
TARGET=$2

TOOLS=Android
SUPERSU_DIR=supersu
SUPERUSER_DIR=superuser
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
SEINJECT_TRACE_LEVEL=1
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

se_allow() {
	"$BOOTIMG" seinject -w ${SEINJECT_TRACE_LEVEL} -s $2 -t $3 -c $4 -p $5 -P $1 -o $1
}

se_trans() {
	"$BOOTIMG" seinject -w ${SEINJECT_TRACE_LEVEL} -s $2 -t $5 -c $4 -f $3 -P $1 -o $1
}

se_add_type() {
	"$BOOTIMG" seinject -w ${SEINJECT_TRACE_LEVEL} -z $2 -P $1 -o $1
}

se_permissive() {
	"$BOOTIMG" seinject -w ${SEINJECT_TRACE_LEVEL} -Z $2 -P $1 -o $1
}

se_add_attr() {
	"$BOOTIMG" seinject -w ${SEINJECT_TRACE_LEVEL} -s $2 -a $3 -P $1 -o $1
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
	RIC_DISABLED=1

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
		se_allow ${policy} init securityfs file write  
	else
		perform rm $rcfile.tmp
	fi
}

add_file_context() {
	local wildcard=""
	local contexts=$(find_file $RAMDISK/file_contexts)
	if [ ! -z "$contexts" ]; then
		perform grep -q -F "$1" $contexts
		[ $? -eq 0 ] && return

		[ ! -z "$3" ] && wildcard="(/.*)?"
		perform echo -e >>${contexts} ""
		perform echo -e >>${contexts} "##########################"
		perform echo -e >>${contexts} "$1${wildcard}\t\tu:object_r:$2:s0"
	else
		contexts=$(find_file $RAMDISK/file_contexts.bin)
		[ ! -z $3 ] && wildcard=-w
		$BOOTIMG fctxinject -q -i ${contexts} ${wildcard} -c u:object_r:$2:s0 -p $1 -o $contexts
	fi

	local policy=$(find_file $RAMDISK/sepolicy)
	se_allow ${policy} init rootfs dir      relabelfrom
	se_allow ${policy} init rootfs file     relabelfrom
	se_allow ${policy} init rootfs lnk_file relabelfrom
	se_allow ${policy} init $2     dir      relabelto
	se_allow ${policy} init $2     file     relabelto
	se_allow ${policy} init $2     lnk_file relabelto
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
	
	add_file_context "/$VENDOR_OVL" "system_file" 1

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
	[ -z "$RIC_DISABLED" ] && perform echo -e >>$initrc "    write /sys/kernel/security/sony_ric/enable 1"
	perform echo -e >>$initrc "    exec u:r:init:s0 -- /system/bin/sh /init.vendor_ovl.sh /$VENDOR_OVL"
	perform echo -e >>$initrc "    restorecon_recursive /$VENDOR_OVL"

	perform sed -i -e "s!\(.*\)\(trigger post-fs\)\$!\1trigger vendor-ovl\n\1\2!" $initrc

	local policy=$(find_file $RAMDISK/sepolicy)
	se_allow ${policy} init		shell_exec	file		execute_no_trans
	se_allow ${policy} init		rootfs		file		create,write,setattr,unlink,execute_no_trans
	se_allow ${policy} init		rootfs		dir			create,write,setattr,add_name,remove_name,rmdir
	se_allow ${policy} init		rootfs		lnk_file	create,write,setattr,unlink,rename
	se_allow ${policy} toolbox	toolbox		capability	sys_module
	se_allow ${policy} init		system_file	dir			setattr
	se_allow ${policy} init		securityfs	dir			mounton
	se_allow ${policy} init		securityfs	file		write
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

add_kcal_module() {
	#	Install kcal kernel module if available
	local kcal
	local KCAL_MODULE
	local install

	for kcal in $TOOLS/kcal/$KERNEL_VERSION/*; do KCAL_MODULE=${kcal}; done
	[ ! -f ${KCAL_MODULE} ] && return

	ask "- Install kcal kernel module?" 1 install
	[ ${install} -ne 1 ] && return

	add_vendor_overlay

	local mod_dir=$RAMDISK/$VENDOR_OVL/lib/modules
	perform mkdir -p ${mod_dir}
	perform cp ${kcal} ${mod_dir}/

#	Due to MLS we need a new type for sysfs and grant access for the app
	local policy=$(find_file $RAMDISK/sepolicy)
	se_add_type ${policy} sysfs_kcal
	se_add_attr ${policy} sysfs_kcal fs_type
	se_add_attr ${policy} sysfs_kcal sysfs_type
	se_add_attr ${policy} sysfs_kcal mlstrustedobject
	se_allow ${policy} sysfs_kcal		sysfs		filesystem	associate
	se_allow ${policy} untrusted_app	sysfs_kcal	dir			search
	se_allow ${policy} untrusted_app	sysfs_kcal	file		open,read,getattr
	add_file_context "/sys/devices/platform/kcal_ctrl.0" "sysfs_kcal" 1
	perform echo -e >>$initrc "    restorecon_recursive /sys/devices/platform/kcal_ctrl.0"
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

	SUPER_INSTALLED=1
	
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
#		in Android 6
		if [ "${VERSION%%.*}" -eq "6" ]; then
			ui_print "  Stripping SuperSU app"
			perform mkdir -p $SUPERSU_DIR/apktmp
			unzip_with_timestamp $file $SUPERSU_DIR/apktmp
			perform rm -rf $SUPERSU_DIR/apktmp/assets
			perform rm $file
			$BOOTIMG zip -i $SUPERSU_DIR/apktmp -o $file
		fi

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
	se_allow ${policy} init		logd		dir     	search
	se_allow ${policy} init		logd		file   	 	read,open
	se_allow ${policy} init		system_file	file		execute_no_trans
	se_allow ${policy} init		kernel		security	read_policy,load_policy
	
#	For copying app_process to /vendor/bin
	se_allow ${policy} toolbox	zygote_exec	file		read,open
}

add_superuser()
{
	local file
	local SUPERUSER
	local preinstall
	
	for file in superuser*.zip; do SUPERUSER=$file; done
	[ ! -f $SUPERUSER ] && return

	if [ "${VERSION%%.*}" -lt "6" ]; then
		ui_print "  Skipping superuser integration. Only supported for Android 6+"
		return
	fi

	ask "- Found $SUPERUSER. Install?" 1 preinstall
	[ $preinstall -ne 1 ] && return

	ask "# Make su permissive (Permits any action as su)?" 1 su_permissive

	add_vendor_overlay

	perform rm -rf $SUPERUSER_DIR
	perform mkdir -p $SUPERUSER_DIR
	unzip_with_timestamp $SUPERUSER $SUPERUSER_DIR

	perform cp -a $SUPERUSER_DIR/scripts/bin/su-arm $RAMDISK/$VENDOR_OVL/bin/su@0755

	local initrc=$(find_file $RAMDISK/init.rc)
	perform grep -q '^service su_daemon' $initrc
	if [ $? -ne 0 ]; then
		ui_print "  Adding service entry for superuser"
		perform echo >>$initrc ""
		perform echo >>$initrc "# launch su daemon"
		perform echo >>$initrc "service su_daemon /$VENDOR_OVL/bin/su --daemon"
		perform echo >>$initrc "    class main"
		perform echo >>$initrc "    user root"
		perform echo >>$initrc "    seclabel u:r:su_daemon:s0"
		perform echo >>$initrc "    oneshot"

		perform sed -i -e "s!\(on early-init\)!\1\n    restorecon /$VENDOR_OVL/bin/su!" $initrc
	fi

	perform rm -rf $SUPERUSER_DIR

	ui_print "  Adjusting SE Linux policy for superuser"

	local type
	local source
	local target
	local policy=$(find_file $RAMDISK/sepolicy)

	se_add_type ${policy} su_daemon
	se_add_attr ${policy} su_daemon domain
	se_add_attr ${policy} su_daemon mlstrustedsubject

	se_add_type ${policy} su
	se_add_attr ${policy} su domain
	se_add_attr ${policy} su appdomain
	se_add_attr ${policy} su netdomain
	se_add_attr ${policy} su bluetoothdomain
	se_add_attr ${policy} su mlstrustedsubject

	se_add_type ${policy} su_device
	se_add_attr ${policy} su_device domain
	se_add_attr ${policy} su_device mlstrustedobject

#	Transition to su_socket in dev
	se_trans ${policy} su_daemon	device			file			su_device
	se_trans ${policy} su_daemon	device			dir				su_device
	se_allow ${policy} su_device	tmpfs			filesystem		associate
	se_allow ${policy} su_daemon	tmpfs			filesystem		associate

#	Allow start from init and transition to u:r:su_daemon:s0
	se_allow ${policy} init			su_daemon		process			transition,rlimitinh,siginh,noatsecure
	se_allow ${policy} su_daemon	rootfs			dir				open,read,ioctl
	se_allow ${policy} su_daemon	rootfs			file			getattr,open,read,ioctl,lock
	se_allow ${policy} su_daemon	rootfs			lnk_file		getattr

	se_allow ${policy} su_daemon	qti_init_shell	fd				use
	se_allow ${policy} su_daemon	init			dir				search
	se_allow ${policy} su_daemon	init			file			open,read
	se_allow ${policy} su_daemon	init			lnk_file		read

	se_allow ${policy} su_daemon	proc			file			read,open,getattr
	se_allow ${policy} su_daemon	devpts			chr_file		read,write,open,getattr

	se_allow ${policy} su_daemon	system_file		file			entrypoint
	se_allow ${policy} su_daemon	system_file		lnk_file		open,execute
	se_allow ${policy} su_daemon	su_daemon		dir				search,read,create
	se_allow ${policy} su_daemon	su_daemon		file			read,write,open
	se_allow ${policy} su_daemon	su_daemon		lnk_file		read
	se_allow ${policy} su_daemon	su_daemon	unix_dgram_socket	create,connect,write
	se_allow ${policy} su_daemon	su_daemon	unix_stream_socket	create,ioctl,read,getattr,write,setattr,lock,append,bind,connect,getopt,setopt,shutdown,listen,accept
	se_allow ${policy} su_daemon	untrusted_app_devpts chr_file	read,write,open,getattr
	se_allow ${policy} su_daemon	su_daemon		capability		setuid,setgid

	#Access to /data/data/me.phh.superuser/xxx
	se_allow ${policy} su_daemon	app_data_file	dir				search,getattr,write,add_name
	se_allow ${policy} su_daemon	app_data_file	file			getattr,read,open,lock

	#FIXME: This shouldn't exist
	#dac_override can be fixed by having pts_slave's fd forwarded over socket
	#Instead of forwarding the name
	se_allow ${policy} su_daemon	su_daemon		capability		dac_override,sys_admin
	se_allow ${policy} su_daemon	su_daemon		process			fork,sigchld

	#toolbox needed for log
	se_allow ${policy} su_daemon	toolbox_exec	file			execute,read,open,execute_no_trans

	#Create /dev/me.phh.superuser. Could be done by init
	se_allow ${policy} su_daemon	device			dir				write,add_name
	se_allow ${policy} su_daemon	su_device		dir				create,setattr,remove_name,add_name
	se_allow ${policy} su_daemon	su_device		sock_file		create,unlink

	#se_allow ${policy}  su daemon to start su apk
	se_allow ${policy} su_daemon	zygote_exec		file			execute,read,open,execute_no_trans
	se_allow ${policy} su_daemon	zygote_exec		lnk_file		read,getattr

	#Send request to APK
	se_allow ${policy} su_daemon	su_device		dir				search,write

	#se_allow ${policy}  su_daemon to switch to su or su_sensitive
	se_allow ${policy} su_daemon	su_daemon		process			setexec,setfscreate

	#se_allow ${policy}  su_daemon to execute a shell (every commands are supposed to go through a shell)
	se_allow ${policy} su_daemon	shell_exec		file			execute,read,open
	se_allow ${policy} su_daemon	su_daemon		capability		chown
	se_allow ${policy} su_daemon	su				process			transition,siginh,rlimitinh,noatsecure

	#Used for ViPER|Audio
	#This is L3 because mediaserver already has { allow mediaserver self:process execmem; } which is much more dangerous
	se_allow ${policy} mediaserver		mediaserver_tmpfs	file	execute

	se_allow ${policy} su_daemon	su_daemon	capability		sys_ptrace

	for source in adbd shell untrusted_app platform_app system_app su; do
		#All domain-s already have read access to rootfs
		se_allow ${policy} $source		rootfs		file			execute_no_trans,execute

		se_allow ${policy} $source		rootfs		dir				open,getattr,read,search,ioctl
		se_allow ${policy} $source		rootfs		file			getattr,open,read,ioctl,lock
		se_allow ${policy} $source		rootfs		lnk_file		read,getattr
		
		se_allow ${policy} $source		su_daemon	unix_stream_socket	connectto
		se_allow ${policy} $source		su_device	dir				search,read
		se_allow ${policy} $source		su_device	sock_file		read,write
		se_allow ${policy} su_daemon	$source		fd				use
		se_allow ${policy} su_daemon	$source		fifo_file		read,write,getattr,ioctl

		#Read /proc/callerpid/cmdline in from_init, drop?
		#Requiring sys_ptrace sucks
		se_allow ${policy} su_daemon	$source		dir				search
		se_allow ${policy} su_daemon	$source		file			read,open
		se_allow ${policy} su_daemon	$source		lnk_file		read

		#TODO: Split in for su/su_sensitive/su_cts
		se_allow ${policy} su			$source		fd				use
		se_allow ${policy} su			$source		fifo_file		read,write
	done

	se_allow ${policy} qti_init_shell	su_daemon	unix_stream_socket	connectto

	#This is the vital minimum for su to open a uid 0 shell
	#Communications with su_daemon
	se_allow ${policy} su			su_daemon		fd				use
	se_allow ${policy} su			su_daemon		process			sigchld
	se_allow ${policy} su			su_daemon	unix_stream_socket read,write

	se_allow ${policy} servicemanager	su			dir				read
	se_allow ${policy} servicemanager	su			binder			transfer

	#Enable the app to write to logs
	se_allow ${policy} su			su				dir				search,read
	se_allow ${policy} su			su				file			read
	se_allow ${policy} su			su				lnk_file		read
	se_allow ${policy} su			su			unix_dgram_socket	create,connect,write
	se_allow ${policy} su			toolbox_exec	file			entrypoint
	se_allow ${policy} su			devpts			chr_file		open

#	Controlled access to tmpfs
	se_add_type ${policy} su_tmpfs
	se_add_attr ${policy} su_tmpfs file_type
	se_trans    ${policy} su tmpfs file	su_tmpfs
	se_allow    ${policy} su su_tmpfs file write,read,execute

	se_allow ${policy} system_server	su			binder			call,transfer

	#ES Explorer opens a sokcet
	se_allow ${policy} untrusted_app	su		unix_stream_socket connectto,ioctl,setattr,lock,append,bind,connect,setopt

	se_allow ${policy} su	sysfs					dir				ioctl,read,lock,open
	se_allow ${policy} su	sysfs					file			ioctl,getattr,read,lock,open
	se_allow ${policy} su	sysfs					lnk_file		ioctl,getattr,lock,open
	se_allow ${policy} su	proc_net				file			getattr,read,open

	se_allow ${policy} su	qti_init_shell	fd				use

	se_allow ${policy} su			su				process			sigkill
	se_allow ${policy} su			proc			file			read,open,getattr

	for target in shell_exec zygote_exec dalvikcache_data_file rootfs system_file toolbox_exec; do
		se_allow ${policy} su ${target}				 file			entrypoint
	done

	for target in dalvikcache_data_file rootfs system_file; do
		se_allow ${policy} su ${target}				dir				open,read,ioctl,write,remove_name,add_name
	done

	se_allow ${policy} su	activity_service		service_manager	find
	se_allow ${policy} su	untrusted_app_devpts	chr_file		read,write,open,getattr,ioctl

	#Give full access to itself
	se_allow ${policy} su				su			file			append,write,getattr,open,ioctl,lock,execute,execute_no_trans
	se_allow ${policy} su				su		unix_stream_socket	create,ioctl,setattr,lock,append,bind,connect,setopt,listen,accept
	se_allow ${policy} su				su			process			sigchld,setpgid,setsched,fork,signal,execmem,getsched

	#Any domain is allowed to send su "sigchld"
	#TODO: Have sepolicy-inject handle that
	#allow "=domain" su process "sigchld"
	se_allow ${policy} surfaceflinger	su			process			sigchld

	#dmesg
	se_allow ${policy} su			kernel			system			syslog_read,syslog_mod
	se_allow ${policy} su			su				capability2		syslog

	#logcat
	se_allow ${policy} su			logd		unix_stream_socket	ioctl,read,getattr,write,setattr,lock,append,bind,connect,getopt,setopt,shutdown

	#Access to /data/local/tmp/
	se_allow ${policy} su		shell_data_file		dir				create,open,getattr,read,search,ioctl,write,add_name,remove_name
	se_allow ${policy} su		shell_data_file		file			append,open,read,ioctl,lock,create,setattr,unlink,rename,execute,execute_no_trans
	se_allow ${policy} su		shell_data_file		lnk_file		read,getattr

	se_allow ${policy} su		fuse				lnk_file		read,getattr
	se_allow ${policy} su		mnt_user_file		file			getattr,open,read,ioctl,lock


	#strace self
	se_allow ${policy} su		su				process			ptrace
	se_allow ${policy} su		su				netlink_route_socket	create,setopt,bind,getattr,write,nlmsg_read,read

	se_allow ${policy} su		net_data_file	dir				open,getattr,read,search,ioctl
	se_allow ${policy} su		net_data_file	file			getattr,open,read,ioctl,lock
	se_allow ${policy} su		net_data_file	lnk_file		read,getattr

	se_allow ${policy} su		app_data_file	dir				search,getattr
	se_allow ${policy} su		app_data_file	file			getattr,execute,read,open,execute_no_trans

	
	se_allow ${policy} su		su			unix_dgram_socket		create ioctl,read,getattr,write,setattr,lock,append,bind,connect,getopt,setopt,shutdown
	se_allow ${policy} su		su				rawip_socket		create ioctl,read,getattr,write,setattr,lock,append,bind,connect,getopt,setopt,shutdown
	se_allow ${policy} su		su				udp_socket			create ioctl,read,getattr,write,setattr,lock,append,bind,connect,getopt,setopt,shutdown
	se_allow ${policy} su		su				tcp_socket			create ioctl,read,getattr,write,setattr,lock,append,bind,connect,getopt,setopt,shutdown
	se_allow ${policy} su		su			netlink_route_socket	nlmsg_write

	[ $su_permissive -eq 1 ] && se_permissive ${policy} su
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

	local policy=$(find_file $RAMDISK/sepolicy)
	se_allow ${policy} init system_file file relabelto

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
	se_allow ${policy} dex2oat	apk_tmp_file	dir		 search
#	Avoid the LD_PRELOAD is removed on transition from installd to dex2oat
	se_allow ${policy} installd			dex2oat			process	 noatsecure
	se_allow ${policy} untrusted_app	dex2oat			process	 noatsecure
	
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

	local policy=$(find_file $RAMDISK/sepolicy)
	se_allow ${policy} init rootfs lnk_file rename
}

# Allow some additional DENYs which are spamming thelog
sepolicy_fixes()
{
	local policy=$(find_file $RAMDISK/sepolicy)
	local source

	se_allow ${policy} ipacm			ipacm-diag		unix_dgram_socket	sendto
	se_allow ${policy} system_server	logd			dir					search
	se_allow ${policy} system_server	logd			file 		  	 	read,open
	se_allow ${policy} vold				logd			dir					search
	se_allow ${policy} vold				logd			file 		  	 	read,open
	for source in rild qcomsysd cnd netmgrd ims cnd thermal-engine mm-pp-daemon time_daemon dpmd ipacm-diag audioserver location bluetooth system_server dataservice_app; do
		se_allow ${policy} $source		diag_device		chr_file			write,read,open,ioctl
	done
	se_allow ${policy} toolbox			unlabeled		dir					getattr,open,read,write
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
add_kcal_module
add_supersu
[ -z "$SUPER_INSTALLED" ] && add_superuser
add_xposed

[ "$VENDOR" == "somc" ] && add_drmfix

add_bb

add_additional
sepolicy_fixes

make_bootimg
cleanup

ui_print "Done"
