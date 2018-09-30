#!/bin/bash
#
JOBS=`grep -c processor /proc/cpuinfo`
let JOBS=${JOBS}*2
JOBS="-j${JOBS}"
RELEASE_DATE=`date +%Y%m%d`
COMMIT_ID=`git log --pretty=format:'%h' -n 1`
ARM=arm
BOOT_PATH="arch/${ARM}/boot"
IMAGE="zImage"
DZIMAGE="dzImage"
MODEL=${1}
CARRIER=${2}
REGION=${3}
OPERATOR=${4}
TIZEN_MODEL=tizen_${MODEL}

export CROSS_COMPILE="/opt/toolchains/tizen2.4_cross_toolchain_for_32bit_host/bin/armv7l-tizen-linux-gnueabi-"


if [ "${MODEL}" = "" ]; then
	echo "Warnning: failed to get machine id."
	echo "ex)./release.sh model_name region_name"
	echo "ex)--------------------------------------------------"
	echo "ex)./release.sh	j1minilte"
	echo "ex)./release.sh	z2 lte"
	echo "ex)./release.sh	z2 lte mea"
	exit
fi

if [ "${CARRIER}" != "" ]; then
	VARIANT="${CARRIER}"
	if [ "${REGION}" != "" ]; then
		VARIANT="${VARIANT}_${REGION}"
		if [ "${OPERATOR}" != "" ]; then
			VARIANT="${VARIANT}_${OPERATOR}"

		fi
	fi
else
	if [ "${REGION}" != "" ]; then
		MODEL="${TIZEN_MODEL}_${REGION}"
	fi
fi

if [ "${VARIANT}" = "" ]; then
	make ARCH=${ARM} ${TIZEN_MODEL}_defconfig
else
	make ARCH=${ARM} ${TIZEN_MODEL}_defconfig VARIANT_DEFCONFIG=${TIZEN_MODEL}_${VARIANT}_defconfig
fi

if [ "$?" != "0" ]; then
	echo "Failed to make defconfig :"$ARCH
	exit 1
fi

make ${JOBS} ARCH=${ARM} ${IMAGE}
if [ "$?" != "0" ]; then
	echo "Failed to make "${IMAGE}
	exit 1
fi

DTC_PATH="scripts/dtc/"

rm ${BOOT_PATH}/dts/*.dtb -f

make ARCH=${ARM} dtbs
if [ "$?" != "0" ]; then
	echo "Failed to make dtbs"
	exit 1
fi

dtbtool -o ${BOOT_PATH}/merged-dtb -p ${DTC_PATH} -v ${BOOT_PATH}/dts/
if [ "$?" != "0" ]; then
	echo "Failed to make merged-dtb"
	exit 1
fi

mkdzimage -o ${BOOT_PATH}/${DZIMAGE} -k ${BOOT_PATH}/${IMAGE} -d ${BOOT_PATH}/merged-dtb
if [ "$?" != "0" ]; then
	echo "Failed to make mkdzImage"
	exit 1
fi

sudo ls > /dev/null
./scripts/mkmodimg.sh

if [ "${VARIANT}" != "" ]; then
	RELEASE_IMAGE=System_${TIZEN_MODEL}_${VARIANT}_${RELEASE_DATE}-${COMMIT_ID}.tar
else
	RELEASE_IMAGE=System_${TIZEN_MODEL}_${RELEASE_DATE}-${COMMIT_ID}.tar
fi

tar cf ${RELEASE_IMAGE} -C ${BOOT_PATH} ${DZIMAGE}
if [ "$?" != "0" ]; then
	echo "Failed to tar ${DZIMAGE}"
	exit 1
fi

tar rf ${RELEASE_IMAGE} -C usr/tmp-mod modules.img
if [ "$?" != "0" ]; then
	echo "Failed to tar modules.img"
	exit 1
fi

echo ${RELEASE_IMAGE}
