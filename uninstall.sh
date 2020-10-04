#!/bin/bash
#make

rm -f /usr/bin/nvidia-container-runtime-hook

ln -s /usr/bin/nvidia-container-toolkit /usr/bin/nvidia-container-runtime-hook

rmmod  cgpu_km

if [ -f "/lib/modules/$(uname -r)/kernel/virt/lib/cgpu_km.ko" ] ; then
    rm -f /lib/modules/$(uname -r)/kernel/virt/lib/cgpu_km.ko
fi

if [ -f "/lib/modules/$(uname -r)/extra/cgpu_km.ko" ] ; then
    rm -f /lib/modules/$(uname -r)/extra/cgpu_km.ko
fi

if [ -f "/etc/cgpu.conf" ] ; then
    rm -f /etc/cgpu.conf
fi

depmod

