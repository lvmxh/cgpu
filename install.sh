#!/bin/bash
make

rm -f /usr/bin/nvidia-container-runtime-hook
cp ./cgpu-container-wrapper /usr/bin/nvidia-container-runtime-hook

cp cgpu_km.ko /lib/modules/$(uname -r)/kernel/virt/lib/cgpu_km.ko
cp cgpu.conf /etc/

if [ $? -ne 0 ]; then
    echo "error: cp cgpu_km.ko  to  /lib/modules/$(uname -r)/kernel/virt/lib/ fail!"
    exit -1
fi

depmod

if [ ! -c /dev/nvidia0  -o  ! -c  /dev/nvidiactl ]; then
    nvidia-smi > /dev/null
fi

if [ -c /dev/nvidiactl ]; then
    modprobe cgpu_km
fi

if ! lsmod | grep cgpu_km; then
    echo "error: cgpu_km not insmod"
    exit -1
fi

