#!/bin/bash


uninstall()
{
    rm -f /usr/bin/nvidia-container-runtime-hook

    ln -s /usr/bin/nvidia-container-toolkit /usr/bin/nvidia-container-runtime-hook

    if  lsmod | grep cgpu_km ;then
        rmmod  cgpu_km
        if [ $? -ne 0 ]; then
            echo "error: rmmod cgpu_km fail!"
            return 1
        else
            echo "rmmod cgpu_km OK"
        fi
    fi


    if [ -f "/lib/modules/$(uname -r)/kernel/virt/lib/cgpu_km.ko" ] ; then
        rm -f /lib/modules/$(uname -r)/kernel/virt/lib/cgpu_km.ko
    fi

    if [ -f "/lib/modules/$(uname -r)/extra/cgpu_km.ko" ] ; then
        rm -f /lib/modules/$(uname -r)/extra/cgpu_km.ko
    fi

    depmod

    return 0
}


install()
{
    make

    rm -f /usr/bin/nvidia-container-runtime-hook
    cp ./cgpu-container-wrapper /usr/bin/nvidia-container-runtime-hook

    cp cgpu_km.ko /lib/modules/$(uname -r)/kernel/virt/lib/cgpu_km.ko

    if [ $? -ne 0 ]; then
        echo "error: cp cgpu_km.ko  to  /lib/modules/$(uname -r)/kernel/virt/lib/ fail!"
        return 1
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
        return  1
    fi
    return 0
}



s=0
for i in `seq 8`
do
    if [ -d /proc/cgpu_km/$s ] ; then
       count=`ls -l /proc/cgpu_km/$s | grep "^d" | wc -l`
       if [ $count -ge 1 ] ; then
	    echo "docker is running, upgrade fail! "
	    exit 1;
       fi
    fi
    s=`expr $s + 1`;
done

uninstall
if [ $? -ne 0 ]; then
    echo "uninstall cgpu fail,can not upgrade cgpu!"
    exit 1
fi


install
if [ $? -ne 0 ]; then
    echo "install cgpu fail,can not upgrade cgpu!"
    exit 1
fi

exit 0

