obj-m := cgpu_km.o

cgpu_km-objs := os-interface.o
cgpu_km-objs += cgpu-procfs.o
cgpu_km-objs += cgpu.o
cgpu_km-objs += cgpu-km.o

all:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
		rm -f cgpu-km.o cgpu-procfs.o os-interface.o cgpu-km.o
