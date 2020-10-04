1. 安装与卸载。
a. 依赖：本产品依赖于nVidia docker，请先安装nvidia docker的相关组件
b. 安装：请运行./install.sh来安装cGPU的所有组件。
c. 卸载：请通过运行./uninstall.sh来卸载所有程序。

2. 运行。
a. 环境变量，cGPU组件会检测以下docker的环境变量，进行相应操作：
- ALIYUN_COM_GPU_MEM_DEV：为正整数，表示为host上每张卡的总显存大小。
- ALIYUN_COM_GPU_MEM_CONTAINER： 为正整数，指定容器内可见的显存容量。此参数同ALIYUN_COM_GPU_MEM_DEV一起设定cGPU内可见的显存大小。如在一张4G显存的显卡上，我们可以通过-e ALIYUN_COM_GPU_MEM_DEV=4 -e ALIYUN_COM_GPU_MEM_CONTAINER=1的参数为容器分配1G显存。如果不指定此参数，则cGPU不会启动，此时会默认使用nvidia容器。
- ALIYUN_COM_GPU_VISIBLE_DEVICES：为正整数或uuid，指定容器内可见的GPU设备。如在一个有4张显卡的机器上，我们可以通过-e ALIYUN_COM_GPU_VISIBLE_DEVICES=0,1来为容器分配第一和第二张显卡。或是-e ALIYUN_COM_GPU_VISIBLE_DEVICES=uuid1,uuid2,uuid3为容器分配uuid为uuid1，uuid2，uuid3z的3张显卡。
- CGPU_DISABLE：总开关，用于禁用cGPU。可以接受的参数是-e CGPU_DISABLE=true或-e CGPU_DISABLE=1，此时cGPU将会被禁用，默认使用nvidia容器。
- 混布：在多卡情况下，可以通过设定不同的ALIYUN_COM_GPU_VISIBLE_DEVICES和NVIDIA_VISIBLE_DEVICES变量来达到cGPU实例与nvidia容器实例混布的效果。例如在一张4卡的机器上，采用-e ALIYUN_COM_GPU_VISIBLE_DEVICES=2 -e NVIDIA_VISIBLE_DEVICES device=0,1,2的参数，容器内就会看到原生的nvidia GPU实例0和实例1，以及显卡2的cGPU实例。此时容器内只有显卡2会被cGPU进行分片化处理。

b. procfs节点。cGPU组件会系统的/proc/cgpu_km下生成多个节点，cGPU的组件会自动处理这些节点，普通用户不需要访问这些节点，这里仅就其做个基本描述。
- default_memsize： 读/写。默认的cGPU实例显存大小，为正整数。
- inst_ctl：读/写。 实例的控制节点。
- major：只读。cGPU内核驱动的主设备号。
- 0...N: 目录，针对宿主机上每个GPU设备，都会生成一个对应id的目录，其内容如下：
-- max_inst：读/写。用于设定最大的cGPU实例数，范围为1~16。
-- policy：读/写。用于对此GPU上的实例设定不同的调度策略：00 表示每个cGPU实例占用固定的时间片，时间片占比为1/max_inst； 1 表示每个cGPU实例可以占用尽量多的时间片，时间片比例为1/当前实例数。
-- 容器实例目录： 针对此GPU上运行的每个cGPU容器实例，都会有个对应的目录，目录名为容器名，可以通过docker ps命令来查看。每个实例目录下有3个节点：
--- id： 只读。cGPU的实例号。
--- memsize：读写。用于设定cGPU容器实例内的显存大小。cGPU用户组件会根据ALIYUN_COM_GPU_MEM_DEV参数自动设定此值。
--- meminfo：只读。容器内显存用量信息。输出如下所示，表示容器内剩余显存容量以及当前正在使用GPU的进程id及其显存用量。
        Free: 6730809344
        PID: 19772 Mem: 200278016
