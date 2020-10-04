/*
 * Copyright © 2019-now Alibaba Cloud Inc. All rights reserved.
 *
 */


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>

#include <linux/cdev.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/memory.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/kthread.h>
#include <linux/version.h>
#include <asm/io.h>

extern int cgpu_km_mmap(struct file *filp, struct vm_area_struct *vma);
extern long cgpu_km_unlocked_ioctl(struct file *filp, unsigned int cmd,
		unsigned long arg);
extern long cgpu_km_compat_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
extern unsigned int cgpu_km_poll(struct file *filp, struct poll_table_struct *pts);
extern int cgpu_km_open(struct inode *inode, struct file *filp);
extern int cgpu_km_close(struct inode *inode, struct file *filp);
extern int cgpu_initialize(void);
extern void cgpu_finalize(void);
extern int cgpu_km_procfs_init(int);
extern int cgpu_km_procfs_deinit(void);

int cgpu_major = 0;

static struct file_operations cgpu_km_fops = {
	.owner     = THIS_MODULE,
	.poll      = cgpu_km_poll,
	.unlocked_ioctl = cgpu_km_unlocked_ioctl,
	.compat_ioctl = cgpu_km_compat_ioctl,
	.mmap      = cgpu_km_mmap,
	.open      = cgpu_km_open,
	.release   = cgpu_km_close,
};

static int __init cgpu_km_init(void)
{
	int ret = 0;
	int num = 0;

	num = cgpu_initialize();
	if(num < 0)
	{
		pr_err("failed to cgpu initialize %s \n", "cgpu-km");
		return num;
	}
	ret = register_chrdev(0, "cgpu-km", &cgpu_km_fops);
	if (ret <= 0) {
		pr_err("failed to register chrdev %s\n", "cgpu-km");
		return ret;
	}

	cgpu_major = ret;
	ret = cgpu_km_procfs_init(num);
	if (ret) {
		pr_err("failed to init cgpu km procfs\n");
		unregister_chrdev(cgpu_major, "cgpu-km");
	}

	return ret;
}

static void __exit cgpu_km_exit(void)
{
	cgpu_finalize();
	cgpu_km_procfs_deinit();
	unregister_chrdev(cgpu_major, "cgpu-km");
}

module_init(cgpu_km_init);
module_exit(cgpu_km_exit);
MODULE_LICENSE("ALI");
