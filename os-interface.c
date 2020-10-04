/*
 * Copyright © 2019-now Alibaba Cloud Inc. All rights reserved.
 *
*/

#include <linux/cdev.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/memory.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/kthread.h>
#include <linux/dmi.h>
#include <linux/version.h>
#include <asm/io.h>


#define CGPU_SCHED_PERIOD 1000   /*in us*/
#define CGPU_SCHED_PERIOD_JIFFIES usecs_to_jiffies(CGPU_SCHED_PERIOD)

enum fops_types {
	cgpu_poll,
	cgpu_unlocked_ioctl,
	cgpu_compat_ioctl,
	cgpu_mmap,
	cgpu_open,
	cgpu_release,
};

typedef struct {
	uint32_t domain;        /* PCI domain number   */
	uint8_t  bus;           /* PCI bus number      */
	uint8_t  slot;          /* PCI slot number     */
	uint8_t  function;      /* PCI function number */
	uint16_t vendor_id;     /* PCI vendor ID       */
	uint16_t device_id;     /* PCI device ID       */
	uint8_t  valid;         /* validation flag     */
} xxx_pci_info_t;

struct xxx_state {
	void  *priv;                    /* private data */
	void  *os_state;                /* os-specific device state */

	int    flags;

	/* PCI config info */
	xxx_pci_info_t pci_info;
};

struct xxx_priv {
	void *rsvd;
	void *rsvd1[3];
	struct semaphore rsvd_locks[3];
	void *rsvd2;
	struct xxx_state *fp;
};


typedef int (*CGPU_THREAD_FN)(void *data);


int os_printf( const char *printf_format, ...)
{
   va_list arglist;
   unsigned long chars_written;

   va_start(arglist, printf_format);
   chars_written = vprintk(printf_format, arglist);
   va_end(arglist);
   return chars_written;
}

int os_wait_event_interruptible_timeout(void *sched_wq)
{
   int ret;
   wait_queue_head_t *sched = (wait_queue_head_t*)sched_wq;
   ret = wait_event_interruptible_timeout(*sched,
                  kthread_should_stop(),
                  CGPU_SCHED_PERIOD_JIFFIES);
   return ret;
}

void *os_init_waitqueue_head(void)
{
    wait_queue_head_t *sched_wq = kmalloc(sizeof(wait_queue_head_t), GFP_KERNEL);

    if(sched_wq)
        init_waitqueue_head(sched_wq);
    return (void*)sched_wq;
}

void os_put_waitqueue_head(void *sched_wq)
{
    if(sched_wq)
        kfree(sched_wq);
}

bool os_kthread_should_stop(void)
{
  return kthread_should_stop();
}

void *os_kthread_run(CGPU_THREAD_FN sched_thread_fn, void *data, const char *name)
{

  return (void *)kthread_run((CGPU_THREAD_FN)sched_thread_fn, data, name);
}

void os_kthread_stop(void *sch)
{
   struct task_struct *sched_ts = (struct task_struct *)sch;
   if(sched_ts)
       kthread_stop(sched_ts);
}


//void os_pr_debug( const char str)
//{
//	pr_debug(&str);
//}

void os_pr_debug( const char *printf_format, ...)
{
#ifdef DEBUG
   va_list arglist;

   va_start(arglist, printf_format);
   vprintk(printf_format, arglist);
   va_end(arglist);
#endif
}

void * os_memcpy(void * dest, const void *src, unsigned long n)
{
    return memcpy(dest, src, n);
}

void os_memcpy_fromio(void *to, const volatile void *from, long count)
{
    memcpy_fromio(to, from, count);
}
void *os_memset(void *s, int c, size_t n)
{
    return memset(s, c, n);
}

void *get_spin_lock(void)
{
  spinlock_t * lock;
  lock = (spinlock_t *) kmalloc(sizeof(spinlock_t), GFP_KERNEL);
  return (void*) lock;
}

void put_spin_lock(void* lock)
{
    if(lock)
      kfree(lock);
}

void os_spin_lock_init(void *lock)
{
   spinlock_t *spinlock = (spinlock_t *) lock;
   spin_lock_init(spinlock);
}

void os_spin_lock(void *lock)
{
    spinlock_t *spinlock = (spinlock_t *) lock;
    spin_lock(spinlock);
}

void os_spin_unlock(void *lock)
{
    spinlock_t *spinlock = (spinlock_t *)lock;
    spin_unlock(spinlock);
}

unsigned long os_get_page_shift(void)
{
    return PAGE_SHIFT;
}

void *os_alloc_file_operations(void)
{
    return kmalloc( sizeof(struct vm_operations_struct), GFP_KERNEL);
}

void *os_kmalloc(int len)
{
    return kmalloc(len, GFP_KERNEL);
}

void *os_kmalloc_array(int len, int size)
{
    return kmalloc_array(len, size, GFP_KERNEL | __GFP_ZERO);

}

void os_kfree(const void *objp)
{
    kfree(objp);
}

void os_free_page(unsigned long addr)
{
     free_page(addr);
}

unsigned long os_copy_from_user(void *to, const void *from, unsigned long n)
{
    unsigned long ret;
    const void __user *osfrom = from;
    ret = copy_from_user(to, osfrom, n);
    return ret;
}

unsigned long os_copy_to_user(void *to, const void *from, unsigned long n)
{
    unsigned long ret;
    void __user *osto = to;
    ret = copy_to_user(osto, from, n);
    return ret;
}

struct file *os_filp_open(const char *filename, int flags, unsigned short  mode)
{

    struct file *os_filp = NULL;
    os_filp = filp_open(filename, flags, mode);

    if (IS_ERR_OR_NULL(os_filp)){
	return NULL;
    }

    return os_filp;
}

unsigned long  os_filp_ops_read(struct file *fi, char* buf, unsigned long size)
{
    unsigned long  ret = 0;
    mm_segment_t old_fs=get_fs();
    set_fs(get_ds());
    ret = fi->f_op->read(fi, buf, size, &fi->f_pos);
    set_fs(old_fs);
    return ret;
}

int os_filp_close(struct file *fi, void *id)
{
    struct file *filp = (struct file *)fi;
    int ret = 0; 
    if(filp)
        ret = filp_close(filp, id);
    return ret;
}

void *os_file_inode(void *fi)
{
    struct file *f = (struct file *)fi;
    return (void *) f->f_inode;
}


void *os_file_op(void *fi)
{
    struct file *f = (struct file *)fi;
    return (void *) f->f_op;
}

const char * os_get_system_info(int field)
{
    return dmi_get_system_info(field);
}

unsigned long os_virt_to_phys(void *addr)
{
    return virt_to_phys(addr);
}

int os_follow_pfn(void *vmadd, unsigned long *pfn)
{
   struct vm_area_struct *vma = (struct vm_area_struct *)vmadd;
   return follow_pfn(vma, vma->vm_start, pfn);
}

void* os_ioremap_nocache (unsigned long phys_addr)
{
    return  ioremap_nocache(phys_addr, PAGE_SIZE);
}

void* os_ioremap_cache (unsigned long phys_addr, unsigned long size)
{
    return  ioremap_cache(phys_addr, size);
}

void os_iounmap(void *addr)
{
    void __iomem *mmio_base = (void __iomem *)addr;
    if(mmio_base)
        iounmap(mmio_base);
}

void os_writel( unsigned int val, void *addr, int offset)
{
    void __iomem *mmio_base = (void __iomem *)addr;
    writel(val, mmio_base + offset);
}

unsigned long os_get_zeroed_page(void)
{
    return get_zeroed_page(GFP_KERNEL);
}

/* to return the "real" inode associated with file pointer */
void *os_get_inode(void *filp)
{
    struct file * fi = (struct file *)filp;
    return (void*) fi->f_path.dentry->d_inode;
}

void *os_get_priv(void *f)
{
    struct file * fi = (struct file *)f;
    return (void*) fi->private_data;
}

unsigned int get_rdev(void *inode)
{
    struct inode * nv_inode = (struct inode *) inode;
    return nv_inode->i_rdev;
}

unsigned int os_minor(unsigned rdev)
{
	return MINOR(rdev);
}

unsigned int os_get_minor(void *f)
{
    struct file *filp = (struct file *)f;
    struct inode *inode = filp->f_path.dentry->d_inode;

    return MINOR(inode->i_rdev);
}

int os_unmap_range(void *priv)
{
	struct address_space *mapping;
	struct vm_area_struct *vma = (struct vm_area_struct *)priv;

	if (!vma || !vma->vm_file)
		return -EINVAL;

	mapping = vma->vm_file->f_mapping;
	if (!mapping)
		return -EINVAL;

	unmap_mapping_range(mapping, vma->vm_start, PAGE_SIZE, 1);
	return 0;
}

int os_vm_insert_pfn(void *priv, unsigned long pfn)
{
	int ret = 0;
	struct vm_area_struct *vma = (struct vm_area_struct *)priv;
	struct mm_struct *mm;

	if (!vma)
		return -EINVAL;

	mm = vma->vm_mm;
	if (!atomic_read(&mm->mm_users))
		return 0;

	ret = vm_insert_pfn(vma, vma->vm_start, pfn);
//#ifdef DEBUG
	ret = follow_pfn(vma, vma->vm_start, &pfn);
	pr_debug("%s new pfn %lx\n", __func__, pfn);
//#endif
	vma->vm_flags |= VM_IO | VM_PFNMAP;
	return ret;
}

void *os_cdev_get(void *priv)
{
	struct inode *inode = (struct inode *)priv;
	struct cdev *p;
	struct module *owner;
	struct kobject *kobj;

	if (!priv)
		return NULL;

	p = inode->i_cdev;
	if (!p)
		return NULL;

	owner = p->owner;
	if (owner && !try_module_get(owner))
		return NULL;
	kobj = kobject_get(&p->kobj);
	if (!kobj)
		module_put(owner);

	return kobj;
}

void os_cdev_put(void *priv)
{
	struct inode *inode = (struct inode *)priv;
	struct cdev *p;

	if (!priv)
		return;

	p = inode->i_cdev;
	if (p) {
		struct module *owner = p->owner;
		kobject_put(&p->kobj);
		module_put(owner);
	}
}

int os_in_vma_range(void *v, uint64_t virt_addr)
{
	struct vm_area_struct *vma = (struct vm_area_struct *)v;

	return ((vma->vm_start <= virt_addr)
			&& (vma->vm_end > virt_addr));
}

void *os_get_fops(void *f, int type)
{
	struct file_operations *fops = (struct file_operations *)f;
	void *func = NULL;

	if (!f)
		return NULL;

	switch (type) {
	case cgpu_poll:
		func = fops->poll;
		break;
	case cgpu_unlocked_ioctl:
		func = fops->unlocked_ioctl;
		break;
	case cgpu_compat_ioctl:
		func = fops->compat_ioctl;
		break;
	case cgpu_mmap:
		func = fops->mmap;
		break;
	case cgpu_open:
		func = fops->open;
		break;
	case cgpu_release:
		func = fops->release;
		break;
	default:
		break;
	}

	return func;
}

void os_set_filp(void *f, void *i)
{
	struct file *filp = (struct file *)f;
	struct inode *inode = (struct inode *)i;

	filp->f_inode = inode;
	filp->f_mapping = inode->i_mapping;
}

extern int inst_vma_fault(void *vma);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
int cgpu_vma_fault(struct vm_fault *vmf)
#else
int cgpu_vma_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
#endif
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
	struct vm_area_struct *vma = vmf->vma;
#endif

	return inst_vma_fault(vma);
}

void *cgpu_km_vma_fault = cgpu_vma_fault;

uint16_t os_get_device_id(void *f)
{
	struct file *filp = (struct file*)f;
	struct xxx_priv *priv = (struct xxx_priv *)filp->private_data;
	uint16_t device_id = 0;

	if (priv->fp) {
		struct xxx_state *state = (struct xxx_state *)priv->fp;

		device_id = state->pci_info.device_id;
	}

	return device_id;
}

void *os_vma_ops(void *vmo, void *vm, void *fault, void *close)
{
	struct vm_area_struct *vma = (struct vm_area_struct *)vm;
	void *ret = vma->vm_ops->close;
	struct vm_operations_struct *ops = (struct vm_operations_struct *)vmo;

	memcpy(ops, vma->vm_ops, sizeof(struct vm_operations_struct));
	ops->fault = fault;
	ops->close = close;
	vma->vm_ops = ops;
	return ret;
}

int os_get_tgid(void)
{
	return current->tgid;
}

void *os_get_vm_file(void *vm)
{
	struct vm_area_struct *vma = (struct vm_area_struct *)vm;
	return vma->vm_file;
}

void os_set_pgoff(void *vm)
{
	struct vm_area_struct *vma = (struct vm_area_struct *)vm;

	if (!vma->vm_pgoff)
		vma->vm_pgoff = vma->vm_start >> PAGE_SHIFT;
}

void os_ireadcount_dec(void *i)
{
        struct inode *inode = (struct inode *)i;
        i_readcount_dec(inode);
}

void os_ireadcount_inc(void *i)
{
        struct inode *inode = (struct inode *)i;
        i_readcount_inc(inode);
}
