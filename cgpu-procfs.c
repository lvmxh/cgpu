/*
 *  Copyright © 2019-now Alibaba Cloud Inc. All rights reserved.
 * 
 */

#include <linux/proc_fs.h>
#include <linux/vmalloc.h>
#include <linux/memory.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/seq_file.h>
#include "version.h"

#define IOCTL_BUF_SIZE   256
#define CGPU_IOCTL_A        _IOC(_IOC_READ|_IOC_WRITE,'C', 1, IOCTL_BUF_SIZE)
#define CGPU_IOCTL_B        _IOC(_IOC_READ|_IOC_WRITE,'C', 2, IOCTL_BUF_SIZE)

#define PROCFS_ROOT_DIR "cgpu_km"
#define PROCFS_INST_CTL_NODE "inst_ctl"
#define PROCFS_POLICY_NODE "policy"
#define PROCFS_MAX_INST_NODE "max_inst"
#define PROCFS_FREE_WEIGHT_NODE "free_weight"
#define NODE_NAME_LEN 12
#define PROCFS_DEF_MEMSIZE_NODE "default_memsize"
#define PROCFS_MAJOR_NODE "major"

#define MAX_GROUP_NUM 8

struct cgpu_meminfo_entry {
	int pid;
	uint64_t mem_size;
};

struct cgpu_meminfo {
	unsigned int num;
	uint64_t free_size;
	struct cgpu_meminfo_entry entries[0];
};

static struct proc_dir_entry *proc_root;
static struct proc_dir_entry *proc_insts[MAX_GROUP_NUM];
static struct proc_dir_entry *node_inst_ctl;
static struct proc_dir_entry *node_default_memsize;
static struct proc_dir_entry *node_major;
static struct proc_dir_entry *node_version;
static int group_num;

extern int inst_get_minor(void *priv);
extern uint64_t inst_get_total_mem(void *priv);
extern int inst_set_total_mem(void *priv, uint64_t total_mem);
extern void *inst_get_node(char *name, int i);
extern void inst_set_name(void *priv, char *buf);
extern int group_get_policy(int idx);
extern void group_set_policy(int idx, int policy);
extern int group_get_max_inst(int idx);
extern int group_set_max_inst(int idx, int policy);
extern struct cgpu_meminfo *inst_get_meminfo(void *priv);
extern int inst_get_free_weight(int idx);
extern int inst_set_weight(void *priv, int weight);
extern int inst_get_weight(void *priv);
extern int cgpu_ioctl(int code, void *argi, void *argo, void *data);
extern int cgpu_major;


static int read_version(struct seq_file *seqf, void *data)
{

        seq_printf(seqf, "%d.%d.%d\n", CGPU_MAJOR_VERSION,  CGPU_MINOR_VERSION,
	            CGPU_BUILD_VERSION);
        return 0;
}

static int cgpu_version_node_open(struct inode *inode, struct file *filp)
{
	void *data = PDE_DATA(inode);
        return single_open(filp, read_version, data);
}

static const struct file_operations cgpu_version_node_fops= {
        .owner          = THIS_MODULE,
        .open           = cgpu_version_node_open,
        .read           = seq_read,
        .llseek         = seq_lseek,
        .release        = single_release,
};


static int read_id_node(struct seq_file *seqf, void *data)
{
	int minor = inst_get_minor(seqf->private);

	seq_printf(seqf, "%d\n", minor);
	return 0;
}

static int cgpu_id_node_open(struct inode *inode, struct file *filp)
{
	void *data = PDE_DATA(inode);

	if (!data) {
		pr_err("cannot get data from inode %p\n", inode);
		return -EINVAL;
	}

	return single_open(filp, read_id_node, data);
}

static const struct file_operations cgpu_id_node_fops= {
	.owner          = THIS_MODULE,
	.open           = cgpu_id_node_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = single_release,
};

static int read_meminfo_node(struct seq_file *seqf, void *data)
{
	struct cgpu_meminfo *info = inst_get_meminfo(seqf->private);
	struct cgpu_meminfo_entry *entry;
	int i;

	if (!info)
		return -EFAULT;

	seq_printf(seqf, "Free: %lld\n", info->free_size);
	for (i = 0; i < info->num; i++) {
		entry = &info->entries[i];
		seq_printf(seqf, "PID: %d Mem: %lld\n", entry->pid,
				entry->mem_size);
	}

	kfree(info);
	return 0;
}

static int cgpu_meminfo_node_open(struct inode *inode, struct file *filp)
{
	void *data = PDE_DATA(inode);

	if (!data) {
		pr_err("cannot get data from inode %p\n", inode);
		return -EINVAL;
	}

	return single_open(filp, read_meminfo_node, data);
}

static const struct file_operations cgpu_meminfo_node_fops= {
	.owner          = THIS_MODULE,
	.open           = cgpu_meminfo_node_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = single_release,
};

static int read_memsize_node(struct seq_file *seqf, void *data)
{
	uint64_t total_mem = inst_get_total_mem(seqf->private);

	seq_printf(seqf, "%lld\n", total_mem);
	return 0;
}

static int cgpu_memsize_node_open(struct inode *inode, struct file *filp)
{
	void *data = PDE_DATA(inode);

	if (!data) {
		pr_err("cannot get data from inode %p\n", inode);
		return -EINVAL;
	}

	return single_open(filp, read_memsize_node, data);
}


static ssize_t cgpu_memsize_node_write(struct file *filp,
		const char __user *buf, size_t count, loff_t *ppos)
{
	void *priv;
	char tmp[16];
	int ret;
	uint64_t size;

	if (!filp || !file_inode(filp) || !buf)
		return -EINVAL;

	priv = PDE_DATA(file_inode(filp));
	if (!priv)
		return -EINVAL;

	if (count > 15) {
		pr_err("invalid buff size %ld\n", count);
		return -EINVAL;
	}

	ret = copy_from_user(tmp, buf, count);
	if (ret) {
		pr_err("failed to copy from user %d\n", ret);
		return ret;
	}

	tmp[count] = '\0';
	ret = sscanf(tmp, "%lld\n", &size);
	if (ret != 1) {
		pr_err("failed to parse string %s\n", tmp);
		return -EINVAL;
	}
	ret = inst_set_total_mem(priv, size);
	return count;
}

static const struct file_operations cgpu_memsize_node_fops= {
	.owner          = THIS_MODULE,
	.open           = cgpu_memsize_node_open,
	.read           = seq_read,
	.write          = cgpu_memsize_node_write,
	.llseek         = seq_lseek,
	.release        = single_release,
};

static int read_weight_node(struct seq_file *seqf, void *data)
{
	int  weight = inst_get_weight(seqf->private);

	seq_printf(seqf, "%d\n", weight);
	return 0;
}


static int cgpu_weight_node_open(struct inode *inode, struct file *filp)
{
	void *data = PDE_DATA(inode);

	if (!data) {
		pr_err("cannot get data from inode %p\n", inode);
		return -EINVAL;
	}
	return single_open(filp, read_weight_node, data);
}


static ssize_t cgpu_weight_node_write(struct file *filp,
        const char __user *buf, size_t count, loff_t *ppos)
{
	void *priv;
	char tmp[4];
	int ret;
	int weight;

	if (!filp || !file_inode(filp) || !buf)
		return -EINVAL;

	priv = PDE_DATA(file_inode(filp));
	if (!priv)
		return -EINVAL;

	if (count > 3) {
		pr_err("invalid buff weight %ld\n", count);
		return -EINVAL;
	}

	ret = copy_from_user(tmp, buf, count);
	if (ret) {
		pr_err("failed to copy from user %d\n", ret);
		return ret;
	}

	tmp[count] = '\0';
	ret = sscanf(tmp, "%d\n", &weight);
	if (ret != 1) {
		pr_err("failed to parse string %s\n", tmp);
		return -EINVAL;
	}

	ret = inst_set_weight(priv, weight);
	if (ret) {
		pr_err("failed to set weight \n");
	}
	return count;
}

static const struct file_operations cgpu_weight_node_fops= {
	.owner          = THIS_MODULE,
	.open           = cgpu_weight_node_open,
	.read           = seq_read,
	.write          = cgpu_weight_node_write,
	.llseek         = seq_lseek,
	.release        = single_release,
};


static int read_freeweight_node(struct seq_file *seqf, void *data)
{
	int free_weight;
	unsigned long idx  = (unsigned long)seqf->private;

	free_weight = inst_get_free_weight(idx);
	seq_printf(seqf, "%d\n", free_weight);
	return 0;
}

static int cgpu_freeweight_node_open(struct inode *inode, struct file *filp)
{
	void *data = PDE_DATA(inode);

	return single_open(filp, read_freeweight_node, data);
}

static const struct file_operations cgpu_freeweight_node_fops= {
	.owner          = THIS_MODULE,
	.open           = cgpu_freeweight_node_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = single_release,
};

int create_new_node(char *name, int i)
{
	int ret = 0;
	char *tmp;
	struct proc_dir_entry *inst_root, *inst;
	void *priv;

	if (i < 0 || i >= group_num) {
		pr_err("invalid new node num %d\n", i);
		return -EINVAL;
	}

	if (!name || !proc_insts[i]) {
		pr_err("create new node null ptr\n");
		return -EINVAL;
	}

	priv = inst_get_node(NULL, i);

	if (!priv) {
		pr_err("no instance available \n");
		return -ENOSPC;
	}

	tmp = kmalloc(NODE_NAME_LEN + 1, GFP_KERNEL);
	if (!tmp) {
		pr_err("faild to allocate node name %d\n", NODE_NAME_LEN);
		return -ENOMEM;
	}

	strcpy(tmp, name);
	tmp[NODE_NAME_LEN] = '\0';
	inst_set_name(priv, tmp);
	inst_root = proc_mkdir(tmp, proc_insts[i]);
	if (!inst_root) {
		pr_err("failed to create node %s\n", tmp);
		goto err_free;
	}

	inst = proc_create_data("id", 0444, inst_root,
		&cgpu_id_node_fops, priv);
	if (!inst) {
		pr_err("failed to create node \"id\"\n");
		goto err_procfs;
	}

	inst = proc_create_data("meminfo", 0444, inst_root,
		&cgpu_meminfo_node_fops, priv);
	if (!inst) {
		pr_err("failed to create node \"meminfo\"\n");
		goto err_procfs;
	}

	inst = proc_create_data("memsize", 0666, inst_root,
		&cgpu_memsize_node_fops, priv);
	if (!inst) {
		pr_err("failed to create node \"memsize\"\n");
		goto err_procfs;
	}

    inst = proc_create_data("weight", 0666, inst_root,
         &cgpu_weight_node_fops, priv);
    if (!inst) {
         pr_err("failed to create node \"weight\"\n");
         goto err_procfs;
    }

	pr_info("create cgpu id %d\n", inst_get_minor(priv));

	return 0;

err_procfs:
	proc_remove(inst_root);
err_free:
	inst_set_name(priv, NULL);

	return ret;
}

int destroy_node(char *name)
{
	int ret = 0;
	void *priv;
	int i = 0;

	if (!name) {
		pr_err("create new node null ptr\n");
		return -EINVAL;
	}

	for (i = 0; i < group_num; i++) {
		priv = inst_get_node(name, i);
		if (!priv) {
			continue;
		}

		inst_set_name(priv, NULL);
		inst_set_weight(priv, 0);
		ret = remove_proc_subtree(name, proc_insts[i]);
	}
	return ret;
}


static ssize_t cgpu_inst_ctl_read(struct file *filp, char __user *buf,
                            size_t count, loff_t *ppos)
{
	return -EBADF;
}

static ssize_t cgpu_inst_ctl_write(struct file *filp, const char __user *buf,
		size_t count, loff_t *ppos)
{
	char *node_name;
	int ret = 0;

	if (!buf || (count != NODE_NAME_LEN + 1)) {
		pr_err("invalid input buf %p count %ld\n", buf, count);
		return -EINVAL;
	}

	node_name = kmalloc(count + 1, GFP_KERNEL);
	if (!node_name) {
		pr_err("failed to allocate buf len %ld\n", count);
		return -ENOMEM;
	}

	ret = copy_from_user(node_name, buf, count);
	if (ret) {
		pr_err("failed to copy data %d \n", ret);
		goto out_free;
	}

	node_name[count] = '\0';
	if (node_name[0] == '-') {
		ret = destroy_node(node_name + 1);
		if (ret) {
			pr_err("failed to destroy node %s\n", node_name + 1);
			goto out_free;
		}
	} else {
		int i = node_name[0] - '0';

		ret = create_new_node(node_name + 1, i);
		if (ret) {
			pr_err("failed to create new node %s\n", node_name);
			goto out_free;
		}
	}

	ret = count;
out_free:
	kfree(node_name);
	return ret;
}

static long cgpu_inst_ctl_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	void *argp = (void *)arg;
	void *argi, *argo;
	size_t size = 0;
	int code, ret = 0;

	if (!filp)
		return -EINVAL;

	size = _IOC_SIZE(cmd);
	code = _IOC_NR(cmd);
	if (size != IOCTL_BUF_SIZE)
		return -EINVAL;

	argi = kmalloc(size, GFP_KERNEL);
	if (!argi)
		return -ENOMEM;
	argo = kmalloc(size, GFP_KERNEL);
	if (!argo)
		return -ENOMEM;

	ret = copy_from_user(argi, argp, size);
	if (ret)
		goto out;

	ret = cgpu_ioctl(code, argi, argo, &filp->private_data);
	if (!ret)
		ret = copy_to_user(argp, argo, size);

out:
	kfree(argo);
	kfree(argi);
	return ret;
}

static const struct file_operations cgpu_inst_ctl_fops= {
	.owner          = THIS_MODULE,
	.open           = nonseekable_open,
	.read           = cgpu_inst_ctl_read,
	.write          = cgpu_inst_ctl_write,
	.unlocked_ioctl = cgpu_inst_ctl_ioctl,
	.llseek         = no_llseek,
};

static int read_default_ms_node(struct seq_file *seqf, void *data)
{
	uint64_t total_mem = inst_get_total_mem(NULL);

	seq_printf(seqf, "%lld\n", total_mem);
	return 0;
}

static int cgpu_default_ms_node_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, read_default_ms_node, NULL);
}


static ssize_t cgpu_default_ms_node_write(struct file *filp,
		const char __user *buf, size_t count, loff_t *ppos)
{
	char tmp[16];
	int ret;
	uint64_t size;

	if (!filp || !buf)
		return -EINVAL;

	if (count > 15) {
		pr_err("invalid buff size %ld\n", count);
		return -EINVAL;
	}

	ret = copy_from_user(tmp, buf, count);
	if (ret) {
		pr_err("failed to copy from user %d\n", ret);
		return ret;
	}

	tmp[count] = '\0';
	ret = sscanf(tmp, "%lld\n", &size);
	if (ret != 1) {
		pr_err("failed to parse string %s\n", tmp);
		return -EINVAL;
	}
	ret = inst_set_total_mem(NULL, size);
	return count;
}

static const struct file_operations cgpu_default_ms_node_fops= {
	.owner          = THIS_MODULE,
	.open           = cgpu_default_ms_node_open,
	.read           = seq_read,
	.write          = cgpu_default_ms_node_write,
	.llseek         = seq_lseek,
	.release        = single_release,
};

static int read_major_node(struct seq_file *seqf, void *data)
{
	seq_printf(seqf, "%d\n", cgpu_major);
	return 0;
}

static int cgpu_major_node_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, read_major_node, NULL);
}

static const struct file_operations cgpu_major_node_fops= {
	.owner          = THIS_MODULE,
	.open           = cgpu_major_node_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = single_release,
};

static int read_policy_node(struct seq_file *seqf, void *data)
{
	unsigned long idx;
	int policy;

	idx  = (unsigned long)seqf->private;
	policy = group_get_policy(idx);
	seq_printf(seqf, "%d\n", policy);
	return 0;
}

static int cgpu_policy_node_open(struct inode *inode, struct file *filp)
{
	void *data = PDE_DATA(inode);
	return single_open(filp, read_policy_node, data);
}


static ssize_t cgpu_policy_node_write(struct file *filp,
		const char __user *buf, size_t count, loff_t *ppos)
{
	char tmp[3];
	int ret;
	unsigned long policy, idx;

        if (!filp || !file_inode(filp) || !buf)
                return -EINVAL;

        idx = (unsigned long)PDE_DATA(file_inode(filp));
        if (idx >= MAX_GROUP_NUM)
                return -EINVAL;

	if (count > 2) {
		pr_err("invalid buff size %ld\n", count);
		return -EINVAL;
	}

	ret = copy_from_user(tmp, buf, count);
	if (ret) {
		pr_err("failed to copy from user %d\n", ret);
		return ret;
	}

	tmp[count] = '\0';
	ret = sscanf(tmp, "%ld\n", &policy);
	if (ret != 1) {
		pr_err("failed to parse string %s\n", tmp);
		return -EINVAL;
	}
	group_set_policy(idx, policy);

	return count;
}

static const struct file_operations cgpu_policy_node_fops= {
	.owner          = THIS_MODULE,
	.open           = cgpu_policy_node_open,
	.read           = seq_read,
	.write          = cgpu_policy_node_write,
	.llseek         = seq_lseek,
	.release        = single_release,
};

static int read_max_inst_node(struct seq_file *seqf, void *data)
{
	unsigned long idx;
	int max_inst;

	idx  = (unsigned long)seqf->private;
	max_inst = group_get_max_inst(idx);
	seq_printf(seqf, "%d\n", max_inst);
	return 0;
}

static int cgpu_max_inst_node_open(struct inode *inode, struct file *filp)
{
	void *data = PDE_DATA(inode);
	return single_open(filp, read_max_inst_node, data);
}


static ssize_t cgpu_max_inst_node_write(struct file *filp,
		const char __user *buf, size_t count, loff_t *ppos)
{
	char tmp[4];
	int ret;
	unsigned long max_inst, idx;

        if (!filp || !file_inode(filp) || !buf)
                return -EINVAL;

        idx = (unsigned long)PDE_DATA(file_inode(filp));
        if (idx >= MAX_GROUP_NUM)
                return -EINVAL;

	if (count > 3) {
		pr_err("invalid buff size %ld\n", count);
		return -EINVAL;
	}

	ret = copy_from_user(tmp, buf, count);
	if (ret) {
		pr_err("failed to copy from user %d\n", ret);
		return ret;
	}

	tmp[count] = '\0';
	ret = sscanf(tmp, "%ld\n", &max_inst);
	if (ret != 1) {
		pr_err("failed to parse string %s\n", tmp);
		return -EINVAL;
	}
	ret = group_set_max_inst(idx, max_inst);
	if (ret)
		return ret;

	return count;
}

static const struct file_operations cgpu_max_inst_node_fops= {
	.owner          = THIS_MODULE,
	.open           = cgpu_max_inst_node_open,
	.read           = seq_read,
	.write          = cgpu_max_inst_node_write,
	.llseek         = seq_lseek,
	.release        = single_release,
};

int cgpu_km_procfs_init(int num)
{
	int ret = 0;
	int i = 0;
	char inst_dir[] = "0";

	if (num < 0 || num > MAX_GROUP_NUM)
		return -EINVAL;

	proc_root = proc_mkdir(PROCFS_ROOT_DIR, NULL);
	if (!proc_root) {
		pr_err("failed to create procfs node %s\n",
			PROCFS_ROOT_DIR);
		return -EFAULT;
	}

	for (i = 0; i < num; i++) {
		struct proc_dir_entry *node_policy, *node_max_inst, *node_weight;
		unsigned long data = i;

		proc_insts[i] = proc_mkdir(inst_dir, proc_root);
		if (!proc_insts[i]) {
			pr_err("failed to create procfs node %s\n",
					inst_dir);
			ret = -EFAULT;
			goto err;
		}

		node_policy = proc_create_data(PROCFS_POLICY_NODE, 0666,
                        proc_insts[i], &cgpu_policy_node_fops, (void *)data);
		node_max_inst = proc_create_data(PROCFS_MAX_INST_NODE, 0666,
                        proc_insts[i], &cgpu_max_inst_node_fops, (void *)data);

		node_weight = proc_create_data(PROCFS_FREE_WEIGHT_NODE, 0444,
                      proc_insts[i], &cgpu_freeweight_node_fops, (void *)data);

		inst_dir[0]++;
	}

	node_inst_ctl = proc_create_data(PROCFS_INST_CTL_NODE, 0666, proc_root,
			&cgpu_inst_ctl_fops, NULL);
	if (!node_inst_ctl) {
		pr_err("failed to create procfs node %s\n",
			PROCFS_INST_CTL_NODE);
		ret = -EFAULT;
		goto err;
	}

	node_default_memsize = proc_create_data(PROCFS_DEF_MEMSIZE_NODE, 0666,
			proc_root, &cgpu_default_ms_node_fops, NULL);
	if (!node_default_memsize) {
		pr_err("failed to create procfs node %s\n",
			PROCFS_DEF_MEMSIZE_NODE);
		ret = -EFAULT;
		goto err;
	}

	node_major = proc_create_data(PROCFS_MAJOR_NODE, 0444,
			proc_root, &cgpu_major_node_fops, NULL);
	if (!node_major) {
		pr_err("failed to create procfs node %s\n",
			PROCFS_MAJOR_NODE);
		ret = -EFAULT;
		goto err;
	}

	node_version = proc_create_data("version", 0444,
                      proc_root, &cgpu_version_node_fops, NULL);
	group_num = num;
	return 0;

err:
	proc_remove(proc_root);
	proc_root = NULL;

	return ret;
}

int cgpu_km_procfs_deinit(void)
{
	if (proc_root) {
		proc_remove(proc_root);
		proc_root = NULL;
	}

	return 0;
}

