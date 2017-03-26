/*
 * INET.. An implementation of the client side port management for connection
 *        sockets
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/errno.h>
#include <linux/pid.h>
#include <linux/cred.h>
#include <linux/printk.h>
#include <linux/task_port.h>
#include <linux/list.h>

/*
 * This is called at exit time, which always have a valid task_struct field. So just
 * reading fields like group_leader is always safe.
 */
void clear_task_reserved_port_list(struct task_struct *tsk)
{
	struct task_reserved_port_pair *p = NULL, *next; 
	struct list_head to_free;
	if (tsk->group_leader == tsk) {
		spin_lock(&tsk->port_lock);
		to_free = tsk->task_reserved_ports;
		INIT_LIST_HEAD(&tsk->task_reserved_ports);
		tsk->task_reserved_ports_freeze = 1;
		/* locking does have effect of wmb */
		spin_unlock(&tsk->port_lock);
		list_for_each_entry_safe(p, next, &to_free, list) {
			list_del(&p->list);
			free_task_port_pair(p);
		}
	}
}
EXPORT_SYMBOL(clear_task_reserved_port_list);

/*
 *	This is only called at fork time, which means both parent and child will have
 *	valid task_struct. No need to do rcu locking, and also child is not yet entered
 *	to pid table, so system calls trying to race it will end up in -ESRCH
 */
int copy_reserved_ports_from_parent(struct task_struct *parent, struct task_struct *child)
{
	int error = 0;
	struct task_reserved_port_pair *p, *new;

	spin_lock(&parent->port_lock);
	INIT_LIST_HEAD(&child->task_reserved_ports);
	list_for_each_entry(p, &parent->task_reserved_ports, list) {
		spin_unlock(&parent->port_lock);
		/*
		 *	allocation may sleep.
		 */
		new = alloc_task_port_pair();
		spin_lock(&parent->port_lock);
		if (unlikely(!new)) {
			error = -ENOMEM;
			break;
		}
		list_add_tail(&new->list, &child->task_reserved_ports);
	}
	spin_unlock(&parent->port_lock);
	return error;

}
EXPORT_SYMBOL(copy_reserved_ports_from_parent);


/*
 *	tsk must have tsk == tsk->group_leader hold. Current reserved ports
 *	only apply to process scope. To ensure the task is still in good
 *	state, we must:
 *		1. call get_task_struct with RCU protection before we obtain tsk
 *		2. check if we should add port after we have grabbed the lock
 */
static int add_task_reserved_port(struct task_struct *tsk, int low, int high)
{
	int error = 0;
	struct task_reserved_port_pair *p;

	/*
	 *	check if we need to copy the port list
	 */
	spin_lock(&tsk->port_lock);
	/* no longer allow we to change the reserve ports list */
	if (tsk->task_reserved_ports_freeze)
		goto out;
	list_for_each_entry(p, &tsk->task_reserved_ports, list) {
		if (p->low == low && p->high == high) {
			/* found existing ports */
			goto out;
		}
	}
	spin_unlock(&tsk->port_lock);

	p = alloc_task_port_pair();
	spin_lock(&tsk->port_lock);
	if (unlikely(!p)) {
		error = -ENOMEM;
		goto out;
	}

	/*
	 *	Ugly workaround: it can happen the list is frozen when
	 *	we try to allocate a memory node without the spinlock hold.
	 *	Maybe mutex would be a better solution but we now do spinlock
	 *	in favor of read access. Or maybe we could use RCU to help
	 *	it.
	 */
	if (tsk->task_reserved_ports_freeze) {
		error = -EACCES;
		goto out_free;
	}
	list_add_tail(&p->list, &tsk->task_reserved_ports);

out_free:
	free_task_port_pair(p);
out:
	spin_unlock(&tsk->port_lock);
	return error;
}


static void delete_task_reserved_port(struct task_struct *tsk, int low, int high)
{
	struct task_reserved_port_pair *p = NULL, *next;
	spin_lock(&tsk->port_lock);
	/* no longer allow we to change the reserve ports list */
	if (tsk->task_reserved_ports_freeze)
		goto out;
	list_for_each_entry_safe(p, next, &tsk->task_reserved_ports, list) {
		if (p->low == low && p->high == high) {
			/* found existing ports */
			list_del(&p->list);
			break;
		}
	}

out:
	spin_unlock(&tsk->port_lock);
	if (p)
		free_task_port_pair(p);
}

/* tsk protected by RCU */
static int test_task_port_reserved(struct task_struct *tsk, int port)
{
	int ret = 0;
	struct task_reserved_port_pair *p;
	/*
	 *	TODO: can we optimize this to use RCU? The write
	 *	of reserved port list is rare event.
	 */
	spin_lock(&tsk->port_lock);
	list_for_each_entry(p, &tsk->task_reserved_ports, list) {
		if (p->low <= port && p->high >= port) {
			ret = 1;
			break;
		}
	}
	spin_unlock(&tsk->port_lock);
	return ret;
}


void inet_get_proc_local_port_range(int *low, int *high)
{
	struct task_struct *leader;
	int curlow, curhigh;
	/*
	 *	RCU lock is enough to make sure leader is alive
	 */
	rcu_read_lock();
	leader = current->group_leader;

	/*
	 *	TODO: this can be optimized by an atomic int64
	 */
	spin_lock(&leader->port_lock);
	curlow = leader->task_port_low;
	curhigh = leader->task_port_high;
	spin_unlock(&leader->port_lock);
	rcu_read_unlock();

	printk("fetch process local ports: %d %d\n", curlow, curhigh);
	if (curhigh < curlow)
		return;

	if (curlow > *low && curlow <= *high)
		*low = curlow;

	if (curhigh < *high && curhigh >= *low)
		*high = curhigh;
}
EXPORT_SYMBOL(inet_get_proc_local_port_range);

/*
 *	TODO: this function might become a bottleneck at connection time, since
 *	it will be repeatably called if there are heavy usage on client ports.
 *
 */
int inet_is_proc_local_reserved_port(int port)
{
	int ret;
	rcu_read_lock();
	ret = test_task_port_reserved(current->group_leader, port);
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL(inet_is_proc_local_reserved_port);


static int check_access_local_port_permission(struct task_struct *target)
{
	const struct cred *cred = current_cred();
	const struct cred *tcred = __task_cred(target);

	if (uid_eq(cred->euid, tcred->suid) ||
			uid_eq(cred->euid, tcred->uid)  ||
			uid_eq(cred->uid,  tcred->suid) ||
			uid_eq(cred->uid,  tcred->uid))
		return 0;

	return -EPERM;
}

static inline struct task_struct *find_process(pid_t pid)
{
	struct pid *target_pid = NULL;
	struct task_struct *p = NULL;

	rcu_read_lock();
	target_pid = find_vpid(pid);
	if (!target_pid) {
		goto out;
	}

	p = pid_task(target_pid, PIDTYPE_PID);
	if (!p) {
		goto out;
	}
	get_task_struct(p);

out:
	rcu_read_unlock();
	return p;
}


SYSCALL_DEFINE3(set_proc_local_ports, pid_t, pid, int, low, int, high)
{
	struct task_struct *target;
	/* validate the parameters */
	if (low < 0 || low > 65536)
		return -EINVAL;
	if (high < 0 || high > 65536 || high < low)
		return -EINVAL;

	target = find_process(pid);

	if (target) {
		/* check permission */
		int error = check_access_local_port_permission(target);
		if (!error) {
			spin_lock(&target->port_lock);
			target->task_port_low = low;
			target->task_port_high = high;
			spin_unlock(&target->port_lock);
		}
		put_task_struct(target);
		return error;
	}
	printk("Can not find target process: %d\n", pid);
	return -ESRCH;
}

SYSCALL_DEFINE3(get_proc_local_ports, pid_t, pid, int __user *, low, int __user *, high)
{
	int error = 0;
	int curr_lo, curr_hi;
	struct task_struct *target, *leader;

	/* quick path for own local port range */
	if (pid == 0) {
		rcu_read_lock(); /* leader should be protected by RCU */
		leader = current->group_leader;
		spin_lock(&leader->port_lock);
		curr_lo = leader->task_port_low;
		curr_hi = leader->task_port_high;
		spin_unlock(&leader->port_lock);
		rcu_read_unlock();
		goto out;
	}

	target = find_process(pid);
	if (target) {
		/* check permission */
		error = check_access_local_port_permission(target);
		if (!error) {
			spin_lock(&target->port_lock);
			curr_lo = target->task_port_low;
			curr_hi = target->task_port_high;
			spin_unlock(&target->port_lock);
		}
		put_task_struct(target);
	}

	if (likely(!target)) {
		printk("Can not find target process: %d\n", pid);
		error = ESRCH;
	}

out:
	if (!error) {
		if (put_user(curr_lo, low))
			return -EFAULT;
		if (put_user(curr_hi, high))
			return -EFAULT;
	}
	return error;
}

static int copy_reserved_ports_to_user(struct task_struct *tsk, int __user *ports, int maxn)
{
	int num_copied = 0;
	struct task_reserved_port_pair *p;
	spin_lock(&tsk->port_lock);
	if (!list_empty(&tsk->task_reserved_ports)) {
		list_for_each_entry(p, &tsk->task_reserved_ports, list) {
			int pair[2] = {p->low, p->high};
			spin_unlock(&tsk->port_lock);
			if (num_copied > maxn - 2) {
				goto out_unlocked;
			}
			if (copy_to_user(ports + num_copied, pair, sizeof(int) * 2)) {
				num_copied = -EFAULT;
				goto out_unlocked;
			}
			num_copied += 2;
			spin_lock(&tsk->port_lock);
		}
	}
	spin_unlock(&tsk->port_lock);
out_unlocked:
	return num_copied;
}

SYSCALL_DEFINE3(get_proc_reserved_ports, pid_t, pid, int __user *, ports, int, maxn)
{
	int error = 0;
	struct task_struct *target = find_process(pid);
	if (target) {
		/* check permission */
		error = check_access_local_port_permission(target);
		if (!error) {
			/* may sleep. Here error means "num copied" */
			error = copy_reserved_ports_to_user(target, ports, maxn);
			put_task_struct(target);
		}
	}
	return error;
}

SYSCALL_DEFINE3(add_proc_reserved_ports, pid_t, pid, int, low, int, high)
{
	int error = 0;
	struct task_struct *target = find_process(pid);
	if (target) {
		/* check permission */
		error = check_access_local_port_permission(target);
		if (!error) {
			error = add_task_reserved_port(target, low, high);
			put_task_struct(target);
		}
	}
	return error;
}

SYSCALL_DEFINE3(delete_proc_reserved_ports, pid_t, pid, int, low, int, high)
{
	int error = 0;
	struct task_struct *target = find_process(pid);
	if (target) {
		/* check permission */
		error = check_access_local_port_permission(target);
		if (!error) {
			delete_task_reserved_port(target, low, high);
			put_task_struct(target);
		}
	}
	return error;
}
