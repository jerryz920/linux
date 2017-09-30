/*
 * INET.. An implementation of the client side port management for connection
 *        sockets
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/syscalls.h>
#include <linux/errno.h>
#include <linux/pid.h>
#include <linux/cred.h>
#include <linux/printk.h>
#include <linux/task_port.h>
#include <linux/list.h>
#include <linux/net.h>
#include <net/inet_hashtables.h>
#include <net/tcp.h>


#define PORT_COUNT 65536

/* #include <asm/bitops.h> */

/*
DECLARE_BITMAP(global_port_usage_map, 65536);

void inet_lock_port(__u16 port) {
  while (test_and_set_bit(port, global_port_usage_map))
          ;
}
EXPORT_SYMBOL(inet_lock_port);

void inet_unlock_port(__u16 port) {
  clear_bit(port, global_port_usage_map);
}
EXPORT_SYMBOL(inet_unlock_port);



static int check_port_range_usable(struct net *net,
    struct hashinfo *info, __u16 s, __u16 e) {
  __u16 i;
  for (i = s; i != e; i++) {
          if (test_bit(i)) {
                  return 0;
          }
          head = &hashinfo->bhash[inet_bhashfn(net, i,
                  hashinfo->bhash_size)];
          spin_lock(&head->lock);
          inet_bind_bucket_for_each(tb, &head->chain)
            if (net_eq(ib_net(tb), net) && tb->port == i
                    && tb->num_owners > 0) {
                    spin_unlock(&head->lock);
                    return 0;
            }
  }

  return 1;
}
*/

extern int __inet_check_port_range_in_use(struct net *net,
    struct inet_hashinfo *hashinfo, const __be16 pmin, const __be16 pmax,
    unsigned long* usage_map);


/*
 * This is called at exit time, which always have a valid task_struct field. So just
 * reading fields like group_leader is always safe.
 */
void clear_task_reserved_port_list(struct task_struct *tsk, int finalize)
{
	struct task_reserved_port_pair *p = NULL, *next; 
	struct list_head to_free = LIST_HEAD_INIT(to_free);
	if (tsk->group_leader == tsk) {

		spin_lock(&tsk->port_lock);
		/* we just move the old list to a new list then we can unlock */
		list_cut_position(&to_free, &tsk->task_reserved_ports,
				tsk->task_reserved_ports.prev);
		INIT_LIST_HEAD(&tsk->task_reserved_ports);
		tsk->task_reserved_ports_freeze = finalize;
		/* locking does have effect of wmb */
		spin_unlock(&tsk->port_lock);
		list_for_each_entry_safe(p, next, &to_free, list) {
			printk("finalize:%d clear port %d %d\n", finalize, p->low, p->high);
			list_del(&p->list);
			free_task_port_pair(p);
		}
	}
}

void finalize_task_reserved_port_list(struct task_struct *tsk)
{
	clear_task_reserved_port_list(tsk, 1);
}
EXPORT_SYMBOL(finalize_task_reserved_port_list);



static int check_process_port_range_usage(struct task_struct *tsk,
        int low, int high)
{
        int error = 0;

        /* FIXME: we only checked TCP connection here, but we could also
         * support UDP in future with udp_table */
        if (tsk != current)
                task_lock(tsk);
        if (!tsk->nsproxy) {
                error = -ESRCH;
                goto out;
        }

        if (__inet_check_port_range_in_use(tsk->nsproxy->net_ns,
                    &tcp_hashinfo, low, high, NULL)) {
                error = -EBUSY;
        }
out:
        if (tsk != current)
                task_unlock(tsk);
        return error;
}

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

	printk(KERN_INFO" add:not found reserved port %d, %d, allocating\n", low, high);
	p = alloc_task_port_pair();
	spin_lock(&tsk->port_lock);

	if (unlikely(!p)) {
		error = -ENOMEM;
		goto out;
	}

        /* It is possible this port is allocated when we try to allocate 
         * the pair.*/
        error = check_process_port_range_usage(tsk, low, high);
        if (error != 0) {
                goto out_free;
        }

	/*
	 *	Ugly workaround: it can happen the list is frozen when
	 *	we try to allocate a memory node without the spinlock hold.
	 *	Maybe mutex would be a better solution but we now do spinlock
	 *	in favor of read access. Or maybe we could use RCU to help
	 *	it.
	 */
	p->low = low;
	p->high = high;
	if (tsk->task_reserved_ports_freeze) {
		error = -EACCES;
		goto out_free;
	}
	list_add_tail(&p->list, &tsk->task_reserved_ports);

out:
	spin_unlock(&tsk->port_lock);
	return error;

out_free:
        spin_unlock(&tsk->port_lock);
	free_task_port_pair(p);
        return error;
}

/* try to allocate port range for given task */
static int try_allocate_port_range(struct task_struct *tsk, int n) {

        int error = 0;
        unsigned long usable;
        unsigned long *usage_map = kcalloc(PORT_COUNT, 1, GFP_KERNEL);
	struct task_reserved_port_pair *p, *pnew;
        int low = tsk->task_port_low;
        int high = tsk->task_port_high;

        if (unlikely(!usage_map)) {
                return -ENOMEM;
        }

        pnew = alloc_task_port_pair();
        if (unlikely(!pnew)) {
                kfree(usage_map);
                return -ENOMEM;
        }

        /* FIXME: tsk is the group leader of current. Locking port_lock will
         * prevent the processes/threads in same group from accessing
         * the critical region, but it will not prevent another process
         * to do this. We will need a bitmap lock to enforce access
         * on all the bits atomically */
	spin_lock(&tsk->port_lock);

        /* fill current usage map with exclusive list */
	list_for_each_entry(p, &tsk->task_reserved_ports, list)
                bitmap_set(usage_map, p->low, p->high - p->low + 1);

        if (tsk != current)
                task_lock(tsk);

        __inet_check_port_range_in_use(tsk->nsproxy->net_ns,
                &tcp_hashinfo, low, high, usage_map);

        if (tsk != current)
                task_unlock(tsk);

        /* find first all zero region with length n */
        usable = bitmap_find_next_zero_area(usage_map, high, low, n, 0);
        printk("allocating port range: first zero area %lu\n", usable);
        if (usable > high) {
                error = -EBUSY;
                goto out;
        }

	pnew->low = usable;
	pnew->high = usable + n - 1;
	if (tsk->task_reserved_ports_freeze) {
		error = -EACCES;
		goto out_free;
	}
	list_add_tail(&pnew->list, &tsk->task_reserved_ports);
        error = usable;
out:
        spin_unlock(&tsk->port_lock);
        kfree(usage_map);
        return error;

out_free:
        spin_unlock(&tsk->port_lock);
        kfree(usage_map);
        free_task_port_pair(p);
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
	if (p) {
		printk(KERN_INFO" del: found reserved port %d, %d\n", low, high);
		free_task_port_pair(p);
	}
}

/* tsk protected by RCU */

static int __test_task_port_reserved(struct task_struct *tsk, int port)
{
	struct task_reserved_port_pair *p;
	list_for_each_entry(p, &tsk->task_reserved_ports, list) {
		if (p->low <= port && p->high >= port) {
                        return 1;
		}
	}
	return 0;
}
static int test_task_port_reserved(struct task_struct *tsk, int port)
{
	int ret = 0;
	/*
	 *	TODO: can we optimize this to use RCU? The write
	 *	of reserved port list is rare event.
	 */
	spin_lock(&tsk->port_lock);
        ret = __test_task_port_reserved(tsk, port);
	spin_unlock(&tsk->port_lock);
	return ret;
}


void inet_get_proc_local_port_range(int *low, int *high)
{
	struct task_struct *leader;
	pid_t task_pid;
	int curlow, curhigh;
	/*
	 *	RCU lock is enough to make sure leader is alive
	 */
	rcu_read_lock();

	leader = current->group_leader;
	task_pid = pid_vnr(get_task_pid(leader, PIDTYPE_PID));

        /*
         *   Note: this method is always called with port_lock
         *   hold, so we don't need to lock here.
         */
	/* spin_lock(&leader->port_lock); */
	curlow = leader->task_port_low;
	curhigh = leader->task_port_high;
	/* spin_unlock(&leader->port_lock); */
	rcu_read_unlock();

	if (curhigh < curlow)
		return;
	printk("task %u fetch process local ports: %d %d, original %d %d\n", task_pid, curlow, curhigh, *low, *high);

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
int inet_is_proc_local_reserved_port(unsigned int type, int port)
{
	int ret = 0;
        if (type != SOCK_STREAM)
                return 0;
	rcu_read_lock();
	ret = test_task_port_reserved(current->group_leader, port);
	rcu_read_unlock();
	return ret;
}
EXPORT_SYMBOL(inet_is_proc_local_reserved_port);


int inet_is_proc_local_reserved_port_locked(unsigned int type, int port)
{
        int ret = 0;
        if (type != SOCK_STREAM)
                return 0;
        rcu_read_lock();
	ret = __test_task_port_reserved(current->group_leader, port);
	rcu_read_unlock();
        return ret;
}
EXPORT_SYMBOL(inet_is_proc_local_reserved_port_locked);

void inet_lock_ports()
{
        printk("%d inet lock\n", current->pid);
        rcu_read_lock();
        get_task_struct(current->group_leader);
	rcu_read_unlock();
	spin_lock(&current->group_leader->port_lock);
}
EXPORT_SYMBOL(inet_lock_ports);

void inet_unlock_ports()
{
	spin_unlock(&current->group_leader->port_lock);
        put_task_struct(current->group_leader);
        printk("%d inet unlock\n", current->pid);
}
EXPORT_SYMBOL(inet_unlock_ports);


static int check_access_local_port_permission(struct task_struct *target)
{
	const struct cred *cred = current_cred();
	const struct cred *tcred = __task_cred(target);

	printk(KERN_INFO" local port access cred: %u %u, %u %u\n", __kuid_val(cred->euid),
			__kuid_val(cred->uid), __kuid_val(tcred->euid), __kuid_val(tcred->uid));
	if (uid_eq(cred->euid, tcred->suid) ||
			uid_eq(cred->euid, tcred->uid)  ||
			uid_eq(cred->uid,  tcred->suid) ||
			uid_eq(cred->uid,  tcred->uid))
		return 0;

	return -EPERM;
}

static inline struct task_struct *find_process(pid_t pid)
{
	struct task_struct *p = NULL;

	rcu_read_lock();
	if (pid == 0) {
		p = current->group_leader;
		get_task_struct(p);
	} else {
		p = pid_task(find_vpid(pid), PIDTYPE_PID);
		if (p) {
			if (!thread_group_leader(p))
				p = p->group_leader;
			get_task_struct(p);
		}
	}
	rcu_read_unlock();
	return p;
}


SYSCALL_DEFINE3(set_proc_local_ports, pid_t, pid, int, low, int, high)
{
	int error = 0;
	struct task_struct *target;
	/* validate the parameters */
	if (low < 0 || low > PORT_COUNT)
		return -EINVAL;
	if (high < 0 || high > PORT_COUNT || high < low)
		return -EINVAL;

	target = find_process(pid);

	if (target) {
		/* check permission */
		error = check_access_local_port_permission(target);
		if (!error) {
			spin_lock(&target->port_lock);
                        target->task_port_low = low;
                        target->task_port_high = high;
			spin_unlock(&target->port_lock);
		}
		put_task_struct(target);
	} else {
		printk("Can not find target process: %d\n", pid);
		error = -ESRCH;
	}
	return error;
}

SYSCALL_DEFINE2(alloc_proc_local_ports, pid_t, pid, int, n)
{
	int error = 0;
	struct task_struct *target, *leader;
        if (n <= 0 || n >= PORT_COUNT)
                return -EINVAL;

	target = find_process(pid);
	if (target) {
		/* check permission */
		error = check_access_local_port_permission(target);
                leader = find_process(0);
                if (unlikely(!leader)) {
                        printk("leader dies!\n");
                        error = -ESRCH;
                        put_task_struct(target);
                        goto out;
                }
		if (!error) {
                        error = try_allocate_port_range(leader, n);
		}

                /* error here is the lower bound  range */
                if (error > 0) {
                        printk("allocating %d ports from %d\n", n, error);
                        spin_lock(&target->port_lock);
                        target->task_port_low = error;
                        target->task_port_high = error + n - 1;
                        spin_unlock(&target->port_lock);
                }
		put_task_struct(target);
                put_task_struct(leader);
	} else {
		printk("Can not find target process: %d\n", pid);
		error = -ESRCH;
	}

out:
        return error;
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
			printk(KERN_INFO" found reserved port %d, %d\n", pair[0], pair[1]);
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

SYSCALL_DEFINE1(clear_proc_reserved_ports, pid_t, pid)
{
	int error = 0;
	struct task_struct *target = find_process(pid);
	if (target) {
		/* check permission */
		error = check_access_local_port_permission(target);
		if (!error) {
			clear_task_reserved_port_list(target, 0);
			put_task_struct(target);
		}
	}
	return error;
}
