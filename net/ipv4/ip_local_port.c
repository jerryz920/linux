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


void inet_get_proc_local_port_range(int *low, int *high)
{
        /*
         * A data race can occur here: one thread is calling syscall to update
         * the two fields, while the actual task is trying to connecting out,
         * which could end up in wrong client port selection.
         *
         * However, it's a benign race. Applications are supposed to set up
         * the local port range before their children are starting to connect
         * out. Also, we maintain an invariant of *low <= *high all the time
         */
        int lo = current->task_port_low;
        int hi = current->task_port_high;
        printk("fetch process local ports: %d %d\n", lo, hi);
        if (hi < lo)
                return;

        if (lo > *low && lo <= *high)
                *low = lo;

        if (hi < *high && hi >= *low)
                *high = hi;
}
EXPORT_SYMBOL(inet_get_proc_local_port_range);

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


SYSCALL_DEFINE3(set_proc_local_ports, pid_t, pid, int, lo, int, hi)
{
        struct pid *target_pid = find_vpid(pid);
        struct task_struct *target;

        /* validate the parameters */
        if (lo < 0 || lo > 65536)
                return -EINVAL;

        if (hi < 0 || hi > 65536 || hi < lo)
                return -EINVAL;

        for (;;) {
                rcu_read_lock();
                target = pid_task(target_pid, PIDTYPE_PID);
                if (target) {
                        /* check permission */
                        int error = check_access_local_port_permission(target);
                        if (!error) {
                                target->task_port_low = lo;
                                target->task_port_high = hi;
                        }
                        rcu_read_unlock();
                        return error;
                }
                rcu_read_unlock();
                if (likely(!target)) {
                        printk("Can not find target process: %d\n", pid);
                        return -ESRCH;
                }
        }
}

SYSCALL_DEFINE3(get_proc_local_ports, pid_t, pid, int __user *, lo, int __user *, hi)
{
        int error = 0;
        int curr_lo, curr_hi;
        struct task_struct *target;
        struct pid *target_pid;

        /* quick path for own local port range */
        if (pid == 0) {
                curr_lo = current->task_port_low;
                curr_hi = current->task_port_high;
                goto out;
        }

        rcu_read_lock();
        target = pid_task(target_pid, PIDTYPE_PID);
        if (target) {
                /* check permission */
                error = check_access_local_port_permission(target);
                if (!error) {
                        /* read is protected by RCU */
                        curr_lo = target->task_port_low;
                        curr_hi = target->task_port_high;
                }
        }
        rcu_read_unlock();

        if (likely(!target)) {
                printk("Can not find target process: %d\n", pid);
                error = ESRCH;
        }

out:
        if (!error) {
                if (copy_to_user(lo, &curr_lo, sizeof(int)))
                        return -EFAULT;
                if (copy_to_user(hi, &curr_hi, sizeof(int)))
                        return -EFAULT;
        }
        return error;
}



