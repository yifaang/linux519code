/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __IPC_NAMESPACE_H__
#define __IPC_NAMESPACE_H__

#include <linux/err.h>
#include <linux/idr.h>
#include <linux/rwsem.h>
#include <linux/notifier.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/refcount.h>
#include <linux/rhashtable-types.h>
#include <linux/sysctl.h>

struct user_namespace;
//ipc_ids 结构体是 Linux 内核中用于管理 IPC（进程间通信）资源的一个数据结构。它在内核的 IPC 子系统（如消息队列、信号量和共享内存）中被使用，用于维护和管理这些资源的状态和访问。
struct ipc_ids {
    int in_use;                // 当前正在使用的 IPC 资源数量，用于统计和管理。
    unsigned short seq;        // 序列号，生成唯一的 IPC ID，每次创建新资源时递增。
    struct rw_semaphore rwsem; // 读写信号量，用于保护对 IPC 数据结构的并发访问，
                               // 确保多线程环境下的读写安全。
    struct idr ipcs_idr;       // ID 分配器，用于高效地分配和管理 IPC 资源 ID。
    int max_idx;               // 当前 ID 范围的最大索引值，用于分配新 ID 时的边界检查。
    int last_idx;              // 上一次分配的 ID 索引，用于检测是否发生了环绕（wrap around）。
#ifdef CONFIG_CHECKPOINT_RESTORE
    int next_id;               // （仅在启用 CHECKPOINT_RESTORE 配置时使用）
                               // 下一个用于恢复的 IPC 资源 ID，用于容器或进程检查点/恢复。
#endif
    struct rhashtable key_ht;  // 哈希表，用于快速查找 IPC 资源的 key（用户定义的键值）。
};

struct ipc_namespace {
	struct ipc_ids	ids[3];

	int		sem_ctls[4];
	int		used_sems;

	unsigned int	msg_ctlmax;
	unsigned int	msg_ctlmnb;
	unsigned int	msg_ctlmni;
	atomic_t	msg_bytes;
	atomic_t	msg_hdrs;

	size_t		shm_ctlmax;
	size_t		shm_ctlall;
	unsigned long	shm_tot;
	int		shm_ctlmni;
	/*
	 * Defines whether IPC_RMID is forced for _all_ shm segments regardless
	 * of shmctl()
	 */
	int		shm_rmid_forced;

	struct notifier_block ipcns_nb;

	/* The kern_mount of the mqueuefs sb.  We take a ref on it */
	struct vfsmount	*mq_mnt;

	/* # queues in this ns, protected by mq_lock */
	unsigned int    mq_queues_count;

	/* next fields are set through sysctl */
	unsigned int    mq_queues_max;   /* initialized to DFLT_QUEUESMAX */
	unsigned int    mq_msg_max;      /* initialized to DFLT_MSGMAX */
	unsigned int    mq_msgsize_max;  /* initialized to DFLT_MSGSIZEMAX */
	unsigned int    mq_msg_default;
	unsigned int    mq_msgsize_default;

	struct ctl_table_set	mq_set;
	struct ctl_table_header	*mq_sysctls;

	struct ctl_table_set	ipc_set;
	struct ctl_table_header	*ipc_sysctls;

	/* user_ns which owns the ipc ns */
	struct user_namespace *user_ns;
	struct ucounts *ucounts;

	struct llist_node mnt_llist;

	struct ns_common ns;
} __randomize_layout;

extern struct ipc_namespace init_ipc_ns;
extern spinlock_t mq_lock;

#ifdef CONFIG_SYSVIPC
extern void shm_destroy_orphaned(struct ipc_namespace *ns);
#else /* CONFIG_SYSVIPC */
static inline void shm_destroy_orphaned(struct ipc_namespace *ns) {}
#endif /* CONFIG_SYSVIPC */

#ifdef CONFIG_POSIX_MQUEUE
extern int mq_init_ns(struct ipc_namespace *ns);
/*
 * POSIX Message Queue default values:
 *
 * MIN_*: Lowest value an admin can set the maximum unprivileged limit to
 * DFLT_*MAX: Default values for the maximum unprivileged limits
 * DFLT_{MSG,MSGSIZE}: Default values used when the user doesn't supply
 *   an attribute to the open call and the queue must be created
 * HARD_*: Highest value the maximums can be set to.  These are enforced
 *   on CAP_SYS_RESOURCE apps as well making them inviolate (so make them
 *   suitably high)
 *
 * POSIX Requirements:
 *   Per app minimum openable message queues - 8.  This does not map well
 *     to the fact that we limit the number of queues on a per namespace
 *     basis instead of a per app basis.  So, make the default high enough
 *     that no given app should have a hard time opening 8 queues.
 *   Minimum maximum for HARD_MSGMAX - 32767.  I bumped this to 65536.
 *   Minimum maximum for HARD_MSGSIZEMAX - POSIX is silent on this.  However,
 *     we have run into a situation where running applications in the wild
 *     require this to be at least 5MB, and preferably 10MB, so I set the
 *     value to 16MB in hopes that this user is the worst of the bunch and
 *     the new maximum will handle anyone else.  I may have to revisit this
 *     in the future.
 */
#define DFLT_QUEUESMAX		      256
#define MIN_MSGMAX			1
#define DFLT_MSG		       10U
#define DFLT_MSGMAX		       10
#define HARD_MSGMAX		    65536
#define MIN_MSGSIZEMAX		      128
#define DFLT_MSGSIZE		     8192U
#define DFLT_MSGSIZEMAX		     8192
#define HARD_MSGSIZEMAX	    (16*1024*1024)
#else
static inline int mq_init_ns(struct ipc_namespace *ns) { return 0; }
#endif

#if defined(CONFIG_IPC_NS)
extern struct ipc_namespace *copy_ipcs(unsigned long flags,
	struct user_namespace *user_ns, struct ipc_namespace *ns);

static inline struct ipc_namespace *get_ipc_ns(struct ipc_namespace *ns)
{
	if (ns)
		refcount_inc(&ns->ns.count);
	return ns;
}

static inline struct ipc_namespace *get_ipc_ns_not_zero(struct ipc_namespace *ns)
{
	if (ns) {
		if (refcount_inc_not_zero(&ns->ns.count))
			return ns;
	}

	return NULL;
}

extern void put_ipc_ns(struct ipc_namespace *ns);
#else
static inline struct ipc_namespace *copy_ipcs(unsigned long flags,
	struct user_namespace *user_ns, struct ipc_namespace *ns)
{
	if (flags & CLONE_NEWIPC)
		return ERR_PTR(-EINVAL);

	return ns;
}

static inline struct ipc_namespace *get_ipc_ns(struct ipc_namespace *ns)
{
	return ns;
}

static inline struct ipc_namespace *get_ipc_ns_not_zero(struct ipc_namespace *ns)
{
	return ns;
}

static inline void put_ipc_ns(struct ipc_namespace *ns)
{
}
#endif

#ifdef CONFIG_POSIX_MQUEUE_SYSCTL

void retire_mq_sysctls(struct ipc_namespace *ns);
bool setup_mq_sysctls(struct ipc_namespace *ns);

#else /* CONFIG_POSIX_MQUEUE_SYSCTL */

static inline void retire_mq_sysctls(struct ipc_namespace *ns)
{
}

static inline bool setup_mq_sysctls(struct ipc_namespace *ns)
{
	return true;
}

#endif /* CONFIG_POSIX_MQUEUE_SYSCTL */

#ifdef CONFIG_SYSVIPC_SYSCTL

bool setup_ipc_sysctls(struct ipc_namespace *ns);
void retire_ipc_sysctls(struct ipc_namespace *ns);

#else /* CONFIG_SYSVIPC_SYSCTL */

static inline void retire_ipc_sysctls(struct ipc_namespace *ns)
{
}

static inline bool setup_ipc_sysctls(struct ipc_namespace *ns)
{
	return true;
}

#endif /* CONFIG_SYSVIPC_SYSCTL */
#endif
