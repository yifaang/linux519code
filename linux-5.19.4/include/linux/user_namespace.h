/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_USER_NAMESPACE_H
#define _LINUX_USER_NAMESPACE_H

#include <linux/kref.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/rwsem.h>
#include <linux/sysctl.h>
#include <linux/err.h>

#define UID_GID_MAP_MAX_BASE_EXTENTS 5
#define UID_GID_MAP_MAX_EXTENTS 340

struct uid_gid_extent {
	u32 first;
	u32 lower_first;
	u32 count;
};

struct uid_gid_map { /* 64 bytes -- 1 cache line */
	u32 nr_extents;
	union {
		struct uid_gid_extent extent[UID_GID_MAP_MAX_BASE_EXTENTS];
		struct {
			struct uid_gid_extent *forward;
			struct uid_gid_extent *reverse;
		};
	};
};

#define USERNS_SETGROUPS_ALLOWED 1UL

#define USERNS_INIT_FLAGS USERNS_SETGROUPS_ALLOWED

struct ucounts;

enum ucount_type {
	UCOUNT_USER_NAMESPACES,
	UCOUNT_PID_NAMESPACES,
	UCOUNT_UTS_NAMESPACES,
	UCOUNT_IPC_NAMESPACES,
	UCOUNT_NET_NAMESPACES,
	UCOUNT_MNT_NAMESPACES,
	UCOUNT_CGROUP_NAMESPACES,
	UCOUNT_TIME_NAMESPACES,
#ifdef CONFIG_INOTIFY_USER
	UCOUNT_INOTIFY_INSTANCES,
	UCOUNT_INOTIFY_WATCHES,
#endif
#ifdef CONFIG_FANOTIFY
	UCOUNT_FANOTIFY_GROUPS,
	UCOUNT_FANOTIFY_MARKS,
#endif
	UCOUNT_RLIMIT_NPROC,
	UCOUNT_RLIMIT_MSGQUEUE,
	UCOUNT_RLIMIT_SIGPENDING,
	UCOUNT_RLIMIT_MEMLOCK,
	UCOUNT_COUNTS,
};

#define MAX_PER_NAMESPACE_UCOUNTS UCOUNT_RLIMIT_NPROC

//struct user_namespace 结构体定义了一个用户命名空间的数据结构，描述了 Linux 内核中的用户命名空间相关信息。该结构体包含了用户 ID、组 ID 映射、用户命名空间的父级、权限、键值管理等信息。
struct user_namespace {
	/* 用户ID映射 */
	struct uid_gid_map	uid_map;   // 映射用户 ID (UID) 到命名空间内的实际 UID
	/* 组ID映射 */
	struct uid_gid_map	gid_map;   // 映射组 ID (GID) 到命名空间内的实际 GID
	/* 项目 ID 映射（例如，某些特定应用可能使用的映射） */
	struct uid_gid_map	projid_map; // 映射项目 ID（如用户应用的项目）

	/* 父用户命名空间 */
	struct user_namespace	*parent;   // 指向父命名空间的指针，用于实现命名空间的继承
	/* 用户命名空间的层级 */
	int			level;     // 当前用户命名空间的层级
	/* 命名空间的所有者 UID */
	kuid_t			owner;     // 用户命名空间的拥有者的 UID
	/* 命名空间的组 GID */
	kgid_t			group;     // 用户命名空间的组 GID
	/* 通用的命名空间信息 */
	struct ns_common	ns;        // 包含命名空间的通用信息，如名字空间ID等
	/* 用户命名空间的标志位 */
	unsigned long		flags;     // 用户命名空间的各种标志

	/* parent_could_setfcap: 如果该命名空间的创建者在创建时具有 CAP_SETFCAP 能力，则为 true */
	bool			parent_could_setfcap; // 标识父命名空间是否具有设置文件能力的权限

#ifdef CONFIG_KEYS
	/* 当前命名空间中可加入的密钥环列表。 */
	struct list_head	keyring_name_list;  // 加入的密钥环列表
	/* 注册的用户密钥环，管理用户级别的密钥 */
	struct key		*user_keyring_register;  // 用户密钥环的注册指针
	/* 键环的信号量，用于控制并发访问 */
	struct rw_semaphore	keyring_sem;    // 键环的读写信号量
#endif

	/* 持久化的 UID 密钥环注册表 */
#ifdef CONFIG_PERSISTENT_KEYRINGS
	struct key		*persistent_keyring_register; // 注册的持久性密钥环
#endif

	/* 命名空间的工作队列 */
	struct work_struct	work;    // 用于延迟执行工作的工作队列

#ifdef CONFIG_SYSCTL
	/* 系统控制表设置 */
	struct ctl_table_set	set;  // 系统控制表的设置
	/* 系统控制表头，用于管理 sysctl 数据 */
	struct ctl_table_header *sysctls; // 指向系统控制表头的指针
#endif

	/* 用户计数器，管理与用户相关的资源 */
	struct ucounts		*ucounts;   // 用户计数器数据结构指针
	/* 用户计数的最大限制 */
	long ucount_max[UCOUNT_COUNTS]; // 每个计数的最大值
} __randomize_layout;


struct ucounts {
	struct hlist_node node;
	struct user_namespace *ns;
	kuid_t uid;
	atomic_t count;
	atomic_long_t ucount[UCOUNT_COUNTS];
};

extern struct user_namespace init_user_ns;
extern struct ucounts init_ucounts;

bool setup_userns_sysctls(struct user_namespace *ns);
void retire_userns_sysctls(struct user_namespace *ns);
struct ucounts *inc_ucount(struct user_namespace *ns, kuid_t uid, enum ucount_type type);
void dec_ucount(struct ucounts *ucounts, enum ucount_type type);
struct ucounts *alloc_ucounts(struct user_namespace *ns, kuid_t uid);
struct ucounts * __must_check get_ucounts(struct ucounts *ucounts);
void put_ucounts(struct ucounts *ucounts);

static inline long get_ucounts_value(struct ucounts *ucounts, enum ucount_type type)
{
	return atomic_long_read(&ucounts->ucount[type]);
}

long inc_rlimit_ucounts(struct ucounts *ucounts, enum ucount_type type, long v);
bool dec_rlimit_ucounts(struct ucounts *ucounts, enum ucount_type type, long v);
long inc_rlimit_get_ucounts(struct ucounts *ucounts, enum ucount_type type);
void dec_rlimit_put_ucounts(struct ucounts *ucounts, enum ucount_type type);
bool is_ucounts_overlimit(struct ucounts *ucounts, enum ucount_type type, unsigned long max);

static inline void set_rlimit_ucount_max(struct user_namespace *ns,
		enum ucount_type type, unsigned long max)
{
	ns->ucount_max[type] = max <= LONG_MAX ? max : LONG_MAX;
}

#ifdef CONFIG_USER_NS

static inline struct user_namespace *get_user_ns(struct user_namespace *ns)
{
	if (ns)
		refcount_inc(&ns->ns.count);
	return ns;
}

extern int create_user_ns(struct cred *new);
extern int unshare_userns(unsigned long unshare_flags, struct cred **new_cred);
extern void __put_user_ns(struct user_namespace *ns);

static inline void put_user_ns(struct user_namespace *ns)
{
	if (ns && refcount_dec_and_test(&ns->ns.count))
		__put_user_ns(ns);
}

struct seq_operations;
extern const struct seq_operations proc_uid_seq_operations;
extern const struct seq_operations proc_gid_seq_operations;
extern const struct seq_operations proc_projid_seq_operations;
extern ssize_t proc_uid_map_write(struct file *, const char __user *, size_t, loff_t *);
extern ssize_t proc_gid_map_write(struct file *, const char __user *, size_t, loff_t *);
extern ssize_t proc_projid_map_write(struct file *, const char __user *, size_t, loff_t *);
extern ssize_t proc_setgroups_write(struct file *, const char __user *, size_t, loff_t *);
extern int proc_setgroups_show(struct seq_file *m, void *v);
extern bool userns_may_setgroups(const struct user_namespace *ns);
extern bool in_userns(const struct user_namespace *ancestor,
		       const struct user_namespace *child);
extern bool current_in_userns(const struct user_namespace *target_ns);
struct ns_common *ns_get_owner(struct ns_common *ns);
#else

static inline struct user_namespace *get_user_ns(struct user_namespace *ns)
{
	return &init_user_ns;
}

static inline int create_user_ns(struct cred *new)
{
	return -EINVAL;
}

static inline int unshare_userns(unsigned long unshare_flags,
				 struct cred **new_cred)
{
	if (unshare_flags & CLONE_NEWUSER)
		return -EINVAL;
	return 0;
}

static inline void put_user_ns(struct user_namespace *ns)
{
}

static inline bool userns_may_setgroups(const struct user_namespace *ns)
{
	return true;
}

static inline bool in_userns(const struct user_namespace *ancestor,
			     const struct user_namespace *child)
{
	return true;
}

static inline bool current_in_userns(const struct user_namespace *target_ns)
{
	return true;
}

static inline struct ns_common *ns_get_owner(struct ns_common *ns)
{
	return ERR_PTR(-EPERM);
}
#endif

#endif /* _LINUX_USER_H */
