/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_MM_TYPES_H
#define _LINUX_MM_TYPES_H

#include <linux/mm_types_task.h>

#include <linux/auxvec.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rbtree.h>
#include <linux/rwsem.h>
#include <linux/completion.h>
#include <linux/cpumask.h>
#include <linux/uprobes.h>
#include <linux/rcupdate.h>
#include <linux/page-flags-layout.h>
#include <linux/workqueue.h>
#include <linux/seqlock.h>

#include <asm/mmu.h>

#ifndef AT_VECTOR_SIZE_ARCH
#define AT_VECTOR_SIZE_ARCH 0
#endif
#define AT_VECTOR_SIZE (2*(AT_VECTOR_SIZE_ARCH + AT_VECTOR_SIZE_BASE + 1))

#define INIT_PASID	0

struct address_space;
struct mem_cgroup;

/*
 * Each physical page in the system has a struct page associated with
 * it to keep track of whatever it is we are using the page for at the
 * moment. Note that we have no way to track which tasks are using
 * a page, though if it is a pagecache page, rmap structures can tell us
 * who is mapping it.
 *
 * If you allocate the page using alloc_pages(), you can use some of the
 * space in struct page for your own purposes.  The five words in the main
 * union are available, except for bit 0 of the first word which must be
 * kept clear.  Many users use this word to store a pointer to an object
 * which is guaranteed to be aligned.  If you use the same storage as
 * page->mapping, you must restore it to NULL before freeing the page.
 *
 * If your page will not be mapped to userspace, you can also use the four
 * bytes in the mapcount union, but you must call page_mapcount_reset()
 * before freeing it.
 *
 * If you want to use the refcount field, it must be used in such a way
 * that other CPUs temporarily incrementing and then decrementing the
 * refcount does not cause problems.  On receiving the page from
 * alloc_pages(), the refcount will be positive.
 *
 * If you allocate pages of order > 0, you can use some of the fields
 * in each subpage, but you may need to restore some of their values
 * afterwards.
 *
 * SLUB uses cmpxchg_double() to atomically update its freelist and counters.
 * That requires that freelist & counters in struct slab be adjacent and
 * double-word aligned. Because struct slab currently just reinterprets the
 * bits of struct page, we align all struct pages to double-word boundaries,
 * and ensure that 'freelist' is aligned within struct slab.
 */
#ifdef CONFIG_HAVE_ALIGNED_STRUCT_PAGE
#define _struct_page_alignment	__aligned(2 * sizeof(unsigned long))
#else
#define _struct_page_alignment
#endif

struct page {
	unsigned long flags;		/* 原子标志，可能会异步更新 */

	/*
	 * 此联合体中有五个字（20/40字节）可用。
	 * 警告：第一个字的第0位用于 PageTail()。这意味着该联合体的其他用户
	 * 绝不能使用此位，以避免冲突和误报 PageTail()。
	 */
	union {
		struct {	/* 页面缓存和匿名页面 */
			/**
			 * @lru: 页面出列列表，例如 active_list，由
			 * lruvec->lru_lock 保护。有时作为页面所有者的通用列表使用。
			 */
			union {
				struct list_head lru; /* LRU链表 */
				/* 或者，对于不可逐出（Unevictable）的“LRU列表”槽 */
				struct {
					/* 始终为偶数，以消除 PageTail */
					void *__filler;
					/* 计数页面或 folio 的锁定数量 */
					unsigned int mlock_count;
				};
			};
			/* 参见 page-flags.h 中的 PAGE_MAPPING_FLAGS */
			struct address_space *mapping; /* 映射信息 */
			pgoff_t index;		/* 我们在映射中的偏移量 */
			/**
			 * @private: 映射私有的模糊数据。
			 * 通常用于 buffer_heads 如果 PagePrivate。
			 * 如果是 PageSwapCache，则用于 swp_entry_t。
			 * 如果是 PageBuddy，则指示在伙伴系统中的顺序。
			 */
			unsigned long private;
		};
		struct {	/* 网络栈使用的 page_pool */
			/**
			 * @pp_magic: 避免回收非 page_pool 分配的页面的魔法值。
			 */
			unsigned long pp_magic;
			struct page_pool *pp; /* 页面池指针 */
			unsigned long _pp_mapping_pad;
			unsigned long dma_addr; /* DMA地址 */
			union {
				/**
				 * dma_addr_upper: 在32位架构上可能需要64位值。
				 */
				unsigned long dma_addr_upper;
				/**
				 * 用于支持片段页面，不支持64位DMA的32位架构。
				 */
				atomic_long_t pp_frag_count; /* 片段计数 */
			};
		};
		struct {	/* 复合页面的尾页 */
			unsigned long compound_head;	/* 设置第0位 */

			/* 仅第一个尾页 */
			unsigned char compound_dtor; /* 复合析构函数 */
			unsigned char compound_order; /* 复合页的顺序 */
			atomic_t compound_mapcount; /* 映射计数 */
			atomic_t compound_pincount; /* 引用计数 */
#ifdef CONFIG_64BIT
			unsigned int compound_nr; /* 1 << compound_order */
#endif
		};
		struct {	/* 复合页面的第二个尾页 */
			unsigned long _compound_pad_1;	/* compound_head */
			unsigned long _compound_pad_2;
			/* 用于全局和内存控制组 */
			struct list_head deferred_list; /* 待处理列表 */
		};
		struct {	/* 页表页面 */
			unsigned long _pt_pad_1;	/* compound_head */
			pgtable_t pmd_huge_pte; /* 由 page->ptl 保护 */
			unsigned long _pt_pad_2;	/* 映射 */
			union {
				struct mm_struct *pt_mm; /* x86 pgds 仅适用 */
				atomic_t pt_frag_refcount; /* PowerPC */
			};
#if ALLOC_SPLIT_PTLOCKS
			spinlock_t *ptl; /* 页表锁指针 */
#else
			spinlock_t ptl; /* 页表锁 */
#endif
		};
		struct {	/* ZONE_DEVICE 页面 */
			/** @pgmap: 指向托管设备的页面映射 */
			struct dev_pagemap *pgmap; /* 设备页面映射 */
			void *zone_device_data; /* 区域设备数据 */
			/*
			 * ZONE_DEVICE 私有页面被计为已映射，
			 * 因此接下来的3个字存储源匿名或页面缓存页面的映射、索引和私有字段
			 * 当页面迁移到设备私有内存时。
			 * ZONE_DEVICE MEMORY_DEVICE_FS_DAX 页面在映射到 pmem 支持的 DAX 文件时
			 * 也使用映射、索引和私有字段。
			 */
		};

		/** @rcu_head: 可以使用此结构通过 RCU 释放页面。 */
		struct rcu_head rcu_head;
	};

	union {		/* 此联合体大小为4字节 */
		/*
		 * 如果页面可以映射到用户空间，编码此页面在页面表中
		 * 被引用的次数。
		 */
		atomic_t _mapcount;

		/*
		 * 如果页面既不是 PageSlab 也不可映射到用户空间，
		 * 存储在这里的值可能有助于确定该页面的用途。
		 * 参见 page-flags.h 中列出的当前存储的页面类型。
		 */
		unsigned int page_type; /* 页面类型 */
	};

	/* 使用计数。*切勿直接使用*。参见 page_ref.h */
	atomic_t _refcount;

#ifdef CONFIG_MEMCG
	unsigned long memcg_data; /* 内存控制组数据 */
#endif

	/*
	 * 在所有 RAM 都映射到内核地址空间的机器上，
	 * 我们可以简单地计算虚拟地址。
	 * 在高内存的机器上，部分内存动态映射到内核虚拟内存，
	 * 因此我们需要一个地方来存储该地址。
	 * 注意：在 x86 上，此字段可能为16位... ;)
	 *
	 * 在乘法较慢的架构上，可以在 asm/page.h 中定义
	 * WANT_PAGE_VIRTUAL。
	 */
#if defined(WANT_PAGE_VIRTUAL)
	void *virtual;			/* 内核虚拟地址（如果未映射，则为NULL，即高内存） */
#endif /* WANT_PAGE_VIRTUAL */

#ifdef LAST_CPUPID_NOT_IN_PAGE_FLAGS
	int _last_cpupid; /* 最后一个 CPU ID */
#endif
} _struct_page_alignment;

/**
 * struct folio - Represents a contiguous set of bytes.
 * @flags: Identical to the page flags.
 * @lru: Least Recently Used list; tracks how recently this folio was used.
 * @mlock_count: Number of times this folio has been pinned by mlock().
 * @mapping: The file this page belongs to, or refers to the anon_vma for
 *    anonymous memory.
 * @index: Offset within the file, in units of pages.  For anonymous memory,
 *    this is the index from the beginning of the mmap.
 * @private: Filesystem per-folio data (see folio_attach_private()).
 *    Used for swp_entry_t if folio_test_swapcache().
 * @_mapcount: Do not access this member directly.  Use folio_mapcount() to
 *    find out how many times this folio is mapped by userspace.
 * @_refcount: Do not access this member directly.  Use folio_ref_count()
 *    to find how many references there are to this folio.
 * @memcg_data: Memory Control Group data.
 *
 * A folio is a physically, virtually and logically contiguous set
 * of bytes.  It is a power-of-two in size, and it is aligned to that
 * same power-of-two.  It is at least as large as %PAGE_SIZE.  If it is
 * in the page cache, it is at a file offset which is a multiple of that
 * power-of-two.  It may be mapped into userspace at an address which is
 * at an arbitrary page offset, but its kernel virtual address is aligned
 * to its size.
 */
struct folio {
	/* private: don't document the anon union */
	union {
		struct {
	/* public: */
			unsigned long flags;
			union {
				struct list_head lru;
	/* private: avoid cluttering the output */
				struct {
					void *__filler;
	/* public: */
					unsigned int mlock_count;
	/* private: */
				};
	/* public: */
			};
			struct address_space *mapping;
			pgoff_t index;
			void *private;
			atomic_t _mapcount;
			atomic_t _refcount;
#ifdef CONFIG_MEMCG
			unsigned long memcg_data;
#endif
	/* private: the union with struct page is transitional */
		};
		struct page page;
	};
};

static_assert(sizeof(struct page) == sizeof(struct folio));
#define FOLIO_MATCH(pg, fl)						\
	static_assert(offsetof(struct page, pg) == offsetof(struct folio, fl))
FOLIO_MATCH(flags, flags);
FOLIO_MATCH(lru, lru);
FOLIO_MATCH(mapping, mapping);
FOLIO_MATCH(compound_head, lru);
FOLIO_MATCH(index, index);
FOLIO_MATCH(private, private);
FOLIO_MATCH(_mapcount, _mapcount);
FOLIO_MATCH(_refcount, _refcount);
#ifdef CONFIG_MEMCG
FOLIO_MATCH(memcg_data, memcg_data);
#endif
#undef FOLIO_MATCH

static inline atomic_t *folio_mapcount_ptr(struct folio *folio)
{
	struct page *tail = &folio->page + 1;
	return &tail->compound_mapcount;
}

static inline atomic_t *compound_mapcount_ptr(struct page *page)
{
	return &page[1].compound_mapcount;
}

static inline atomic_t *compound_pincount_ptr(struct page *page)
{
	return &page[1].compound_pincount;
}

/*
 * Used for sizing the vmemmap region on some architectures
 */
#define STRUCT_PAGE_MAX_SHIFT	(order_base_2(sizeof(struct page)))

#define PAGE_FRAG_CACHE_MAX_SIZE	__ALIGN_MASK(32768, ~PAGE_MASK)
#define PAGE_FRAG_CACHE_MAX_ORDER	get_order(PAGE_FRAG_CACHE_MAX_SIZE)

/*
 * page_private can be used on tail pages.  However, PagePrivate is only
 * checked by the VM on the head page.  So page_private on the tail pages
 * should be used for data that's ancillary to the head page (eg attaching
 * buffer heads to tail pages after attaching buffer heads to the head page)
 */
#define page_private(page)		((page)->private)

static inline void set_page_private(struct page *page, unsigned long private)
{
	page->private = private;
}

static inline void *folio_get_private(struct folio *folio)
{
	return folio->private;
}

struct page_frag_cache {
	void * va;
#if (PAGE_SIZE < PAGE_FRAG_CACHE_MAX_SIZE)
	__u16 offset;
	__u16 size;
#else
	__u32 offset;
#endif
	/* we maintain a pagecount bias, so that we dont dirty cache line
	 * containing page->_refcount every time we allocate a fragment.
	 */
	unsigned int		pagecnt_bias;
	bool pfmemalloc;
};

typedef unsigned long vm_flags_t;

/*
 * A region containing a mapping of a non-memory backed file under NOMMU
 * conditions.  These are held in a global tree and are pinned by the VMAs that
 * map parts of them.
 */
struct vm_region {
	struct rb_node	vm_rb;		/* link in global region tree */
	vm_flags_t	vm_flags;	/* VMA vm_flags */
	unsigned long	vm_start;	/* start address of region */
	unsigned long	vm_end;		/* region initialised to here */
	unsigned long	vm_top;		/* region allocated to here */
	unsigned long	vm_pgoff;	/* the offset in vm_file corresponding to vm_start */
	struct file	*vm_file;	/* the backing file or NULL */

	int		vm_usage;	/* region usage count (access under nommu_region_sem) */
	bool		vm_icache_flushed : 1; /* true if the icache has been flushed for
						* this region */
};

#ifdef CONFIG_USERFAULTFD
#define NULL_VM_UFFD_CTX ((struct vm_userfaultfd_ctx) { NULL, })
struct vm_userfaultfd_ctx {
	struct userfaultfd_ctx *ctx;
};
#else /* CONFIG_USERFAULTFD */
#define NULL_VM_UFFD_CTX ((struct vm_userfaultfd_ctx) {})
struct vm_userfaultfd_ctx {};
#endif /* CONFIG_USERFAULTFD */

struct anon_vma_name {
	struct kref kref;
	/* The name needs to be at the end because it is dynamically sized. */
	char name[];
};

/*
 * This struct describes a virtual memory area. There is one of these
 * per VM-area/task. A VM area is any part of the process virtual memory
 * space that has a special rule for the page-fault handlers (ie a shared
 * library, the executable area etc).
 */
struct vm_area_struct {
	/* The first cache line has the info for VMA tree walking. */

	unsigned long vm_start;		/* Our start address within vm_mm. */
	unsigned long vm_end;		/* The first byte after our end address
					   within vm_mm. */

	/* linked list of VM areas per task, sorted by address */
	struct vm_area_struct *vm_next, *vm_prev;

	struct rb_node vm_rb;

	/*
	 * Largest free memory gap in bytes to the left of this VMA.
	 * Either between this VMA and vma->vm_prev, or between one of the
	 * VMAs below us in the VMA rbtree and its ->vm_prev. This helps
	 * get_unmapped_area find a free area of the right size.
	 */
	unsigned long rb_subtree_gap;

	/* Second cache line starts here. */

	struct mm_struct *vm_mm;	/* The address space we belong to. */

	/*
	 * Access permissions of this VMA.
	 * See vmf_insert_mixed_prot() for discussion.
	 */
	pgprot_t vm_page_prot;
	unsigned long vm_flags;		/* Flags, see mm.h. */

	/*
	 * For areas with an address space and backing store,
	 * linkage into the address_space->i_mmap interval tree.
	 *
	 * For private anonymous mappings, a pointer to a null terminated string
	 * containing the name given to the vma, or NULL if unnamed.
	 */

	union {
		struct {
			struct rb_node rb;
			unsigned long rb_subtree_last;
		} shared;
		/*
		 * Serialized by mmap_sem. Never use directly because it is
		 * valid only when vm_file is NULL. Use anon_vma_name instead.
		 */
		struct anon_vma_name *anon_name;
	};

	/*
	 * A file's MAP_PRIVATE vma can be in both i_mmap tree and anon_vma
	 * list, after a COW of one of the file pages.	A MAP_SHARED vma
	 * can only be in the i_mmap tree.  An anonymous MAP_PRIVATE, stack
	 * or brk vma (with NULL file) can only be in an anon_vma list.
	 */
	struct list_head anon_vma_chain; /* Serialized by mmap_lock &
					  * page_table_lock */
	struct anon_vma *anon_vma;	/* Serialized by page_table_lock */

	/* Function pointers to deal with this struct. */
	const struct vm_operations_struct *vm_ops;

	/* Information about our backing store: */
	unsigned long vm_pgoff;		/* Offset (within vm_file) in PAGE_SIZE
					   units */
	struct file * vm_file;		/* File we map to (can be NULL). */
	void * vm_private_data;		/* was vm_pte (shared mem) */

#ifdef CONFIG_SWAP
	atomic_long_t swap_readahead_info;
#endif
#ifndef CONFIG_MMU
	struct vm_region *vm_region;	/* NOMMU mapping region */
#endif
#ifdef CONFIG_NUMA
	struct mempolicy *vm_policy;	/* NUMA policy for the VMA */
#endif
	struct vm_userfaultfd_ctx vm_userfaultfd_ctx;
} __randomize_layout;

struct kioctx_table;
struct mm_struct {
	struct {
		struct vm_area_struct *mmap;		/* list of VMAs */
		struct rb_root mm_rb;
		u64 vmacache_seqnum;                   /* per-thread vmacache */
#ifdef CONFIG_MMU
		unsigned long (*get_unmapped_area) (struct file *filp,
				unsigned long addr, unsigned long len,
				unsigned long pgoff, unsigned long flags);
#endif
		unsigned long mmap_base;	/* base of mmap area */
		unsigned long mmap_legacy_base;	/* base of mmap area in bottom-up allocations */
#ifdef CONFIG_HAVE_ARCH_COMPAT_MMAP_BASES
		/* Base addresses for compatible mmap() */
		unsigned long mmap_compat_base;
		unsigned long mmap_compat_legacy_base;
#endif
		unsigned long task_size;	/* size of task vm space */
		unsigned long highest_vm_end;	/* highest vma end address */
		pgd_t * pgd;

#ifdef CONFIG_MEMBARRIER
		/**
		 * @membarrier_state: Flags controlling membarrier behavior.
		 *
		 * This field is close to @pgd to hopefully fit in the same
		 * cache-line, which needs to be touched by switch_mm().
		 */
		atomic_t membarrier_state;
#endif

		/**
		 * @mm_users: The number of users including userspace.
		 *
		 * Use mmget()/mmget_not_zero()/mmput() to modify. When this
		 * drops to 0 (i.e. when the task exits and there are no other
		 * temporary reference holders), we also release a reference on
		 * @mm_count (which may then free the &struct mm_struct if
		 * @mm_count also drops to 0).
		 */
		atomic_t mm_users;

		/**
		 * @mm_count: The number of references to &struct mm_struct
		 * (@mm_users count as 1).
		 *
		 * Use mmgrab()/mmdrop() to modify. When this drops to 0, the
		 * &struct mm_struct is freed.
		 */
		atomic_t mm_count;

#ifdef CONFIG_MMU
		atomic_long_t pgtables_bytes;	/* PTE page table pages */
#endif
		int map_count;			/* number of VMAs */

		spinlock_t page_table_lock; /* Protects page tables and some
					     * counters
					     */
		/*
		 * With some kernel config, the current mmap_lock's offset
		 * inside 'mm_struct' is at 0x120, which is very optimal, as
		 * its two hot fields 'count' and 'owner' sit in 2 different
		 * cachelines,  and when mmap_lock is highly contended, both
		 * of the 2 fields will be accessed frequently, current layout
		 * will help to reduce cache bouncing.
		 *
		 * So please be careful with adding new fields before
		 * mmap_lock, which can easily push the 2 fields into one
		 * cacheline.
		 */
		struct rw_semaphore mmap_lock;

		struct list_head mmlist; /* List of maybe swapped mm's.	These
					  * are globally strung together off
					  * init_mm.mmlist, and are protected
					  * by mmlist_lock
					  */


		unsigned long hiwater_rss; /* High-watermark of RSS usage */
		unsigned long hiwater_vm;  /* High-water virtual memory usage */

		unsigned long total_vm;	   /* Total pages mapped */
		unsigned long locked_vm;   /* Pages that have PG_mlocked set */
		atomic64_t    pinned_vm;   /* Refcount permanently increased */
		unsigned long data_vm;	   /* VM_WRITE & ~VM_SHARED & ~VM_STACK */
		unsigned long exec_vm;	   /* VM_EXEC & ~VM_WRITE & ~VM_STACK */
		unsigned long stack_vm;	   /* VM_STACK */
		unsigned long def_flags;

		/**
		 * @write_protect_seq: Locked when any thread is write
		 * protecting pages mapped by this mm to enforce a later COW,
		 * for instance during page table copying for fork().
		 */
		seqcount_t write_protect_seq;

		spinlock_t arg_lock; /* protect the below fields */

		unsigned long start_code, end_code, start_data, end_data;
		unsigned long start_brk, brk, start_stack;
		unsigned long arg_start, arg_end, env_start, env_end;

		unsigned long saved_auxv[AT_VECTOR_SIZE]; /* for /proc/PID/auxv */

		/*
		 * Special counters, in some configurations protected by the
		 * page_table_lock, in other configurations by being atomic.
		 */
		struct mm_rss_stat rss_stat;

		struct linux_binfmt *binfmt;

		/* Architecture-specific MM context */
		mm_context_t context;

		unsigned long flags; /* Must use atomic bitops to access */

#ifdef CONFIG_AIO
		spinlock_t			ioctx_lock;
		struct kioctx_table __rcu	*ioctx_table;
#endif
#ifdef CONFIG_MEMCG
		/*
		 * "owner" points to a task that is regarded as the canonical
		 * user/owner of this mm. All of the following must be true in
		 * order for it to be changed:
		 *
		 * current == mm->owner
		 * current->mm != mm
		 * new_owner->mm == mm
		 * new_owner->alloc_lock is held
		 */
		struct task_struct __rcu *owner;
#endif
		struct user_namespace *user_ns;

		/* store ref to file /proc/<pid>/exe symlink points to */
		struct file __rcu *exe_file;
#ifdef CONFIG_MMU_NOTIFIER
		struct mmu_notifier_subscriptions *notifier_subscriptions;
#endif
#if defined(CONFIG_TRANSPARENT_HUGEPAGE) && !USE_SPLIT_PMD_PTLOCKS
		pgtable_t pmd_huge_pte; /* protected by page_table_lock */
#endif
#ifdef CONFIG_NUMA_BALANCING
		/*
		 * numa_next_scan is the next time that the PTEs will be marked
		 * pte_numa. NUMA hinting faults will gather statistics and
		 * migrate pages to new nodes if necessary.
		 */
		unsigned long numa_next_scan;

		/* Restart point for scanning and setting pte_numa */
		unsigned long numa_scan_offset;

		/* numa_scan_seq prevents two threads setting pte_numa */
		int numa_scan_seq;
#endif
		/*
		 * An operation with batched TLB flushing is going on. Anything
		 * that can move process memory needs to flush the TLB when
		 * moving a PROT_NONE or PROT_NUMA mapped page.
		 */
		atomic_t tlb_flush_pending;
#ifdef CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH
		/* See flush_tlb_batched_pending() */
		atomic_t tlb_flush_batched;
#endif
		struct uprobes_state uprobes_state;
#ifdef CONFIG_PREEMPT_RT
		struct rcu_head delayed_drop;
#endif
#ifdef CONFIG_HUGETLB_PAGE
		atomic_long_t hugetlb_usage;
#endif
		struct work_struct async_put_work;

#ifdef CONFIG_IOMMU_SVA
		u32 pasid;
#endif
#ifdef CONFIG_KSM
		/*
		 * Represent how many pages of this process are involved in KSM
		 * merging.
		 */
		unsigned long ksm_merging_pages;
#endif
	} __randomize_layout;

	/*
	 * The mm_cpumask needs to be at the end of mm_struct, because it
	 * is dynamically sized based on nr_cpu_ids.
	 */
	unsigned long cpu_bitmap[];
};

extern struct mm_struct init_mm;

/* Pointer magic because the dynamic array size confuses some compilers. */
static inline void mm_init_cpumask(struct mm_struct *mm)
{
	unsigned long cpu_bitmap = (unsigned long)mm;

	cpu_bitmap += offsetof(struct mm_struct, cpu_bitmap);
	cpumask_clear((struct cpumask *)cpu_bitmap);
}

/* Future-safe accessor for struct mm_struct's cpu_vm_mask. */
static inline cpumask_t *mm_cpumask(struct mm_struct *mm)
{
	return (struct cpumask *)&mm->cpu_bitmap;
}

struct mmu_gather;
extern void tlb_gather_mmu(struct mmu_gather *tlb, struct mm_struct *mm);
extern void tlb_gather_mmu_fullmm(struct mmu_gather *tlb, struct mm_struct *mm);
extern void tlb_finish_mmu(struct mmu_gather *tlb);

struct vm_fault;

/**
 * typedef vm_fault_t - Return type for page fault handlers.
 *
 * Page fault handlers return a bitmask of %VM_FAULT values.
 */
typedef __bitwise unsigned int vm_fault_t;

/**
 * enum vm_fault_reason - Page fault handlers return a bitmask of
 * these values to tell the core VM what happened when handling the
 * fault. Used to decide whether a process gets delivered SIGBUS or
 * just gets major/minor fault counters bumped up.
 *
 * @VM_FAULT_OOM:		Out Of Memory
 * @VM_FAULT_SIGBUS:		Bad access
 * @VM_FAULT_MAJOR:		Page read from storage
 * @VM_FAULT_WRITE:		Special case for get_user_pages
 * @VM_FAULT_HWPOISON:		Hit poisoned small page
 * @VM_FAULT_HWPOISON_LARGE:	Hit poisoned large page. Index encoded
 *				in upper bits
 * @VM_FAULT_SIGSEGV:		segmentation fault
 * @VM_FAULT_NOPAGE:		->fault installed the pte, not return page
 * @VM_FAULT_LOCKED:		->fault locked the returned page
 * @VM_FAULT_RETRY:		->fault blocked, must retry
 * @VM_FAULT_FALLBACK:		huge page fault failed, fall back to small
 * @VM_FAULT_DONE_COW:		->fault has fully handled COW
 * @VM_FAULT_NEEDDSYNC:		->fault did not modify page tables and needs
 *				fsync() to complete (for synchronous page faults
 *				in DAX)
 * @VM_FAULT_HINDEX_MASK:	mask HINDEX value
 *
 */
enum vm_fault_reason {
	VM_FAULT_OOM            = (__force vm_fault_t)0x000001,
	VM_FAULT_SIGBUS         = (__force vm_fault_t)0x000002,
	VM_FAULT_MAJOR          = (__force vm_fault_t)0x000004,
	VM_FAULT_WRITE          = (__force vm_fault_t)0x000008,
	VM_FAULT_HWPOISON       = (__force vm_fault_t)0x000010,
	VM_FAULT_HWPOISON_LARGE = (__force vm_fault_t)0x000020,
	VM_FAULT_SIGSEGV        = (__force vm_fault_t)0x000040,
	VM_FAULT_NOPAGE         = (__force vm_fault_t)0x000100,
	VM_FAULT_LOCKED         = (__force vm_fault_t)0x000200,
	VM_FAULT_RETRY          = (__force vm_fault_t)0x000400,
	VM_FAULT_FALLBACK       = (__force vm_fault_t)0x000800,
	VM_FAULT_DONE_COW       = (__force vm_fault_t)0x001000,
	VM_FAULT_NEEDDSYNC      = (__force vm_fault_t)0x002000,
	VM_FAULT_HINDEX_MASK    = (__force vm_fault_t)0x0f0000,
};

/* Encode hstate index for a hwpoisoned large page */
#define VM_FAULT_SET_HINDEX(x) ((__force vm_fault_t)((x) << 16))
#define VM_FAULT_GET_HINDEX(x) (((__force unsigned int)(x) >> 16) & 0xf)

#define VM_FAULT_ERROR (VM_FAULT_OOM | VM_FAULT_SIGBUS |	\
			VM_FAULT_SIGSEGV | VM_FAULT_HWPOISON |	\
			VM_FAULT_HWPOISON_LARGE | VM_FAULT_FALLBACK)

#define VM_FAULT_RESULT_TRACE \
	{ VM_FAULT_OOM,                 "OOM" },	\
	{ VM_FAULT_SIGBUS,              "SIGBUS" },	\
	{ VM_FAULT_MAJOR,               "MAJOR" },	\
	{ VM_FAULT_WRITE,               "WRITE" },	\
	{ VM_FAULT_HWPOISON,            "HWPOISON" },	\
	{ VM_FAULT_HWPOISON_LARGE,      "HWPOISON_LARGE" },	\
	{ VM_FAULT_SIGSEGV,             "SIGSEGV" },	\
	{ VM_FAULT_NOPAGE,              "NOPAGE" },	\
	{ VM_FAULT_LOCKED,              "LOCKED" },	\
	{ VM_FAULT_RETRY,               "RETRY" },	\
	{ VM_FAULT_FALLBACK,            "FALLBACK" },	\
	{ VM_FAULT_DONE_COW,            "DONE_COW" },	\
	{ VM_FAULT_NEEDDSYNC,           "NEEDDSYNC" }

struct vm_special_mapping {
	const char *name;	/* The name, e.g. "[vdso]". */

	/*
	 * If .fault is not provided, this points to a
	 * NULL-terminated array of pages that back the special mapping.
	 *
	 * This must not be NULL unless .fault is provided.
	 */
	struct page **pages;

	/*
	 * If non-NULL, then this is called to resolve page faults
	 * on the special mapping.  If used, .pages is not checked.
	 */
	vm_fault_t (*fault)(const struct vm_special_mapping *sm,
				struct vm_area_struct *vma,
				struct vm_fault *vmf);

	int (*mremap)(const struct vm_special_mapping *sm,
		     struct vm_area_struct *new_vma);
};

enum tlb_flush_reason {
	TLB_FLUSH_ON_TASK_SWITCH,
	TLB_REMOTE_SHOOTDOWN,
	TLB_LOCAL_SHOOTDOWN,
	TLB_LOCAL_MM_SHOOTDOWN,
	TLB_REMOTE_SEND_IPI,
	NR_TLB_FLUSH_REASONS,
};

 /*
  * A swap entry has to fit into a "unsigned long", as the entry is hidden
  * in the "index" field of the swapper address space.
  */
typedef struct {
	unsigned long val;
} swp_entry_t;

/**
 * enum fault_flag - Fault flag definitions.
 * @FAULT_FLAG_WRITE: Fault was a write fault.
 * @FAULT_FLAG_MKWRITE: Fault was mkwrite of existing PTE.
 * @FAULT_FLAG_ALLOW_RETRY: Allow to retry the fault if blocked.
 * @FAULT_FLAG_RETRY_NOWAIT: Don't drop mmap_lock and wait when retrying.
 * @FAULT_FLAG_KILLABLE: The fault task is in SIGKILL killable region.
 * @FAULT_FLAG_TRIED: The fault has been tried once.
 * @FAULT_FLAG_USER: The fault originated in userspace.
 * @FAULT_FLAG_REMOTE: The fault is not for current task/mm.
 * @FAULT_FLAG_INSTRUCTION: The fault was during an instruction fetch.
 * @FAULT_FLAG_INTERRUPTIBLE: The fault can be interrupted by non-fatal signals.
 * @FAULT_FLAG_UNSHARE: The fault is an unsharing request to unshare (and mark
 *                      exclusive) a possibly shared anonymous page that is
 *                      mapped R/O.
 * @FAULT_FLAG_ORIG_PTE_VALID: whether the fault has vmf->orig_pte cached.
 *                        We should only access orig_pte if this flag set.
 *
 * About @FAULT_FLAG_ALLOW_RETRY and @FAULT_FLAG_TRIED: we can specify
 * whether we would allow page faults to retry by specifying these two
 * fault flags correctly.  Currently there can be three legal combinations:
 *
 * (a) ALLOW_RETRY and !TRIED:  this means the page fault allows retry, and
 *                              this is the first try
 *
 * (b) ALLOW_RETRY and TRIED:   this means the page fault allows retry, and
 *                              we've already tried at least once
 *
 * (c) !ALLOW_RETRY and !TRIED: this means the page fault does not allow retry
 *
 * The unlisted combination (!ALLOW_RETRY && TRIED) is illegal and should never
 * be used.  Note that page faults can be allowed to retry for multiple times,
 * in which case we'll have an initial fault with flags (a) then later on
 * continuous faults with flags (b).  We should always try to detect pending
 * signals before a retry to make sure the continuous page faults can still be
 * interrupted if necessary.
 *
 * The combination FAULT_FLAG_WRITE|FAULT_FLAG_UNSHARE is illegal.
 * FAULT_FLAG_UNSHARE is ignored and treated like an ordinary read fault when
 * no existing R/O-mapped anonymous page is encountered.
 */
enum fault_flag {
	FAULT_FLAG_WRITE =		1 << 0,
	FAULT_FLAG_MKWRITE =		1 << 1,
	FAULT_FLAG_ALLOW_RETRY =	1 << 2,
	FAULT_FLAG_RETRY_NOWAIT = 	1 << 3,
	FAULT_FLAG_KILLABLE =		1 << 4,
	FAULT_FLAG_TRIED = 		1 << 5,
	FAULT_FLAG_USER =		1 << 6,
	FAULT_FLAG_REMOTE =		1 << 7,
	FAULT_FLAG_INSTRUCTION =	1 << 8,
	FAULT_FLAG_INTERRUPTIBLE =	1 << 9,
	FAULT_FLAG_UNSHARE =		1 << 10,
	FAULT_FLAG_ORIG_PTE_VALID =	1 << 11,
};

typedef unsigned int __bitwise zap_flags_t;

#endif /* _LINUX_MM_TYPES_H */
