/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _M68K_PAGE_NO_H
#define _M68K_PAGE_NO_H

#ifndef __ASSEMBLY__

// 定义内存起始和结束地址
extern unsigned long memory_start;
extern unsigned long memory_end;

// 将一个页面清零
#define clear_page(page)	memset((page), 0, PAGE_SIZE)
// 复制一个页面的数据
#define copy_page(to, from)	memcpy((to), (from), PAGE_SIZE)

// 清空用户页面，通常与用户空间相关
#define clear_user_page(page, vaddr, pg)	clear_page(page)
// 复制用户页面，通常与用户空间相关
#define copy_user_page(to, from, vaddr, pg)	copy_page(to, from)

// 分配并清零一个用户高页，支持可移动的高内存
#define alloc_zeroed_user_highpage_movable(vma, vaddr) \
	alloc_page_vma(GFP_HIGHUSER_MOVABLE | __GFP_ZERO, vma, vaddr)
// 指示此架构支持分配已清零的用户高页
#define __HAVE_ARCH_ALLOC_ZEROED_USER_HIGHPAGE_MOVABLE

// 虚拟地址转换为物理地址
#define __pa(vaddr)		((unsigned long)(vaddr))
// 物理地址转换为虚拟地址
#define __va(paddr)		((void *)((unsigned long)(paddr)))

// 将虚拟地址转换为页面帧号（PFN）
#define virt_to_pfn(kaddr)	(__pa(kaddr) >> PAGE_SHIFT)
// 将页面帧号转换为虚拟地址
#define pfn_to_virt(pfn)	__va((pfn) << PAGE_SHIFT)

// 将虚拟地址转换为页结构体指针
#define virt_to_page(addr)	(mem_map + (((unsigned long)(addr)-PAGE_OFFSET) >> PAGE_SHIFT))
// 将页结构体指针转换为虚拟地址
#define page_to_virt(page)	__va(((((page) - mem_map) << PAGE_SHIFT) + PAGE_OFFSET))

// 将页面帧号转换为页结构体指针
#define pfn_to_page(pfn)	virt_to_page(pfn_to_virt(pfn))
// 将页结构体指针转换为页面帧号
#define page_to_pfn(page)	virt_to_pfn(page_to_virt(page))
// 检查页面帧号是否有效
#define pfn_valid(pfn)	        ((pfn) < max_mapnr)

// 检查虚拟地址是否有效
#define	virt_addr_valid(kaddr)	(((unsigned long)(kaddr) >= PAGE_OFFSET) && \
				((unsigned long)(kaddr) < memory_end))

#endif /* __ASSEMBLY__ */

#endif /* _M68K_PAGE_NO_H */
