/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_PATH_H
#define _LINUX_PATH_H

struct dentry;
struct vfsmount;
//struct path 是 Linux 内核中用于描述一个完整路径（路径名）所关联的文件系统和目录项的结构体
struct path {
	struct vfsmount *mnt;   // 指向路径所在挂载点的指针
	struct dentry *dentry; // 指向路径最后一个组件的目录项
} __randomize_layout;


extern void path_get(const struct path *);
extern void path_put(const struct path *);

static inline int path_equal(const struct path *path1, const struct path *path2)
{
	return path1->mnt == path2->mnt && path1->dentry == path2->dentry;
}

static inline void path_put_init(struct path *path)
{
	path_put(path);
	*path = (struct path) { };
}

#endif  /* _LINUX_PATH_H */
