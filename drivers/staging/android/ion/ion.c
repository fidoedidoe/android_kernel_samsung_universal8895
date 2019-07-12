// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2011 Google, Inc.
 * Copyright (c) 2011-2018, The Linux Foundation. All rights reserved.
 * Copyright (C) 2019 Sultan Alsawaf <sultan@kerneltoast.com>.
 */

#include <linux/atomic.h>
#include <linux/dma-buf.h>
#include <linux/memblock.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <linux/exynos_iovmm.h>
#include <linux/exynos_ion.h>
#include <linux/highmem.h>

#define CREATE_TRACE_POINTS
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>

#include "ion.h"
#include "ion_priv.h"
#include "compat_ion.h"

struct ion_device {
	struct miscdevice dev;
	struct plist_head heaps;
	struct rw_semaphore heap_lock;
	long (*custom_ioctl)(struct ion_client *client, unsigned int cmd,
			     unsigned long arg);
};

struct ion_client {
	struct ion_device *dev;
	struct rb_root handles;
	struct rb_node node;
	struct idr idr;
	rwlock_t idr_lock;
	rwlock_t rb_lock;
};

struct ion_handle {
	unsigned int user_ref_count;
	struct ion_buffer *buffer;
	struct ion_client *client;
	struct rb_node node;
	atomic_t kmap_cnt;
	atomic_t refcount;
	int id;
};

struct ion_vma_list {
	struct list_head list;
	struct vm_area_struct *vma;
};

static struct page *ion_buffer_page(struct page *page)
{
	return (struct page *)((unsigned long)page & ~(1UL));
}

static bool ion_buffer_page_is_dirty(struct page *page)
{
	return (unsigned long)page & 1UL;
}

static void ion_buffer_page_dirty(struct page **page)
{
	*page = (struct page *)((unsigned long)(*page) | 1UL);
}

static void ion_buffer_page_clean(struct page **page)
{
	*page = (struct page *)((unsigned long)(*page) & ~(1UL));
}

/* Exynos-specific dummy functions */
#define ION_EVENT_ALLOC(buffer, begin)			do { } while (0)
#define ION_EVENT_FREE(buffer, begin)			do { } while (0)
#define ION_EVENT_MMAP(buffer, begin)			do { } while (0)
#define ion_buffer_set_task_info(buffer)		do { } while (0)
#define ion_buffer_task_add(buffer, master)		do { } while (0)
#define ion_buffer_task_add_lock(buffer, master)	do { } while (0)
#define ion_buffer_task_remove(buffer, master)		do { } while (0)
#define ion_buffer_task_remove_lock(buffer, master)	do { } while (0)
#define ion_buffer_task_remove_all(buffer)		do { } while (0)

static struct ion_buffer *ion_buffer_create(struct ion_heap *heap,
					    struct ion_device *dev,
					    unsigned long len,
					    unsigned long align,
					    unsigned long flags)
{
	struct ion_buffer *buffer;
	struct scatterlist *sg;
	struct sg_table *table;
	int i, ret;

	buffer = kmalloc(sizeof(*buffer), GFP_KERNEL);
	if (!buffer)
		return ERR_PTR(-ENOMEM);

	*buffer = (typeof(*buffer)){
		.dev = dev,
		.heap = heap,
		.flags = flags,
		.size = len,
		.vmas = LIST_HEAD_INIT(buffer->vmas),
		.iovas = LIST_HEAD_INIT(buffer->iovas),
		.kmap_lock = __MUTEX_INITIALIZER(buffer->kmap_lock),
		.page_lock = __MUTEX_INITIALIZER(buffer->page_lock),
		.vma_lock = __MUTEX_INITIALIZER(buffer->vma_lock),
		.ref = {
			.refcount = ATOMIC_INIT(1)
		}
	};

	ret = heap->ops->allocate(heap, buffer, len, align, flags);
	if (ret) {
		if (!(heap->flags & ION_HEAP_FLAG_DEFER_FREE))
			goto free_buffer;

		ion_heap_freelist_drain(heap, 0);
		ret = heap->ops->allocate(heap, buffer, len, align, flags);
		if (ret)
			goto free_buffer;
	}

	table = heap->ops->map_dma(heap, buffer);
	if (IS_ERR_OR_NULL(table))
		goto free_heap;

	buffer->sg_table = table;
	if (ion_buffer_fault_user_mappings(buffer)) {
		int num_pages = PAGE_ALIGN(buffer->size) / PAGE_SIZE;
		int j, k = 0;

		buffer->pages = vmalloc(sizeof(*buffer->pages) * num_pages);
		if (!buffer->pages)
			goto unmap_dma;

		for_each_sg(table->sgl, sg, table->nents, i) {
			struct page *page = sg_page(sg);

			for (j = 0; j < sg->length / PAGE_SIZE; j++)
				buffer->pages[k++] = page++;
		}
	}

	for_each_sg(buffer->sg_table->sgl, sg, buffer->sg_table->nents, i) {
		sg_dma_address(sg) = sg_phys(sg);
		sg_dma_len(sg) = sg->length;
	}

	return buffer;

unmap_dma:
	heap->ops->unmap_dma(heap, buffer);
free_heap:
	heap->ops->free(buffer);
free_buffer:
	kfree(buffer);
	return ERR_PTR(-EINVAL);
}

void ion_buffer_destroy(struct ion_buffer *buffer)
{
	struct ion_iovm_map *iovm_map;
	struct ion_iovm_map *tmp;

	if (buffer->kmap_cnt > 0)
		buffer->heap->ops->unmap_kernel(buffer->heap, buffer);

	list_for_each_entry_safe(iovm_map, tmp, &buffer->iovas, list) {
		iovmm_unmap(iovm_map->dev, iovm_map->iova);
		list_del(&iovm_map->list);
		kfree(iovm_map);
	}

	buffer->heap->ops->unmap_dma(buffer->heap, buffer);
	buffer->heap->ops->free(buffer);
	if (ion_buffer_fault_user_mappings(buffer))
		vfree(buffer->pages);
	kfree(buffer);
}

static void ion_buffer_kref_destroy(struct kref *kref)
{
	struct ion_buffer *buffer = container_of(kref, typeof(*buffer), ref);
	struct ion_heap *heap = buffer->heap;

	if (heap->flags & ION_HEAP_FLAG_DEFER_FREE)
		ion_heap_freelist_add(heap, buffer);
	else
		ion_buffer_destroy(buffer);
}

static struct ion_handle *ion_handle_create(struct ion_client *client,
					    struct ion_buffer *buffer)
{
	struct ion_handle *handle;

	handle = kmalloc(sizeof(*handle), GFP_KERNEL);
	if (!handle)
		return ERR_PTR(-ENOMEM);

	*handle = (typeof(*handle)){
		.buffer = buffer,
		.client = client,
		.kmap_cnt = ATOMIC_INIT(0),
		.refcount = ATOMIC_INIT(1)
	};

	return handle;
}

static void *ion_buffer_kmap_get(struct ion_buffer *buffer)
{
	void *vaddr;

	mutex_lock(&buffer->kmap_lock);
	if (buffer->kmap_cnt) {
		vaddr = buffer->vaddr;
		buffer->kmap_cnt++;
	} else {
		vaddr = buffer->heap->ops->map_kernel(buffer->heap, buffer);
		if (IS_ERR_OR_NULL(vaddr)) {
			vaddr = ERR_PTR(-EINVAL);
		} else {
			buffer->vaddr = vaddr;
			buffer->kmap_cnt++;
		}
	}
	mutex_unlock(&buffer->kmap_lock);

	return vaddr;
}

static void ion_buffer_kmap_put(struct ion_buffer *buffer)
{
	mutex_lock(&buffer->kmap_lock);
	if (!--buffer->kmap_cnt) {
		buffer->heap->ops->unmap_kernel(buffer->heap, buffer);
		buffer->vaddr = NULL;
	}
	mutex_unlock(&buffer->kmap_lock);
}

static void *ion_handle_kmap_get(struct ion_handle *handle)
{
	struct ion_buffer *buffer = handle->buffer;
	void *objp;

	objp = ion_buffer_kmap_get(buffer);
	if (!IS_ERR(objp))
		atomic_inc(&handle->kmap_cnt);

	return objp;
}

static void ion_handle_kmap_put(struct ion_handle *handle)
{
	struct ion_buffer *buffer = handle->buffer;

	if (atomic_add_unless(&handle->kmap_cnt, -1, 0))
		ion_buffer_kmap_put(buffer);
}

static void ion_handle_get(struct ion_handle *handle)
{
	atomic_inc(&handle->refcount);
}

bool ion_handle_validate(struct ion_client *client, struct ion_handle *handle)
{
	bool found;

	read_lock(&client->idr_lock);
	found = idr_find(&client->idr, handle->id) == handle;
	read_unlock(&client->idr_lock);

	return found;
}

void *ion_map_kernel(struct ion_client *client, struct ion_handle *handle)
{
	struct ion_buffer *buffer;

	if (!ion_handle_validate(client, handle))
		return ERR_PTR(-EINVAL);

	buffer = handle->buffer;
	if (!buffer->heap->ops->map_kernel)
		return ERR_PTR(-ENODEV);

	return ion_handle_kmap_get(handle);
}

void ion_unmap_kernel(struct ion_client *client, struct ion_handle *handle)
{
	if (ion_handle_validate(client, handle))
		ion_handle_kmap_put(handle);
}

void ion_handle_put(struct ion_handle *handle)
{
	struct ion_client *client = handle->client;
	struct ion_buffer *buffer = handle->buffer;

	if (atomic_dec_return(&handle->refcount))
		return;

	write_lock(&client->idr_lock);
	idr_remove(&client->idr, handle->id);
	write_unlock(&client->idr_lock);

	write_lock(&client->rb_lock);
	rb_erase(&handle->node, &client->handles);
	write_unlock(&client->rb_lock);

	ion_handle_kmap_put(handle);
	kref_put(&buffer->ref, ion_buffer_kref_destroy);
	kfree(handle);
}

static struct ion_handle *ion_handle_lookup_get(struct ion_client *client,
						struct ion_buffer *buffer)
{
	struct rb_node **p = &client->handles.rb_node;
	struct ion_handle *entry;

	read_lock(&client->rb_lock);
	while (*p) {
		entry = rb_entry(*p, typeof(*entry), node);
		if (buffer < entry->buffer) {
			p = &(*p)->rb_left;
		} else if (buffer > entry->buffer) {
			p = &(*p)->rb_right;
		} else {
			read_unlock(&client->rb_lock);
			ion_handle_get(entry);
			return entry;
		}
	}
	read_unlock(&client->rb_lock);

	return ERR_PTR(-EINVAL);
}

struct ion_handle *ion_handle_find_by_id(struct ion_client *client, int id)
{
	struct ion_handle *handle;

	read_lock(&client->idr_lock);
	handle = idr_find(&client->idr, id);
	read_unlock(&client->idr_lock);

	return handle ? handle : ERR_PTR(-EINVAL);
}

static int ion_handle_add(struct ion_client *client, struct ion_handle *handle)
{
	struct rb_node **p = &client->handles.rb_node;
	struct ion_buffer *buffer = handle->buffer;
	struct rb_node *parent = NULL;
	struct ion_handle *entry;
	int id;

	idr_preload(GFP_KERNEL);
	write_lock(&client->idr_lock);
	id = idr_alloc(&client->idr, handle, 1, 0, GFP_NOWAIT);
	write_unlock(&client->idr_lock);
	idr_preload_end();

	if (id < 0)
		return id;

	handle->id = id;

	write_lock(&client->rb_lock);
	while (*p) {
		parent = *p;
		entry = rb_entry(parent, typeof(*entry), node);
		if (buffer < entry->buffer)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}
	rb_link_node(&handle->node, parent, p);
	rb_insert_color(&handle->node, &client->handles);
	write_unlock(&client->rb_lock);

	return 0;
}

unsigned int ion_parse_heap_id(unsigned int heap_id_mask, unsigned int flags);

struct ion_handle *ion_alloc(struct ion_client *client, size_t len,
			     size_t align, unsigned int heap_id_mask,
			     unsigned int flags)
{
	struct ion_device *dev = client->dev;
	struct ion_buffer *buffer = NULL;
	struct ion_handle *handle;
	struct ion_heap *heap;

	len = PAGE_ALIGN(len);
	if (!len)
		return ERR_PTR(-EINVAL);

	down_read(&dev->heap_lock);
	heap_id_mask = ion_parse_heap_id(heap_id_mask, flags);
	if (heap_id_mask == 0)
		return ERR_PTR(-EINVAL);

	plist_for_each_entry(heap, &dev->heaps, node) {
		if (!(BIT(heap->id) & heap_id_mask))
			continue;

		buffer = ion_buffer_create(heap, dev, len, align, flags);
		if (!IS_ERR(buffer))
			break;
	}
	up_read(&dev->heap_lock);

	if (IS_ERR_OR_NULL(buffer))
		return ERR_PTR(-EINVAL);

	handle = ion_handle_create(client, buffer);
	if (IS_ERR(handle)) {
		kref_put(&buffer->ref, ion_buffer_kref_destroy);
		return ERR_PTR(-EINVAL);
	}

	if (ion_handle_add(client, handle)) {
		/* ion_handle_put will put the buffer as well */
		ion_handle_put(handle);
		return ERR_PTR(-EINVAL);
	}

	return handle;
}

void ion_free(struct ion_client *client, struct ion_handle *handle)
{
	if (ion_handle_validate(client, handle))
		ion_handle_put(handle);
}

int ion_phys(struct ion_client *client, struct ion_handle *handle,
	     ion_phys_addr_t *addr, size_t *len)
{
	struct ion_buffer *buffer;

	if (!ion_handle_validate(client, handle))
		return -EINVAL;

	buffer = handle->buffer;
	if (!buffer->heap->ops->phys)
		return -ENODEV;

	return buffer->heap->ops->phys(buffer->heap, buffer, addr, len);
}

struct ion_client *ion_client_create(struct ion_device *dev)
{
	struct ion_client *client;

	client = kmalloc(sizeof(*client), GFP_KERNEL);
	if (!client)
		return ERR_PTR(-ENOMEM);

	*client = (typeof(*client)){
		.dev = dev,
		.handles = RB_ROOT,
		.idr = IDR_INIT(client->idr),
		.idr_lock = __RW_LOCK_UNLOCKED(client->idr_lock),
		.rb_lock = __RW_LOCK_UNLOCKED(client->rb_lock)
	};

	return client;
}

void ion_client_destroy(struct ion_client *client)
{
	struct ion_handle *handle;
	struct rb_node *n;

	while ((n = rb_first(&client->handles))) {
		handle = rb_entry(n, typeof(*handle), node);
		ion_handle_put(handle);
	}

	idr_destroy(&client->idr);
	kfree(client);
}

int ion_handle_get_flags(struct ion_client *client, struct ion_handle *handle,
			 unsigned long *flags)
{
	struct ion_buffer *buffer;

	if (!ion_handle_validate(client, handle))
		return -EINVAL;

	buffer = handle->buffer;
	*flags = buffer->flags;
	return 0;
}

int ion_handle_get_size(struct ion_client *client, struct ion_handle *handle,
			size_t *size)
{
	struct ion_buffer *buffer;

	if (!ion_handle_validate(client, handle))
		return -EINVAL;

	buffer = handle->buffer;
	*size = buffer->size;
	return 0;
}

struct sg_table *ion_sg_table(struct ion_client *client,
			      struct ion_handle *handle)
{
	struct ion_buffer *buffer;
	struct sg_table *table;

	if (!ion_handle_validate(client, handle))
		return ERR_PTR(-EINVAL);

	buffer = handle->buffer;
	table = buffer->sg_table;
	return table;
}

void ion_pages_sync_for_device(struct device *dev, struct page *page,
			       size_t size, enum dma_data_direction dir)
{
	struct scatterlist sg;

	sg_init_table(&sg, 1);
	sg_set_page(&sg, page, size, 0);
	sg_dma_address(&sg) = page_to_phys(page);
	dma_sync_sg_for_device(dev, &sg, 1, dir);
}

static void ion_buffer_sync_for_device(struct ion_buffer *buffer,
				       struct device *dev,
				       enum dma_data_direction dir)
{
	struct ion_vma_list *vma_list;
	int i, pages;

	if (!ion_buffer_cached(buffer))		
		return;

	if (!ion_buffer_fault_user_mappings(buffer))
		return;

	pages = PAGE_ALIGN(buffer->size) / PAGE_SIZE;
	mutex_lock(&buffer->page_lock);
	for (i = 0; i < pages; i++) {
		struct page *page = buffer->pages[i];

		if (ion_buffer_page_is_dirty(page))
			ion_pages_sync_for_device(dev, ion_buffer_page(page),
						  PAGE_SIZE, dir);

		ion_buffer_page_clean(buffer->pages + i);
	}
	mutex_unlock(&buffer->page_lock);

	mutex_lock(&buffer->vma_lock);
	list_for_each_entry(vma_list, &buffer->vmas, list) {
		struct vm_area_struct *vma = vma_list->vma;

		zap_page_range(vma, vma->vm_start, vma->vm_end - vma->vm_start,
			       NULL);
	}
	mutex_unlock(&buffer->vma_lock);
}

static struct sg_table *ion_map_dma_buf(struct dma_buf_attachment *attachment,
					enum dma_data_direction direction)
{
	struct dma_buf *dmabuf = attachment->dmabuf;
	struct ion_buffer *buffer = dmabuf->priv;

	ion_buffer_sync_for_device(buffer, attachment->dev, direction);
	return buffer->sg_table;
}

static void ion_unmap_dma_buf(struct dma_buf_attachment *attachment,
			      struct sg_table *table,
			      enum dma_data_direction direction)
{
}

static int ion_vm_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct ion_buffer *buffer = vma->vm_private_data;
	unsigned long pfn;
	int ret;

	mutex_lock(&buffer->page_lock);
	ion_buffer_page_dirty(buffer->pages + vmf->pgoff);
	pfn = page_to_pfn(ion_buffer_page(buffer->pages[vmf->pgoff]));
	ret = vm_insert_pfn(vma, (unsigned long)vmf->virtual_address, pfn);
	mutex_unlock(&buffer->page_lock);

	return ret ? VM_FAULT_ERROR : VM_FAULT_NOPAGE;
}

static void ion_vm_open(struct vm_area_struct *vma)
{
	struct ion_buffer *buffer = vma->vm_private_data;
	struct ion_vma_list *vma_list;

	vma_list = kmalloc(sizeof(*vma_list), GFP_KERNEL);
	if (!vma_list)
		return;

	vma_list->vma = vma;

	mutex_lock(&buffer->vma_lock);
	list_add(&vma_list->list, &buffer->vmas);
	mutex_unlock(&buffer->vma_lock);
}

static void ion_vm_close(struct vm_area_struct *vma)
{
	struct ion_buffer *buffer = vma->vm_private_data;
	struct ion_vma_list *vma_list;

	mutex_lock(&buffer->vma_lock);
	list_for_each_entry(vma_list, &buffer->vmas, list) {
		if (vma_list->vma == vma) {
			list_del(&vma_list->list);
			break;
		}
	}
	mutex_unlock(&buffer->vma_lock);

	kfree(vma_list);
}

static const struct vm_operations_struct ion_vma_ops = {
	.open = ion_vm_open,
	.close = ion_vm_close,
	.fault = ion_vm_fault
};

static int ion_mmap(struct dma_buf *dmabuf, struct vm_area_struct *vma)
{
	struct ion_buffer *buffer = dmabuf->priv;

	if (buffer->flags & ION_FLAG_NOZEROED) {
		pr_err("%s: mmap non-zeroed buffer to user is prohibited!\n",
			__func__);
		return -EINVAL;
	}

	if (buffer->flags & ION_FLAG_PROTECTED) {
		pr_err("%s: mmap protected buffer to user is prohibited!\n",
			__func__);
		return -EPERM;
	}

	if ((((vma->vm_pgoff << PAGE_SHIFT) >= buffer->size)) ||
		((vma->vm_end - vma->vm_start) >
			 (buffer->size - (vma->vm_pgoff << PAGE_SHIFT)))) {
		pr_err("%s: trying to map outside of buffer.\n", __func__);
		return -EINVAL;
	}

	if (!buffer->heap->ops->map_user)
		return -EINVAL;

	if (ion_buffer_fault_user_mappings(buffer)) {
		vma->vm_flags |= VM_IO | VM_PFNMAP | VM_DONTEXPAND |
							VM_DONTDUMP;
		vma->vm_private_data = buffer;
		vma->vm_ops = &ion_vma_ops;
		ion_vm_open(vma);
		return 0;
	}

	if (!(buffer->flags & ION_FLAG_CACHED))
		vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

	return buffer->heap->ops->map_user(buffer->heap, buffer, vma);
}

static void ion_dma_buf_release(struct dma_buf *dmabuf)
{
	struct ion_buffer *buffer = dmabuf->priv;

	kref_put(&buffer->ref, ion_buffer_kref_destroy);
}

static void *ion_dma_buf_vmap(struct dma_buf *dmabuf)
{
	struct ion_buffer *buffer = dmabuf->priv;
	void *vaddr;

	if (!buffer->heap->ops->map_kernel) {
		pr_err("%s: map kernel is not implemented by this heap.\n",
		       __func__);
		return ERR_PTR(-ENODEV);
	}

	vaddr = ion_buffer_kmap_get(buffer);
	return vaddr;
}

static void ion_dma_buf_vunmap(struct dma_buf *dmabuf, void *ptr)
{
	struct ion_buffer *buffer = dmabuf->priv;

	ion_buffer_kmap_put(buffer);
}

static void *ion_dma_buf_kmap(struct dma_buf *dmabuf, unsigned long offset)
{
	struct ion_buffer *buffer = dmabuf->priv;

	return buffer->vaddr + offset * PAGE_SIZE;
}

static int ion_dma_buf_begin_cpu_access(struct dma_buf *dmabuf, size_t start,
					size_t len,
					enum dma_data_direction direction)
{
	struct ion_buffer *buffer = dmabuf->priv;

	if (!buffer->heap->ops->map_kernel)
		return -ENODEV;

	return PTR_RET(ion_buffer_kmap_get(buffer));
}

static void ion_dma_buf_end_cpu_access(struct dma_buf *dmabuf, size_t start,
				       size_t len,
				       enum dma_data_direction direction)
{
	struct ion_buffer *buffer = dmabuf->priv;

	ion_buffer_kmap_put(buffer);
}

static void ion_dma_buf_set_privflag(struct dma_buf *dmabuf)
{
	struct ion_buffer *buffer = dmabuf->priv;

	buffer->private_flags |= ION_PRIV_FLAG_NEED_TO_FLUSH;
}

static bool ion_dma_buf_get_privflag(struct dma_buf *dmabuf, bool clear)
{
	struct ion_buffer *buffer = dmabuf->priv;
	bool ret;

	ret = buffer->private_flags & ION_PRIV_FLAG_NEED_TO_FLUSH;
	if (clear)
		buffer->private_flags &= ~ION_PRIV_FLAG_NEED_TO_FLUSH;

	return ret;
}

static const struct dma_buf_ops dma_buf_ops = {
	.map_dma_buf = ion_map_dma_buf,
	.unmap_dma_buf = ion_unmap_dma_buf,
	.mmap = ion_mmap,
	.release = ion_dma_buf_release,
	.begin_cpu_access = ion_dma_buf_begin_cpu_access,
	.end_cpu_access = ion_dma_buf_end_cpu_access,
	.kmap_atomic = ion_dma_buf_kmap,
	.kmap = ion_dma_buf_kmap,
	.vmap = ion_dma_buf_vmap,
	.vunmap = ion_dma_buf_vunmap,
	.set_privflag = ion_dma_buf_set_privflag,
	.get_privflag = ion_dma_buf_get_privflag
};

struct dma_buf *ion_share_dma_buf(struct ion_client *client,
				  struct ion_handle *handle)
{
	DEFINE_DMA_BUF_EXPORT_INFO(exp_info);
	struct ion_buffer *buffer;
	struct dma_buf *dmabuf;

	if (!ion_handle_validate(client, handle))
		return ERR_PTR(-EINVAL);

	buffer = handle->buffer;

	exp_info.ops = &dma_buf_ops;
	exp_info.size = buffer->size;
	exp_info.flags = O_RDWR;
	exp_info.priv = buffer;

	dmabuf = dma_buf_export(&exp_info);
	if (!IS_ERR(dmabuf))
		kref_get(&buffer->ref);

	return dmabuf;
}

int ion_share_dma_buf_fd(struct ion_client *client, struct ion_handle *handle)
{
	struct dma_buf *dmabuf;
	int fd;

	dmabuf = ion_share_dma_buf(client, handle);
	if (IS_ERR(dmabuf))
		return PTR_ERR(dmabuf);

	fd = dma_buf_fd(dmabuf, O_CLOEXEC);
	if (fd < 0)
		dma_buf_put(dmabuf);

	return fd;
}

struct ion_handle *ion_import_dma_buf(struct ion_client *client, int fd)
{
	struct ion_buffer *buffer;
	struct ion_handle *handle;
	struct dma_buf *dmabuf;
	int ret;

	dmabuf = dma_buf_get(fd);
	if (IS_ERR(dmabuf))
		return ERR_CAST(dmabuf);

	if (dmabuf->ops != &dma_buf_ops)
		goto put_dmabuf;

	buffer = dmabuf->priv;
	handle = ion_handle_lookup_get(client, buffer);
	if (IS_ERR(handle)) {
		handle = ion_handle_create(client, buffer);
		if (IS_ERR(handle))
			goto put_dmabuf;

		kref_get(&buffer->ref);
		ret = ion_handle_add(client, handle);
		if (ret)
			goto put_handle;
	}

	dma_buf_put(dmabuf);
	return handle;

put_handle:
	/* ion_handle_put will put the buffer as well */
	ion_handle_put(handle);
put_dmabuf:
	dma_buf_put(dmabuf);
	return ERR_PTR(-EINVAL);
}

int ion_cached_needsync_dmabuf(struct dma_buf *dmabuf)
{
	struct ion_buffer *buffer = dmabuf->priv;
	unsigned long cacheflag = ION_FLAG_CACHED | ION_FLAG_CACHED_NEEDS_SYNC;

	if (dmabuf->ops != &dma_buf_ops)
		return -EINVAL;

	return ((buffer->flags & cacheflag) == cacheflag) ? 1 : 0;
}
EXPORT_SYMBOL(ion_cached_needsync_dmabuf);

bool ion_may_hwrender_dmabuf(struct dma_buf *dmabuf)
{
	struct ion_buffer *buffer = dmabuf->priv;

	if (dmabuf->ops != &dma_buf_ops) {
		WARN(1, "%s: given dmabuf is not exported by ION\n", __func__);
		return false;
	}

	return buffer->flags & ION_FLAG_MAY_HWRENDER;
}
EXPORT_SYMBOL(ion_may_hwrender_dmabuf);

bool ion_may_hwrender_handle(struct ion_client *client, struct ion_handle *handle)
{
	struct ion_buffer *buffer = handle->buffer;
	bool valid_handle;

	valid_handle = ion_handle_validate(client, handle);

	if (!valid_handle) {
		WARN(1, "%s: invalid handle passed\n", __func__);
		return false;
	}

	return buffer->flags & ION_FLAG_MAY_HWRENDER;
}
EXPORT_SYMBOL(ion_may_hwrender_handle);

static int ion_sync_for_device(struct ion_client *client, int fd)
{
	struct ion_buffer *buffer;
	struct dma_buf *dmabuf;
	struct scatterlist *sg, *sgl;		
	int nelems;		
	void *vaddr;		
	int i = 0;

	dmabuf = dma_buf_get(fd);
	if (IS_ERR(dmabuf))
		return PTR_ERR(dmabuf);

	if (dmabuf->ops != &dma_buf_ops)
		goto put_dmabuf;

	buffer = dmabuf->priv;

	if (!ion_buffer_cached(buffer) ||
			ion_buffer_fault_user_mappings(buffer))
		goto done;

	sgl = buffer->sg_table->sgl;
	nelems = buffer->sg_table->nents;

	for_each_sg(sgl, sg, nelems, i) {
		vaddr = phys_to_virt(sg_phys(sg));		
		__dma_flush_range(vaddr, vaddr + sg->length);		
	}

done:
	dma_buf_put(dmabuf);
	return 0;

put_dmabuf:
	dma_buf_put(dmabuf);
	return -EINVAL;
}

static int ion_sync_partial_for_device(struct ion_client *client, int fd,
					off_t offset, size_t len)
{
	struct dma_buf *dmabuf;
	struct ion_buffer *buffer;
	struct scatterlist *sg, *sgl;
	size_t remained = len;
	int nelems;
	int i;

	dmabuf = dma_buf_get(fd);
	if (IS_ERR(dmabuf))
		return PTR_ERR(dmabuf);

	if (dmabuf->ops != &dma_buf_ops)
		goto put_dmabuf;

	buffer = dmabuf->priv;

	if (!ion_buffer_cached(buffer) ||
			ion_buffer_fault_user_mappings(buffer))
		goto done;

	sgl = buffer->sg_table->sgl;
	nelems = buffer->sg_table->nents;

	for_each_sg(sgl, sg, nelems, i) {
		size_t len_to_flush;
		if (offset >= sg->length) {
			offset -= sg->length;
			continue;
		}

		len_to_flush = sg->length - offset;
		if (remained < len_to_flush) {
			len_to_flush = remained;
			remained = 0;
		} else {
			remained -= len_to_flush;
		}

		__dma_map_area(phys_to_virt(sg_phys(sg)) + offset,
				len_to_flush, DMA_TO_DEVICE);

		if (remained == 0)
			break;
		offset = 0;
	}

done:
	dma_buf_put(dmabuf);
	return 0;

put_dmabuf:
	dma_buf_put(dmabuf);
	return -EINVAL;
}

static long ion_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	union {
		struct ion_fd_data fd;
		struct ion_fd_partial_data fd_partial;
		struct ion_allocation_data allocation;
		struct ion_handle_data handle;
		struct ion_custom_data custom;
	} data;
	struct ion_client *client = file->private_data;
	struct ion_device *dev = client->dev;
	struct ion_handle *handle;

	if (_IOC_SIZE(cmd) > sizeof(data))
		return -EINVAL;

	switch (cmd) {
	case ION_IOC_ALLOC:
	case ION_IOC_FREE:
	case ION_IOC_SHARE:
	case ION_IOC_MAP:
	case ION_IOC_IMPORT:
	case ION_IOC_SYNC:
	case ION_IOC_SYNC_PARTIAL:
	case ION_IOC_CUSTOM:
		if (copy_from_user(&data, (void __user *)arg, _IOC_SIZE(cmd)))
			return -EFAULT;
		break;
	}

	switch (cmd) {
	case ION_IOC_ALLOC:
		handle = ion_alloc(client, data.allocation.len,
				   data.allocation.align,
				   data.allocation.heap_id_mask,
				   data.allocation.flags);
		if (IS_ERR(handle))
			return PTR_ERR(handle);

		data.allocation.handle = handle->id;
		break;
	case ION_IOC_FREE:
		handle = ion_handle_find_by_id(client, data.handle.handle);
		if (IS_ERR(handle))
			return PTR_ERR(handle);

		ion_handle_put(handle);
		break;
	case ION_IOC_SHARE:
	case ION_IOC_MAP:
		handle = ion_handle_find_by_id(client, data.handle.handle);
		if (IS_ERR(handle))
			return PTR_ERR(handle);

		data.fd.fd = ion_share_dma_buf_fd(client, handle);
		if (data.fd.fd < 0)
			return data.fd.fd;
		break;
	case ION_IOC_IMPORT:
		handle = ion_import_dma_buf(client, data.fd.fd);
		if (IS_ERR(handle))
			return PTR_ERR(handle);

		data.handle.handle = handle->id;
		break;
	case ION_IOC_SYNC:
		return ion_sync_for_device(client, data.fd.fd);
	case ION_IOC_SYNC_PARTIAL:
		return ion_sync_partial_for_device(client, data.fd_partial.fd,
			data.fd_partial.offset, data.fd_partial.len);
	case ION_IOC_CUSTOM:
		if (dev->custom_ioctl)
			return dev->custom_ioctl(client, data.custom.cmd,
						 data.custom.arg);
		return -ENOTTY;
	default:
		return -ENOTTY;
	}

	switch (cmd) {
	case ION_IOC_ALLOC:
	case ION_IOC_SHARE:
	case ION_IOC_MAP:
	case ION_IOC_IMPORT:
		if (copy_to_user((void __user *)arg, &data, _IOC_SIZE(cmd))) {
			if (cmd == ION_IOC_ALLOC)
				ion_handle_put(handle);
			return -EFAULT;
		}
		break;
	}

	return 0;
}

static int ion_release(struct inode *inode, struct file *file)
{
	struct ion_client *client = file->private_data;

	ion_client_destroy(client);
	return 0;
}

static int ion_open(struct inode *inode, struct file *file)
{
	struct miscdevice *miscdev = file->private_data;
	struct ion_device *dev = container_of(miscdev, typeof(*dev), dev);
	struct ion_client *client;

	client = ion_client_create(dev);
	if (IS_ERR(client))
		return PTR_ERR(client);

	file->private_data = client;
	return 0;
}

static const struct file_operations ion_fops = {
	.owner = THIS_MODULE,
	.open = ion_open,
	.release = ion_release,
	.unlocked_ioctl = ion_ioctl,
	.compat_ioctl = compat_ion_ioctl
};

void ion_device_add_heap(struct ion_device *dev, struct ion_heap *heap)
{
	spin_lock_init(&heap->free_lock);
	heap->free_list_size = 0;

	if (heap->flags & ION_HEAP_FLAG_DEFER_FREE)
		ion_heap_init_deferred_free(heap);

	if (heap->flags & ION_HEAP_FLAG_DEFER_FREE || heap->ops->shrink)
		ion_heap_init_shrinker(heap);

	heap->dev = dev;
	plist_node_init(&heap->node, -heap->id);

	down_write(&dev->heap_lock);
	plist_add(&heap->node, &dev->heaps);
	up_write(&dev->heap_lock);
}

struct ion_device *ion_device_create(long (*custom_ioctl)
				     (struct ion_client *client,
				      unsigned int cmd, unsigned long arg))
{
	struct ion_device *dev;
	int ret;

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return ERR_PTR(-ENOMEM);

	dev->dev.minor = MISC_DYNAMIC_MINOR;
	dev->dev.name = "ion";
	dev->dev.fops = &ion_fops;
	dev->dev.parent = NULL;
	ret = misc_register(&dev->dev);
	if (ret)
		goto free_dev;

	dev->custom_ioctl = custom_ioctl;
	init_rwsem(&dev->heap_lock);
	plist_head_init(&dev->heaps);
	return dev;

free_dev:
	kfree(dev);
	return ERR_PTR(-ENOMEM);
}

void __init ion_reserve(struct ion_platform_data *data)
{
	phys_addr_t paddr;
	int i;

	for (i = 0; i < data->nr; i++) {
		if (!data->heaps[i].size)
			continue;

		if (data->heaps[i].base) {
			memblock_reserve(data->heaps[i].base,
					 data->heaps[i].size);
		} else {
			paddr = memblock_alloc_base(data->heaps[i].size,
						    data->heaps[i].align,
						    MEMBLOCK_ALLOC_ANYWHERE);
			if (paddr)
				data->heaps[i].base = paddr;
		}
	}
}

static struct ion_iovm_map *ion_buffer_iova_create(struct ion_buffer *buffer,
		struct device *dev, enum dma_data_direction dir, int prop)
{
	/* Must be called under buffer->lock held */
	struct ion_iovm_map *iovm_map;
	int ret = 0;

	iovm_map = kzalloc(sizeof(struct ion_iovm_map), GFP_KERNEL);
	if (!iovm_map) {
		pr_err("%s: Failed to allocate ion_iovm_map for %s\n",
			__func__, dev_name(dev));
		return ERR_PTR(-ENOMEM);
	}

	iovm_map->iova = iovmm_map(dev, buffer->sg_table->sgl,
					0, buffer->size, dir, prop);

	if (iovm_map->iova == (dma_addr_t)-ENOSYS) {
		size_t len;
		ion_phys_addr_t addr;

		BUG_ON(!buffer->heap->ops->phys);
		ret = buffer->heap->ops->phys(buffer->heap, buffer,
						&addr, &len);
		if (ret)
			pr_err("%s: Unable to get PA for %s\n",
					__func__, dev_name(dev));
	} else if (IS_ERR_VALUE(iovm_map->iova)) {
		ret = iovm_map->iova;
		pr_err("%s: Unable to allocate IOVA for %s\n",
			__func__, dev_name(dev));
	}

	if (ret) {
		kfree(iovm_map);
		return ERR_PTR(ret);
	}

	iovm_map->dev = dev;
	iovm_map->domain = get_domain_from_dev(dev);
	iovm_map->map_cnt = 1;

	pr_debug("%s: new map added for dev %s, iova %pa, prop %d\n", __func__,
		 dev_name(dev), &iovm_map->iova, prop);

	return iovm_map;
}

dma_addr_t ion_iovmm_map(struct dma_buf_attachment *attachment,
			 off_t offset, size_t size,
			 enum dma_data_direction direction, int prop)
{
	struct dma_buf *dmabuf = attachment->dmabuf;
	struct ion_buffer *buffer = dmabuf->priv;
	struct ion_iovm_map *iovm_map;
	struct iommu_domain *domain;

	BUG_ON(dmabuf->ops != &dma_buf_ops);

	if (IS_ENABLED(CONFIG_EXYNOS_CONTENT_PATH_PROTECTION) &&
			buffer->flags & ION_FLAG_PROTECTED) {
		struct ion_buffer_info *info = buffer->priv_virt;

		if (info->prot_desc.dma_addr)
			return info->prot_desc.dma_addr;
		pr_err("%s: protected buffer but no secure iova\n", __func__);
		return -EINVAL;
	}

	domain = get_domain_from_dev(attachment->dev);
	if (!domain) {
		pr_err("%s: invalid iommu device\n", __func__);
		return -EINVAL;
	}

	list_for_each_entry(iovm_map, &buffer->iovas, list) {
		if (domain == iovm_map->domain) {
			iovm_map->map_cnt++;
			return iovm_map->iova;
		}
	}

	if (!ion_buffer_cached(buffer))
		prop &= ~IOMMU_CACHE;

	iovm_map = ion_buffer_iova_create(buffer, attachment->dev,
					  direction, prop);
	if (IS_ERR(iovm_map)) {
		return PTR_ERR(iovm_map);
	}

	list_add_tail(&iovm_map->list, &buffer->iovas);

	return iovm_map->iova;
}

void ion_iovmm_unmap(struct dma_buf_attachment *attachment, dma_addr_t iova)
{
	struct ion_iovm_map *iovm_map;
	struct dma_buf * dmabuf = attachment->dmabuf;
	struct device *dev = attachment->dev;
	struct ion_buffer *buffer = attachment->dmabuf->priv;
	struct iommu_domain *domain;

	BUG_ON(dmabuf->ops != &dma_buf_ops);

	if (IS_ENABLED(CONFIG_EXYNOS_CONTENT_PATH_PROTECTION) &&
			buffer->flags & ION_FLAG_PROTECTED)
		return;

	domain = get_domain_from_dev(attachment->dev);
	if (!domain) {
		pr_err("%s: invalid iommu device\n", __func__);
		return;
	}

	list_for_each_entry(iovm_map, &buffer->iovas, list) {
		if ((domain == iovm_map->domain) && (iova == iovm_map->iova)) {
			if (--iovm_map->map_cnt == 0) {
				list_del(&iovm_map->list);
				pr_debug("%s: unmap previous %pa for dev %s\n",
					 __func__, &iovm_map->iova,
					dev_name(iovm_map->dev));
				iovmm_unmap(iovm_map->dev, iovm_map->iova);
				kfree(iovm_map);
			}

			return;
		}
	}

	WARN(1, "IOVA %pa is not found for %s\n", &iova, dev_name(dev));
}

struct ion_buffer *get_buffer(struct ion_handle *handle)
{
	struct ion_buffer *buffer = handle->buffer;

	return buffer;
}