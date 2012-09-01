// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*- 
// vim: ts=8 sw=2 smarttab
/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2011 New Dream Network
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License version 2.1, as published by the Free Software
 * Foundation.	See file COPYING.
 *
 */

#ifndef CEPH_LIBRBD_H
#define CEPH_LIBRBD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#if defined(__linux__)
#include <linux/types.h>
#elif defined(__FreeBSD__)
#include <sys/types.h>
#endif
#include <string.h>
#include "../rados/librados.h"
#include "features.h"

#define LIBRBD_VER_MAJOR 0
#define LIBRBD_VER_MINOR 1
#define LIBRBD_VER_EXTRA 4

#define LIBRBD_VERSION(maj, min, extra) ((maj << 16) + (min << 8) + extra)

#define LIBRBD_VERSION_CODE LIBRBD_VERSION(LIBRBD_VER_MAJOR, LIBRBD_VER_MINOR, LIBRBD_VER_EXTRA)

#define LIBRBD_SUPPORTS_WATCH 0

typedef void *rbd_snap_t;
typedef void *rbd_image_t;

typedef int (*librbd_progress_fn_t)(uint64_t offset, uint64_t total, void *ptr);

typedef struct {
  uint64_t id;
  uint64_t size;
  const char *name;
} rbd_snap_info_t;

#define RBD_MAX_IMAGE_NAME_SIZE 96
#define RBD_MAX_BLOCK_NAME_SIZE 24

typedef struct {
  uint64_t size;
  uint64_t obj_size;
  uint64_t num_objs;
  int order;
  char block_name_prefix[RBD_MAX_BLOCK_NAME_SIZE];
  int64_t parent_pool;			      /* deprecated */
  char parent_name[RBD_MAX_IMAGE_NAME_SIZE];  /* deprecated */
} rbd_image_info_t;

void rbd_version(int *major, int *minor, int *extra);

/* images */
int rbd_list(rados_ioctx_t io, char *names, size_t *size);
int rbd_create(rados_ioctx_t io, const char *name, uint64_t size, int *order);
int rbd_create2(rados_ioctx_t io, const char *name, uint64_t size,
		uint64_t features, int *order);
int rbd_clone(rados_ioctx_t p_ioctx, const char *p_name,
	      const char *p_snapname, rados_ioctx_t c_ioctx,
	      const char *c_name, uint64_t features, int *c_order);
int rbd_remove(rados_ioctx_t io, const char *name);
int rbd_remove_with_progress(rados_ioctx_t io, const char *name,
			     librbd_progress_fn_t cb, void *cbdata);
int rbd_rename(rados_ioctx_t src_io_ctx, const char *srcname, const char *destname);

int rbd_open(rados_ioctx_t io, const char *name, rbd_image_t *image, const char *snap_name);
int rbd_close(rbd_image_t image);
int rbd_resize(rbd_image_t image, uint64_t size);
int rbd_resize_with_progress(rbd_image_t image, uint64_t size,
			     librbd_progress_fn_t cb, void *cbdata);
int rbd_stat(rbd_image_t image, rbd_image_info_t *info, size_t infosize);
int rbd_get_old_format(rbd_image_t image, uint8_t *old);
int rbd_get_size(rbd_image_t image, uint64_t *size);
int rbd_get_features(rbd_image_t image, uint64_t *features);
int rbd_get_overlap(rbd_image_t image, uint64_t *overlap);
int rbd_get_parent_info(rbd_image_t image,
			char *parent_poolname, size_t ppoolnamelen,
			char *parent_name, size_t pnamelen,
			char *parent_snapname, size_t psnapnamelen);
int rbd_copy(rbd_image_t image, rados_ioctx_t dest_io_ctx, const char *destname);
int rbd_copy_with_progress(rbd_image_t image, rados_ioctx_t dest_p, const char *destname,
			   librbd_progress_fn_t cb, void *cbdata);

/* snapshots */
int rbd_snap_list(rbd_image_t image, rbd_snap_info_t *snaps, int *max_snaps);
void rbd_snap_list_end(rbd_snap_info_t *snaps);
int rbd_snap_create(rbd_image_t image, const char *snapname);
int rbd_snap_remove(rbd_image_t image, const char *snapname);
int rbd_snap_rollback(rbd_image_t image, const char *snapname);
int rbd_snap_rollback_with_progress(rbd_image_t image, const char *snapname,
				    librbd_progress_fn_t cb, void *cbdata);
/**
 * Prevent a snapshot from being deleted until it is unprotected.
 *
 * @param snap_name which snapshot to protect
 * @returns 0 on success, negative error code on failure
 * @returns -EBUSY if snap is already protected
 */
int rbd_snap_protect(rbd_image_t image, const char *snap_name);
/**
 * Allow a snaphshot to be deleted.
 *
 * @param snap_name which snapshot to unprotect
 * @returns 0 on success, negative error code on failure
 * @returns -EINVAL if snap is not protected
 */
int rbd_snap_unprotect(rbd_image_t image, const char *snap_name);
/**
 * Determine whether a snapshot is protected.
 *
 * @param snap_name which snapshot query
 * @param is_protected where to store the result (0 or 1)
 * @returns 0 on success, negative error code on failure
 */
int rbd_snap_is_protected(rbd_image_t image, const char *snap_name,
			  int *is_protected);
int rbd_snap_set(rbd_image_t image, const char *snapname);

int rbd_flatten(rbd_image_t image);

/**
 * List all images that are cloned from the image at the
 * snapshot that is set via rbd_snap_set().
 *
 * This iterates over all pools, so it should be run by a user with
 * read access to all of them. pools_len and images_len are filled in
 * with the number of bytes put into the pools and images buffers.
 *
 * If the provided buffers are too short, the required lengths are
 * still filled in, but the data is not and -ERANGE is returned.
 * Otherwise, the buffers are filled with the pool and image names
 * of the children, with a '\0' after each.
 *
 * @param image which image (and implicitly snapshot) to list clones of
 * @param pools buffer in which to store pool names
 * @param pools_len number of bytes in pools buffer
 * @param images buffer in which to store image names
 * @param images_len number of bytes in images buffer
 * @returns number of children on success, negative error code on failure
 * @returns -ERANGE if either buffer is too short
 */
ssize_t rbd_list_children(rbd_image_t image, char *pools, size_t *pools_len,
			  char *images, size_t *images_len);

/**
 * @defgroup librbd_h_locking Advisory Locking
 *
 * An rbd image may be locking exclusively, or shared, to facilitate
 * e.g. live migration where the image may be open in two places at once.
 * These locks are intended to guard against more than one client
 * writing to an image without coordination. They don't need to
 * be used for snapshots, since snapshots are read-only.
 *
 * Currently locks only guard against locks being acquired.
 * They do not prevent anything else.
 *
 * A locker is identified by the internal rados client id of the
 * holder and a user-defined cookie. This (client id, cookie) pair
 * must be unique for each locker.
 *
 * A shared lock also has a user-defined tag associated with it. Each
 * additional shared lock must specify the same tag or lock
 * acquisition will fail. This can be used by e.g. groups of hosts
 * using a clustered filesystem on top of an rbd image to make sure
 * they're accessing the correct image.
 *
 * @{
 */
/**
 * List clients that have locked the image and information about the lock.
 *
 * The number of bytes required in each buffer is put in the
 * corresponding size out parameter. If any of the provided buffers
 * are too short, -ERANGE is returned after these sizes are filled in.
 *
 * @param exclusive where to store whether the lock is exclusive (1) or shared (0)
 * @param tag where to store the tag associated with the image
 * @param tag_len number of bytes in tag buffer
 * @param clients buffer in which locker clients are stored, separated by '\0'
 * @param clients_len number of bytes in the clients buffer
 * @param cookies buffer in which locker cookies are stored, separated by '\0'
 * @param cookies_len number of bytes in the cookies buffer
 * @param addrs buffer in which locker addresses are stored, separated by '\0'
 * @param addrs_len number of bytes in the clients buffer
 * @returns number of lockers on success, negative error code on failure
 * @returns -ERANGE if any of the buffers are too short
 */
ssize_t rbd_list_lockers(rbd_image_t image, int *exclusive,
			 char *tag, size_t *tag_len,
			 char *clients, size_t *clients_len,
			 char *cookies, size_t *cookies_len,
			 char *addrs, size_t *addrs_len);

/**
 * Take an exclusive lock on the image.
 *
 * @param image the image to lock
 * @param cookie user-defined identifier for this instance of the lock
 * @returns 0 on success, negative error code on failure
 * @returns -EBUSY if the lock is already held by another (client, cookie) pair
 * @returns -EEXIST if the lock is already held by the same (client, cookie) pair
 */
int rbd_lock_exclusive(rbd_image_t image, const char *cookie);

/**
 * Take a shared lock on the image.
 *
 * Other clients may also take a shared lock, as lock as they use the
 * same tag.
 *
 * @param image the image to lock
 * @param cookie user-defined identifier for this instance of the lock
 * @param tag user-defined identifier for this shared use of the lock
 * @returns 0 on success, negative error code on failure
 * @returns -EBUSY if the lock is already held by another (client, cookie) pair
 * @returns -EEXIST if the lock is already held by the same (client, cookie) pair
 */
int rbd_lock_shared(rbd_image_t image, const char *cookie, const char *tag);

/**
 * Release a shared or exclusive lock on the image.
 *
 * @param image the image to unlock
 * @param cookie user-defined identifier for the instance of the lock
 * @returns 0 on success, negative error code on failure
 * @returns -ENOENT if the lock is not held by the specified (client, cookie) pair
 */
int rbd_unlock(rbd_image_t image, const char *cookie);

/**
 * Release a shared or exclusive lock that was taken by the specified client.
 *
 * @param image the image to unlock
 * @param client the entity holding the lock (as given by rbd_list_lockers())
 * @param cookie user-defined identifier for the instance of the lock to break
 * @returns 0 on success, negative error code on failure
 * @returns -ENOENT if the lock is not held by the specified (client, cookie) pair
 */
int rbd_break_lock(rbd_image_t image, const char *client, const char *cookie);

/** @} locking */

/* I/O */
typedef void *rbd_completion_t;
typedef void (*rbd_callback_t)(rbd_completion_t cb, void *arg);
ssize_t rbd_read(rbd_image_t image, uint64_t ofs, size_t len, char *buf);
int64_t rbd_read_iterate(rbd_image_t image, uint64_t ofs, size_t len,
			 int (*cb)(uint64_t, size_t, const char *, void *), void *arg);
ssize_t rbd_write(rbd_image_t image, uint64_t ofs, size_t len, const char *buf);
int rbd_discard(rbd_image_t image, uint64_t ofs, uint64_t len);
int rbd_aio_write(rbd_image_t image, uint64_t off, size_t len, const char *buf, rbd_completion_t c);
int rbd_aio_read(rbd_image_t image, uint64_t off, size_t len, char *buf, rbd_completion_t c);
int rbd_aio_discard(rbd_image_t image, uint64_t off, uint64_t len, rbd_completion_t c);
int rbd_aio_create_completion(void *cb_arg, rbd_callback_t complete_cb, rbd_completion_t *c);
int rbd_aio_wait_for_complete(rbd_completion_t c);
ssize_t rbd_aio_get_return_value(rbd_completion_t c);
void rbd_aio_release(rbd_completion_t c);
int rbd_flush(rbd_image_t image);

#ifdef __cplusplus
}
#endif

#endif
