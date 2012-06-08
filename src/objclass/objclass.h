// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#ifndef CEPH_OBJCLASS_H
#define CEPH_OBJCLASS_H

#ifdef __cplusplus

#include "../include/types.h"

extern "C" {
#endif

#define CLS_VER(maj,min) \
int __cls_ver__## maj ## _ ##min = 0; \
int __cls_ver_maj = maj; \
int __cls_ver_min = min;

#define CLS_NAME(name) \
int __cls_name__## name = 0; \
const char *__cls_name = #name;

#define CLS_METHOD_RD		0x1
#define CLS_METHOD_WR		0x2
#define CLS_METHOD_PUBLIC	0x4


#define CLS_LOG(fmt, ...) \
	cls_log("<cls> %s:%d: " fmt, __FILE__, __LINE__, ##__VA_ARGS__)

void __cls_init();

typedef void *cls_handle_t;
typedef void *cls_method_handle_t;
typedef void *cls_method_context_t;
typedef int (*cls_method_call_t)(cls_method_context_t ctx,
				 char *indata, int datalen,
				 char **outdata, int *outdatalen);
typedef struct {
	const char *name;
	const char *ver;
} cls_deps_t;

/* class utils */
extern int cls_log(const char *format, ...);
extern void *cls_alloc(size_t size);
extern void cls_free(void *p);

extern int cls_read(cls_method_context_t hctx, int ofs, int len,
                                 char **outdata, int *outdatalen);
extern int cls_call(cls_method_context_t hctx, const char *cls, const char *method,
                                 char *indata, int datalen,
                                 char **outdata, int *outdatalen);
extern int cls_getxattr(cls_method_context_t hctx, const char *name,
                                 char **outdata, int *outdatalen);
extern int cls_setxattr(cls_method_context_t hctx, const char *name,
                                 const char *value, int val_len);

/* class registration api */
extern int cls_register(const char *name, cls_handle_t *handle);
extern int cls_unregister(cls_handle_t);

extern int cls_register_method(cls_handle_t hclass, const char *method, int flags,
                        cls_method_call_t class_call, cls_method_handle_t *handle);
extern int cls_unregister_method(cls_method_handle_t handle);



/* triggers */
#define OBJ_READ    0x1
#define OBJ_WRITE   0x2

typedef int cls_trigger_t;

extern int cls_link(cls_method_handle_t handle, int priority, cls_trigger_t trigger);
extern int cls_unlink(cls_method_handle_t handle);


/* should be defined by the class implementation
   defined here inorder to get it compiled without C++ mangling */
extern void class_init(void);
extern void class_fini(void);

#ifdef __cplusplus
}

typedef int (*cls_method_cxx_call_t)(cls_method_context_t ctx,
				     class buffer::list *inbl, class buffer::list *outbl);

extern int cls_register_cxx_method(cls_handle_t hclass, const char *method, int flags,
				   cls_method_cxx_call_t class_call, cls_method_handle_t *handle);

extern int cls_cxx_stat(cls_method_context_t hctx, uint64_t *size, time_t *mtime);
extern int cls_cxx_read(cls_method_context_t hctx, int ofs, int len, bufferlist *bl);
extern int cls_cxx_write(cls_method_context_t hctx, int ofs, int len, bufferlist *bl);
extern int cls_cxx_write_full(cls_method_context_t hctx, bufferlist *bl);
extern int cls_cxx_replace(cls_method_context_t hctx, int ofs, int len, bufferlist *bl);
extern int cls_cxx_snap_revert(cls_method_context_t hctx, snapid_t snapid);
extern int cls_cxx_map_clear(cls_method_context_t hctx);
extern int cls_cxx_map_read_all_keys(cls_method_context_t hctx, std::map<string, bufferlist> *keys);
extern int cls_cxx_map_read_keys(cls_method_context_t hctx, string& start_after, string& filter_prefix,
				 uint64_t max, std::map<string, bufferlist> *keys);
extern int cls_cxx_map_read_header(cls_method_context_t hctx, bufferlist *outbl);
extern int cls_cxx_map_read_key(cls_method_context_t hctx, string key, bufferlist *outbl);
extern int cls_cxx_map_write_key(cls_method_context_t hctx, string key, bufferlist *inbl);
extern int cls_cxx_map_write_header(cls_method_context_t hctx, bufferlist *inbl);
extern int cls_cxx_map_remove_key(cls_method_context_t hctx, string key);
extern int cls_cxx_map_update(cls_method_context_t hctx, bufferlist* inbl);

/* These are also defined in rados.h and librados.h. Keep them in sync! */
#define CEPH_OSD_TMAP_HDR 'h'
#define CEPH_OSD_TMAP_SET 's'
#define CEPH_OSD_TMAP_CREATE 'c'
#define CEPH_OSD_TMAP_RM 'r'


#endif

#endif
