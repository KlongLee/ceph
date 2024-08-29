// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab ft=cpp

#pragma once

enum RGWOpType {
  RGW_OP_UNKNOWN = 0,
  RGW_OP_GET_OBJ,
  RGW_OP_LIST_BUCKETS,
  RGW_OP_STAT_ACCOUNT,
  RGW_OP_LIST_BUCKET,
  RGW_OP_GET_BUCKET_LOGGING,
  RGW_OP_GET_BUCKET_LOCATION,
  RGW_OP_GET_BUCKET_VERSIONING,
  RGW_OP_SET_BUCKET_VERSIONING,
  RGW_OP_GET_BUCKET_WEBSITE,
  RGW_OP_SET_BUCKET_WEBSITE,
  RGW_OP_STAT_BUCKET,
  RGW_OP_CREATE_BUCKET,
  RGW_OP_DELETE_BUCKET,
  RGW_OP_PUT_OBJ,
  RGW_OP_STAT_OBJ,
  RGW_OP_POST_OBJ,
  RGW_OP_PUT_METADATA_ACCOUNT,
  RGW_OP_PUT_METADATA_BUCKET,
  RGW_OP_PUT_METADATA_OBJECT,
  RGW_OP_SET_TEMPURL,
  RGW_OP_RESTORE_OBJ,
  RGW_OP_DELETE_OBJ,
  RGW_OP_COPY_OBJ,
  RGW_OP_GET_ACLS,
  RGW_OP_PUT_ACLS,
  RGW_OP_GET_CORS,
  RGW_OP_PUT_CORS,
  RGW_OP_DELETE_CORS,
  RGW_OP_OPTIONS_CORS,
  RGW_OP_GET_BUCKET_ENCRYPTION,
  RGW_OP_PUT_BUCKET_ENCRYPTION,
  RGW_OP_DELETE_BUCKET_ENCRYPTION,
  RGW_OP_GET_REQUEST_PAYMENT,
  RGW_OP_SET_REQUEST_PAYMENT,
  RGW_OP_INIT_MULTIPART,
  RGW_OP_COMPLETE_MULTIPART,
  RGW_OP_ABORT_MULTIPART,
  RGW_OP_LIST_MULTIPART,
  RGW_OP_LIST_BUCKET_MULTIPARTS,
  RGW_OP_DELETE_MULTI_OBJ,
  RGW_OP_BULK_DELETE,
  RGW_OP_GET_KEYS,
  RGW_OP_GET_ATTRS,
  RGW_OP_DELETE_ATTRS,
  RGW_OP_SET_ATTRS,
  RGW_OP_GET_CROSS_DOMAIN_POLICY,
  RGW_OP_GET_HEALTH_CHECK,
  RGW_OP_GET_INFO,
  RGW_OP_PUT_BUCKET_POLICY,
  RGW_OP_GET_BUCKET_POLICY,
  RGW_OP_DELETE_BUCKET_POLICY,
  RGW_OP_PUT_OBJ_TAGGING,
  RGW_OP_GET_OBJ_TAGGING,
  RGW_OP_DELETE_OBJ_TAGGING,
  RGW_OP_PUT_LC,
  RGW_OP_GET_LC,
  RGW_OP_DELETE_LC,
  RGW_OP_PUT_BUCKET_OBJ_LOCK,
  RGW_OP_GET_BUCKET_OBJ_LOCK,
  RGW_OP_PUT_OBJ_RETENTION,
  RGW_OP_GET_OBJ_RETENTION,
  RGW_OP_PUT_OBJ_LEGAL_HOLD,
  RGW_OP_GET_OBJ_LEGAL_HOLD,
  // IAM
  RGW_OP_PUT_USER_POLICY,
  RGW_OP_GET_USER_POLICY,
  RGW_OP_LIST_USER_POLICIES,
  RGW_OP_DELETE_USER_POLICY,
  RGW_OP_ATTACH_USER_POLICY,
  RGW_OP_DETACH_USER_POLICY,
  RGW_OP_LIST_ATTACHED_USER_POLICIES,
  RGW_OP_CREATE_ROLE,
  RGW_OP_DELETE_ROLE,
  RGW_OP_GET_ROLE,
  RGW_OP_MODIFY_ROLE_TRUST_POLICY,
  RGW_OP_LIST_ROLES,
  RGW_OP_PUT_ROLE_POLICY,
  RGW_OP_GET_ROLE_POLICY,
  RGW_OP_LIST_ROLE_POLICIES,
  RGW_OP_DELETE_ROLE_POLICY,
  RGW_OP_ATTACH_ROLE_POLICY,
  RGW_OP_DETACH_ROLE_POLICY,
  RGW_OP_LIST_ATTACHED_ROLE_POLICIES,
  RGW_OP_TAG_ROLE,
  RGW_OP_LIST_ROLE_TAGS,
  RGW_OP_UNTAG_ROLE,
  RGW_OP_UPDATE_ROLE,
  RGW_OP_CREATE_USER,
  RGW_OP_GET_USER,
  RGW_OP_UPDATE_USER,
  RGW_OP_DELETE_USER,
  RGW_OP_LIST_USERS,
  RGW_OP_CREATE_ACCESS_KEY,
  RGW_OP_UPDATE_ACCESS_KEY,
  RGW_OP_DELETE_ACCESS_KEY,
  RGW_OP_LIST_ACCESS_KEYS,
  RGW_OP_CREATE_GROUP,
  RGW_OP_GET_GROUP,
  RGW_OP_UPDATE_GROUP,
  RGW_OP_DELETE_GROUP,
  RGW_OP_LIST_GROUPS,
  RGW_OP_ADD_USER_TO_GROUP,
  RGW_OP_REMOVE_USER_FROM_GROUP,
  RGW_OP_LIST_GROUPS_FOR_USER,
  RGW_OP_PUT_GROUP_POLICY,
  RGW_OP_GET_GROUP_POLICY,
  RGW_OP_LIST_GROUP_POLICIES,
  RGW_OP_DELETE_GROUP_POLICY,
  RGW_OP_ATTACH_GROUP_POLICY,
  RGW_OP_DETACH_GROUP_POLICY,
  RGW_OP_LIST_ATTACHED_GROUP_POLICIES,
  /* rgw specific */
  RGW_OP_ADMIN_SET_METADATA,
  RGW_OP_GET_OBJ_LAYOUT,
  RGW_OP_BULK_UPLOAD,
  RGW_OP_METADATA_SEARCH,
  RGW_OP_CONFIG_BUCKET_META_SEARCH,
  RGW_OP_GET_BUCKET_META_SEARCH,
  RGW_OP_DEL_BUCKET_META_SEARCH,
  RGW_OP_SYNC_DATALOG_NOTIFY,
  RGW_OP_SYNC_DATALOG_NOTIFY2,
  RGW_OP_SYNC_MDLOG_NOTIFY,
  RGW_OP_PERIOD_POST,
  /* sts specific*/
  RGW_STS_ASSUME_ROLE,
  RGW_STS_GET_SESSION_TOKEN,
  RGW_STS_ASSUME_ROLE_WEB_IDENTITY,
  /* pubsub */
  RGW_OP_PUBSUB_TOPIC_CREATE,
  RGW_OP_PUBSUB_TOPICS_LIST,
  RGW_OP_PUBSUB_TOPIC_GET,
  RGW_OP_PUBSUB_TOPIC_SET,
  RGW_OP_PUBSUB_TOPIC_DELETE,
  RGW_OP_PUBSUB_SUB_CREATE,
  RGW_OP_PUBSUB_SUB_GET,
  RGW_OP_PUBSUB_SUB_DELETE,
  RGW_OP_PUBSUB_SUB_PULL,
  RGW_OP_PUBSUB_SUB_ACK,
  RGW_OP_PUBSUB_NOTIF_CREATE,
  RGW_OP_PUBSUB_NOTIF_DELETE,
  RGW_OP_PUBSUB_NOTIF_LIST,
  RGW_OP_GET_BUCKET_TAGGING,
  RGW_OP_PUT_BUCKET_TAGGING,
  RGW_OP_DELETE_BUCKET_TAGGING,
  RGW_OP_GET_BUCKET_REPLICATION,
  RGW_OP_PUT_BUCKET_REPLICATION,
  RGW_OP_DELETE_BUCKET_REPLICATION,
  /* public access */
  RGW_OP_GET_BUCKET_POLICY_STATUS,
  RGW_OP_PUT_BUCKET_PUBLIC_ACCESS_BLOCK,
  RGW_OP_GET_BUCKET_PUBLIC_ACCESS_BLOCK,
  RGW_OP_DELETE_BUCKET_PUBLIC_ACCESS_BLOCK,
  /*OIDC provider specific*/
  RGW_OP_CREATE_OIDC_PROVIDER,
  RGW_OP_DELETE_OIDC_PROVIDER,
  RGW_OP_GET_OIDC_PROVIDER,
  RGW_OP_LIST_OIDC_PROVIDERS,
  RGW_OP_ADD_CLIENTID_TO_OIDC_PROVIDER,
  RGW_OP_UPDATE_OIDC_PROVIDER_THUMBPRINT,
};

