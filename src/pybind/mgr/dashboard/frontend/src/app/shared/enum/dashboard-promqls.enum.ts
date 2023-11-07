export enum Promqls {
  USEDCAPACITY = 'ceph_cluster_total_used_bytes',
  WRITEIOPS = 'sum(rate(ceph_pool_wr[1m]))',
  READIOPS = 'sum(rate(ceph_pool_rd[1m]))',
  READLATENCY = 'avg_over_time(ceph_osd_apply_latency_ms[1m])',
  WRITELATENCY = 'avg_over_time(ceph_osd_commit_latency_ms[1m])',
  READCLIENTTHROUGHPUT = 'sum(rate(ceph_pool_rd_bytes[1m]))',
  WRITECLIENTTHROUGHPUT = 'sum(rate(ceph_pool_wr_bytes[1m]))',
  RECOVERYBYTES = 'sum(rate(ceph_osd_recovery_bytes[1m]))'
}

export enum RgwPromqls {
  RGW_REQUEST_PER_SECOND = 'sum(rate(ceph_rgw_req[1m]))',
  AVG_GET_LATENCY = 'sum(rate(ceph_rgw_get_initial_lat_sum[1m])) / sum(rate(ceph_rgw_get_initial_lat_count[1m]))',
  AVG_PUT_LATENCY = 'sum(rate(ceph_rgw_put_initial_lat_sum[1m])) / sum(rate(ceph_rgw_put_initial_lat_count[1m]))',
  GET_BANDWIDTH = 'sum(rate(ceph_rgw_get_b[1m]))',
  PUT_BANDWIDTH = 'sum(rate(ceph_rgw_put_b[1m]))'
}

export enum MultiClusterPromqls {
  ALERTS_COUNT = 'count(ALERTS{alertstate=\"firing\"}) or vector(0)',
  CLUSTER_COUNT = 'count(ceph_health_status) or vector(0)',
  HEALTH_OK_COUNT = 'count(ceph_health_status==0) or vector(0)',
  HEALTH_WARNING_COUNT = 'count(ceph_health_status==1) or vector(0)',
  HEALTH_ERROR_COUNT = 'count(ceph_health_status==2) or vector(0)',
  TOTAL_CLUSTERS_CAPACITY = 'sum(ceph_cluster_total_bytes) or vector(0)',
  TOTAL_USED_CAPACITY = 'sum(ceph_cluster_by_class_total_used_bytes) or vector(0)',
  HEALTH_STATUS = 'ceph_health_status',
  TOTAL_CAPACITY = 'ceph_cluster_total_bytes',
  USED_CAPACITY = 'ceph_cluster_total_used_bytes',
  POOLS = 'count by (cluster) (ceph_pool_metadata) or vector(0)',
  OSDS = 'count by (cluster) (ceph_osd_metadata) or vector(0)',
  CRITICAL_ALERTS_COUNT = 'count(ALERTS{alertstate=\"firing\",severity=\"critical\"}) or vector(0)',
  WARNING_ALERTS_COUNT = 'count(ALERTS{alertstate=\"firing\",severity=\"warning\"}) or vector(0)',
  ALERTS = 'ALERTS'
}
