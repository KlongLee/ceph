local g = import 'grafana.libsonnet';

local dashboardSchema(title, description, uid, time_from, refresh, schemaVersion, tags, timezone, timepicker) =
  g.dashboard.new(title=title, description=description, uid=uid, time_from=time_from, refresh=refresh, schemaVersion=schemaVersion, tags=tags, timezone=timezone, timepicker=timepicker);

local graphPanelSchema(aliasColors, title, description, nullPointMode, stack, formatY1, formatY2, labelY1, labelY2, min, fill, datasource) =
  g.graphPanel.new(aliasColors=aliasColors, title=title, description=description, nullPointMode=nullPointMode, stack=stack, formatY1=formatY1, formatY2=formatY2, labelY1=labelY1, labelY2=labelY2, min=min, fill=fill, datasource=datasource);

local addTargetSchema(expr, intervalFactor, format, legendFormat) =
  g.prometheus.target(expr=expr, intervalFactor=intervalFactor, format=format, legendFormat=legendFormat);

local addTemplateSchema(name, datasource, query, refresh, includeAll, sort, label, regex) =
  g.template.new(name=name, datasource=datasource, query=query, refresh=refresh, includeAll=includeAll, sort=sort, label=label, regex=regex);

local addAnnotationSchema(builtIn, datasource, enable, hide, iconColor, name, type) =
  g.annotation.datasource(builtIn=builtIn, datasource=datasource, enable=enable, hide=hide, iconColor=iconColor, name=name, type=type);

local addRowSchema(collapse, showTitle, title) =
  g.row.new(collapse=collapse, showTitle=showTitle, title=title);

local addSingelStatSchema(datasource, format, title, description, valueName, colorValue, gaugeMaxValue, gaugeShow, sparklineShow, thresholds) =
  g.singlestat.new(datasource=datasource, format=format, title=title, description=description, valueName=valueName, colorValue=colorValue, gaugeMaxValue=gaugeMaxValue, gaugeShow=gaugeShow, sparklineShow=sparklineShow, thresholds=thresholds);

local addPieChartSchema(aliasColors, datasource, description, legendType, pieType, title, valueName) =
  g.pieChartPanel.new(aliasColors=aliasColors, datasource=datasource, description=description, legendType=legendType, pieType=pieType, title=title, valueName=valueName);

local addTableSchema(datasource, description, sort, styles, title, transform) =
  g.tablePanel.new(datasource=datasource, description=description, sort=sort, styles=styles, title=title, transform=transform);

local addStyle(alias, colorMode, colors, dateFormat, decimals, mappingType, pattern, thresholds, type, unit, valueMaps) =
  {'alias': alias, 'colorMode': colorMode, 'colors':colors, 'dateFormat':dateFormat, 'decimals':decimals, 'mappingType':mappingType, 'pattern':pattern, 'thresholds':thresholds, 'type':type, 'unit':unit, 'valueMaps':valueMaps};

{
  "osds-overview.json":
    local OsdOverviewStyle(alias, pattern, type, unit) =
      addStyle(alias, null, ["rgba(245, 54, 54, 0.9)","rgba(237, 129, 40, 0.89)","rgba(50, 172, 45, 0.97)"], 'YYYY-MM-DD HH:mm:ss', 2, 1, pattern, [], type, unit, []);
    local OsdOverviewGraphPanel(alias, title, description, formatY1, labelY1, min, expr, legendFormat1, x, y, w, h) =
      graphPanelSchema(alias, title, description, 'null', false, formatY1, 'short', labelY1, null, min, 1, '$datasource')
      .addTargets(
        [addTargetSchema(expr, 1, 'time_series', legendFormat1)]) + {gridPos: {x: x, y: y, w: w, h: h}};
    local OsdOverviewPieChartPanel(alias, description, title) =
      addPieChartSchema(alias, '$datasource', description, 'Under graph', 'pie', title, 'current');

    dashboardSchema(
      'OSD Overview', '', 'lo02I1Aiz', 'now-1h', '10s', 16, [], '', {refresh_intervals:['5s','10s','30s','1m','5m','15m','30m','1h','2h','1d'],time_options:['5m','15m','1h','6h','12h','24h','2d','7d','30d']}
    )
    .addAnnotation(
      addAnnotationSchema(
        1, '-- Grafana --', true, true, 'rgba(0, 211, 255, 1)', 'Annotations & Alerts', 'dashboard')
    )
    .addRequired(
       type='grafana', id='grafana', name='Grafana', version='5.0.0'
    )
    .addRequired(
       type='panel', id='grafana-piechart-panel', name='Pie Chart', version='1.3.3'
    )
    .addRequired(
       type='panel', id='graph', name='Graph', version='5.0.0'
    )
    .addRequired(
       type='panel', id='table', name='Table', version='5.0.0'
    )
    .addTemplate(
       g.template.datasource('datasource', 'prometheus', 'default', label='Data Source')
    )
    .addPanels([
      OsdOverviewGraphPanel(
        {"@95%ile": "#e0752d"},'OSD Read Latencies', '', 'ms', null, '0', 'avg (irate(ceph_osd_op_r_latency_sum[1m]) / on (ceph_daemon) irate(ceph_osd_op_r_latency_count[1m]) * 1000)', 'AVG read', 0, 0, 8, 8)
      .addTargets(
        [addTargetSchema('max (irate(ceph_osd_op_r_latency_sum[1m]) / on (ceph_daemon) irate(ceph_osd_op_r_latency_count[1m]) * 1000)', 1, 'time_series', 'MAX read'),addTargetSchema('quantile(0.95,\n  (irate(ceph_osd_op_r_latency_sum[1m]) / on (ceph_daemon) irate(ceph_osd_op_r_latency_count[1m]) * 1000)\n)', 1, 'time_series', '@95%ile')],
      ),
      addTableSchema(
        '$datasource', 'This table shows the osd\'s that are delivering the 10 highest read latencies within the cluster', {"col": 2,"desc": true}, [OsdOverviewStyle('OSD ID', 'ceph_daemon', 'string', 'short'),OsdOverviewStyle('Latency (ms)', 'Value', 'number', 'none'),OsdOverviewStyle('', '/.*/', 'hidden', 'short')], 'Highest READ Latencies', 'table'
      )
      .addTarget(
        addTargetSchema('topk(10,\n  (sort(\n    (irate(ceph_osd_op_r_latency_sum[1m]) / on (ceph_daemon) irate(ceph_osd_op_r_latency_count[1m]) * 1000)\n  ))\n)\n\n', 1, 'table', '')
      ) + {gridPos: {x: 8, y: 0, w: 4, h: 8}},
      OsdOverviewGraphPanel(
        {"@95%ile write": "#e0752d"},'OSD Write Latencies', '', 'ms', null, '0', 'avg (irate(ceph_osd_op_w_latency_sum[1m]) / on (ceph_daemon) irate(ceph_osd_op_w_latency_count[1m]) * 1000)', 'AVG write', 12, 0, 8, 8)
      .addTargets(
        [addTargetSchema('max (irate(ceph_osd_op_w_latency_sum[1m]) / on (ceph_daemon) irate(ceph_osd_op_w_latency_count[1m]) * 1000)', 1, 'time_series', 'MAX write'),addTargetSchema('quantile(0.95,\n (irate(ceph_osd_op_w_latency_sum[1m]) / on (ceph_daemon) irate(ceph_osd_op_w_latency_count[1m]) * 1000)\n)', 1, 'time_series', '@95%ile write')],
      ),
      addTableSchema(
        '$datasource', 'This table shows the osd\'s that are delivering the 10 highest write latencies within the cluster', {"col": 2,"desc": true}, [OsdOverviewStyle('OSD ID', 'ceph_daemon', 'string', 'short'),OsdOverviewStyle('Latency (ms)', 'Value', 'number', 'none'),OsdOverviewStyle('', '/.*/', 'hidden', 'short')], 'Highest WRITE Latencies', 'table'
      )
      .addTarget(
        addTargetSchema('topk(10,\n  (sort(\n    (irate(ceph_osd_op_w_latency_sum[1m]) / on (ceph_daemon) irate(ceph_osd_op_w_latency_count[1m]) * 1000)\n  ))\n)\n\n', 1, 'table', '')
      ) + {gridPos: {x: 20, y: 0, w: 4, h: 8}},
      OsdOverviewPieChartPanel(
        {}, '', 'OSD Types Summary'
      )
      .addTarget(addTargetSchema('count by (device_class) (ceph_osd_metadata)', 1, 'time_series', '{{device_class}}')) + {gridPos: {x: 0, y: 8, w: 4, h: 8}},
      OsdOverviewPieChartPanel(
        {"Non-Encrypted": "#E5AC0E"}, '', 'OSD Objectstore Types'
      )
      .addTarget(addTargetSchema('count(ceph_bluefs_wal_total_bytes)', 1, 'time_series', 'bluestore'))
      .addTarget(addTargetSchema('count(ceph_osd_metadata) - count(ceph_bluefs_wal_total_bytes)', 1, 'time_series', 'filestore'))
      .addTarget(addTargetSchema('absent(ceph_bluefs_wal_total_bytes)*count(ceph_osd_metadata)', 1, 'time_series', 'filestore')) + {gridPos: {x: 4, y: 8, w: 4, h: 8}},
      OsdOverviewPieChartPanel(
        {}, 'The pie chart shows the various OSD sizes used within the cluster', 'OSD Size Summary'
      )
      .addTarget(addTargetSchema('count(ceph_osd_stat_bytes < 1099511627776)', 1, 'time_series', '<1TB'))
      .addTarget(addTargetSchema('count(ceph_osd_stat_bytes >= 1099511627776 < 2199023255552)', 1, 'time_series', '<2TB'))
      .addTarget(addTargetSchema('count(ceph_osd_stat_bytes >= 2199023255552 < 3298534883328)', 1, 'time_series', '<3TB'))
      .addTarget(addTargetSchema('count(ceph_osd_stat_bytes >= 3298534883328 < 4398046511104)', 1, 'time_series', '<4TB'))
      .addTarget(addTargetSchema('count(ceph_osd_stat_bytes >= 4398046511104 < 6597069766656)', 1, 'time_series', '<6TB'))
      .addTarget(addTargetSchema('count(ceph_osd_stat_bytes >= 6597069766656 < 8796093022208)', 1, 'time_series', '<8TB'))
      .addTarget(addTargetSchema('count(ceph_osd_stat_bytes >= 8796093022208 < 10995116277760)', 1, 'time_series', '<10TB'))
      .addTarget(addTargetSchema('count(ceph_osd_stat_bytes >= 10995116277760 < 13194139533312)', 1, 'time_series', '<12TB'))
      .addTarget(addTargetSchema('count(ceph_osd_stat_bytes >= 13194139533312)', 1, 'time_series', '<12TB+')) + {gridPos: {x: 8, y: 8, w: 4, h: 8}},
      g.graphPanel.new(bars=true, datasource='$datasource', title='Distribution of PGs per OSD', x_axis_buckets=20, x_axis_mode='histogram', x_axis_values=['total'], formatY1='short', formatY2='short', labelY1='# of OSDs', min='0', nullPointMode='null')
      .addTarget(addTargetSchema('ceph_osd_numpg\n', 1, 'time_series', 'PGs per OSD')) + {gridPos: {x: 12, y: 8, w: 12, h: 8}},
      addRowSchema(false, true, 'R/W Profile') + {gridPos: {x: 0, y: 16, w: 24, h: 1}},
      OsdOverviewGraphPanel(
        {},'Read/Write Profile', 'Show the read/write workload profile overtime', 'short', null, null, 'round(sum(irate(ceph_pool_rd[30s])))', 'Reads', 0, 17, 24, 8)
      .addTargets([addTargetSchema('round(sum(irate(ceph_pool_wr[30s])))', 1, 'time_series', 'Writes')])
      ])   
}
{
  "osd-device-details.json":
    local OsdDeviceDetailsPanel(title, description, formatY1, labelY1, expr1, expr2, legendFormat1, legendFormat2, x, y, w, h) =
      graphPanelSchema({}, title, description, 'null', false, formatY1, 'short', labelY1, null, null, 1, '$datasource')
      .addTargets(
        [addTargetSchema(expr1, 1, 'time_series', legendFormat1),addTargetSchema(expr2, 1, 'time_series', legendFormat2)]) + {gridPos: {x: x, y: y, w: w, h: h}};

    dashboardSchema(
      'OSD device details', '', 'CrAHE0iZz', 'now-3h', '', 16, [], '', {refresh_intervals:['5s','10s','30s','1m','5m','15m','30m','1h','2h','1d'],time_options:['5m','15m','1h','6h','12h','24h','2d','7d','30d']}
    )
    .addAnnotation(
      addAnnotationSchema(
        1, '-- Grafana --', true, true, 'rgba(0, 211, 255, 1)', 'Annotations & Alerts', 'dashboard')
    )
    .addRequired(
       type='grafana', id='grafana', name='Grafana', version='5.3.2'
    )
    .addRequired(
       type='panel', id='graph', name='Graph', version='5.0.0'
    )
    .addTemplate(
       g.template.datasource('datasource', 'prometheus', 'default', label='Data Source')
    )
    .addTemplate(
       addTemplateSchema('osd', '$datasource', 'label_values(ceph_osd_metadata,ceph_daemon)', 1, false, 1, 'OSD', '(.*)')
    )
    .addPanels([
      addRowSchema(false, true, 'OSD Performance') + {gridPos: {x: 0, y: 0, w: 24, h: 1}},
      OsdDeviceDetailsPanel(
        '$osd Latency', '', 's', 'Read (-) / Write (+)', 'irate(ceph_osd_op_r_latency_sum{ceph_daemon=~\"$osd\"}[1m]) / on (ceph_daemon) irate(ceph_osd_op_r_latency_count[1m])', 'irate(ceph_osd_op_w_latency_sum{ceph_daemon=~\"$osd\"}[1m]) / on (ceph_daemon) irate(ceph_osd_op_w_latency_count[1m])', 'read', 'write', 0, 1, 6, 9)
      .addSeriesOverride({"alias": "read","transform": "negative-Y"}
      ),
      OsdDeviceDetailsPanel(
        '$osd R/W IOPS', '', 'short', 'Read (-) / Write (+)', 'irate(ceph_osd_op_r{ceph_daemon=~\"$osd\"}[1m])', 'irate(ceph_osd_op_w{ceph_daemon=~\"$osd\"}[1m])', 'Reads', 'Writes', 6, 1, 6, 9)
      .addSeriesOverride({"alias": "Reads","transform": "negative-Y"}
      ),
      OsdDeviceDetailsPanel(
        '$osd R/W Bytes', '', 'bytes', 'Read (-) / Write (+)', 'irate(ceph_osd_op_r_out_bytes{ceph_daemon=~\"$osd\"}[1m])', 'irate(ceph_osd_op_w_in_bytes{ceph_daemon=~\"$osd\"}[1m])', 'Read Bytes', 'Write Bytes', 12, 1, 6, 9)
      .addSeriesOverride({"alias": "Read Bytes","transform": "negative-Y"}),
      addRowSchema(false, true, 'Physical Device Performance') + {gridPos: {x: 0, y: 10, w: 24, h: 1}},
      OsdDeviceDetailsPanel(
        'Physical Device Latency for $osd', '', 's', 'Read (-) / Write (+)', '(label_replace(irate(node_disk_read_time_seconds_total[1m]) / irate(node_disk_reads_completed_total[1m]), \"instance\", \"$1\", \"instance\", \"([^:.]*).*\") and on (instance, device) label_replace(label_replace(ceph_disk_occupation{ceph_daemon=~\"$osd\"}, \"device\", \"$1\", \"device\", \"/dev/(.*)\"), \"instance\", \"$1\", \"instance\", \"([^:.]*).*\"))', '(label_replace(irate(node_disk_write_time_seconds_total[1m]) / irate(node_disk_writes_completed_total[1m]), \"instance\", \"$1\", \"instance\", \"([^:.]*).*\") and on (instance, device) label_replace(label_replace(ceph_disk_occupation{ceph_daemon=~\"$osd\"}, \"device\", \"$1\", \"device\", \"/dev/(.*)\"), \"instance\", \"$1\", \"instance\", \"([^:.]*).*\"))', '{{instance}}/{{device}} Reads', '{{instance}}/{{device}} Writes', 0, 11, 6, 9)
      .addSeriesOverride({"alias": "/.*Reads/","transform": "negative-Y"}
      ),
      OsdDeviceDetailsPanel(
        'Physical Device R/W IOPS for $osd', '', 'short', 'Read (-) / Write (+)', 'label_replace(irate(node_disk_writes_completed_total[1m]), \"instance\", \"$1\", \"instance\", \"([^:.]*).*\") and on (instance, device) label_replace(label_replace(ceph_disk_occupation{ceph_daemon=~\"$osd\"}, \"device\", \"$1\", \"device\", \"/dev/(.*)\"), \"instance\", \"$1\", \"instance\", \"([^:.]*).*\")', 'label_replace(irate(node_disk_reads_completed_total[1m]), \"instance\", \"$1\", \"instance\", \"([^:.]*).*\") and on (instance, device) label_replace(label_replace(ceph_disk_occupation{ceph_daemon=~\"$osd\"}, \"device\", \"$1\", \"device\", \"/dev/(.*)\"), \"instance\", \"$1\", \"instance\", \"([^:.]*).*\")', '{{device}} on {{instance}} Writes', '{{device}} on {{instance}} Reads', 6, 11, 6, 9)
      .addSeriesOverride({"alias": "/.*Reads/","transform": "negative-Y"}
      ),
      OsdDeviceDetailsPanel(
        'Physical Device R/W Bytes for $osd', '', 'Bps', 'Read (-) / Write (+)', 'label_replace(irate(node_disk_read_bytes_total[1m]), \"instance\", \"$1\", \"instance\", \"([^:.]*).*\") and on (instance, device) label_replace(label_replace(ceph_disk_occupation{ceph_daemon=~\"$osd\"}, \"device\", \"$1\", \"device\", \"/dev/(.*)\"), \"instance\", \"$1\", \"instance\", \"([^:.]*).*\")', 'label_replace(irate(node_disk_written_bytes_total[1m]), \"instance\", \"$1\", \"instance\", \"([^:.]*).*\") and on (instance, device) label_replace(label_replace(ceph_disk_occupation{ceph_daemon=~\"$osd\"}, \"device\", \"$1\", \"device\", \"/dev/(.*)\"), \"instance\", \"$1\", \"instance\", \"([^:.]*).*\")', '{{instance}} {{device}} Reads', '{{instance}} {{device}} Writes', 12, 11, 6, 9)
      .addSeriesOverride({"alias": "/.*Reads/","transform": "negative-Y"}
      ),
      graphPanelSchema(
        {}, 'Physical Device Util% for $osd', '', 'null', false, 'percentunit', 'short', null, null, null, 1, '$datasource'
      )
      .addTarget(addTargetSchema('label_replace(irate(node_disk_io_time_seconds_total[1m]), \"instance\", \"$1\", \"instance\", \"([^:.]*).*\") and on (instance, device) label_replace(label_replace(ceph_disk_occupation{ceph_daemon=~\"$osd\"}, \"device\", \"$1\", \"device\", \"/dev/(.*)\"), \"instance\", \"$1\", \"instance\", \"([^:.]*).*\")', 1, 'time_series', '{{device}} on {{instance}}')) + {gridPos: {x: 18, y: 11, w: 6, h: 9}},
    ])
}