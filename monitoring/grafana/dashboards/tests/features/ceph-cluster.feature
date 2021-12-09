Feature: Ceph Cluster Dashboard

Scenario: "Test total PG States"
  Given the following series:
    | metrics                  | values |
    | ceph_pg_total{foo="var"} | 10 100 |
    | ceph_pg_total{foo="bar"} | 20 200 |
  Then Grafana panel `PG States` with legend `Total` shows:
    | metrics | values |
    | {}      | 300    |

Scenario: "Test OSDs in"
  Given the following series:
    | metrics                          | values |
    | ceph_osd_in{ceph_daemon="osd.0"} | 1.0    |
    | ceph_osd_in{ceph_daemon="osd.1"} | 0.0    |
    | ceph_osd_in{ceph_daemon="osd.2"} | 1.0    |
  When variable `instance` is `.*`
  Then Grafana panel `OSDs` with legend `In` shows:
    | metrics | values |
    | {}      | 2      |
