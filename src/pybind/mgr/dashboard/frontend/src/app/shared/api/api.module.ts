import { CommonModule } from '@angular/common';
import { NgModule } from '@angular/core';

import { AuthService } from './auth.service';
import { CephfsService } from './cephfs.service';
import { ConfigurationService } from './configuration.service';
import { DashboardService } from './dashboard.service';
import { HostService } from './host.service';
import { MonitorService } from './monitor.service';
import { OsdService } from './osd.service';
import { PoolService } from './pool.service';
import { RbdMirroringService } from './rbd-mirroring.service';
import { RgwDaemonService } from './rgw-daemon.service';
import { TablePerformanceCounterService } from './table-performance-counter.service';
import { TcmuIscsiService } from './tcmu-iscsi.service';
import { UserService } from './user.service';

@NgModule({
  imports: [CommonModule],
  declarations: [],
  providers: [
    AuthService,
    CephfsService,
    ConfigurationService,
    DashboardService,
    HostService,
    MonitorService,
    OsdService,
    PoolService,
    RbdMirroringService,
    RgwDaemonService,
    TablePerformanceCounterService,
    TcmuIscsiService,
    UserService
  ]
})
export class ApiModule {}
