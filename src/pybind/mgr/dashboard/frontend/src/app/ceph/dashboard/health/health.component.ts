import { Component, OnDestroy, OnInit } from '@angular/core';

import { I18n } from '@ngx-translate/i18n-polyfill';
import * as _ from 'lodash';
import { Subscription } from 'rxjs/Subscription';

import { HealthService } from '../../../shared/api/health.service';
import { Permissions } from '../../../shared/models/permissions';
import { DimlessBinaryPipe } from '../../../shared/pipes/dimless-binary.pipe';
import { AuthStorageService } from '../../../shared/services/auth-storage.service';
import {
  FeatureTogglesMap$,
  FeatureTogglesService
} from '../../../shared/services/feature-toggles.service';
import { RefreshIntervalService } from '../../../shared/services/refresh-interval.service';
import { PgCategoryService } from '../../shared/pg-category.service';
import { HealthPieColor } from '../health-pie/health-pie-color.enum';

@Component({
  selector: 'cd-health',
  templateUrl: './health.component.html',
  styleUrls: ['./health.component.scss']
})
export class HealthComponent implements OnInit, OnDestroy {
  healthData: any;
  interval = new Subscription();
  permissions: Permissions;
  enabledFeature$: FeatureTogglesMap$;

  constructor(
    private healthService: HealthService,
    private i18n: I18n,
    private authStorageService: AuthStorageService,
    private pgCategoryService: PgCategoryService,
    private featureToggles: FeatureTogglesService,
    private refreshIntervalService: RefreshIntervalService,
    private dimlessBinary: DimlessBinaryPipe
  ) {
    this.permissions = this.authStorageService.getPermissions();
    this.enabledFeature$ = this.featureToggles.get();
  }

  ngOnInit() {
    this.getHealth();
    this.interval = this.refreshIntervalService.intervalData$.subscribe(() => {
      this.getHealth();
    });
  }

  ngOnDestroy() {
    this.interval.unsubscribe();
  }

  getHealth() {
    this.healthService.getMinimalHealth().subscribe((data: any) => {
      this.healthData = data;
    });
  }

  prepareReadWriteRatio(chart) {
    const ratioLabels = [];
    const ratioData = [];

    const total =
      this.healthData.client_perf.write_op_per_sec + this.healthData.client_perf.read_op_per_sec;
    const calcPercentage = (status) =>
      Math.round(((this.healthData.client_perf[status] || 0) / total) * 100);

    ratioLabels.push(`${this.i18n('Writes')} (${calcPercentage('write_op_per_sec')}%)`);
    ratioData.push(this.healthData.client_perf.write_op_per_sec);
    ratioLabels.push(`${this.i18n('Reads')} (${calcPercentage('read_op_per_sec')}%)`);
    ratioData.push(this.healthData.client_perf.read_op_per_sec);

    chart.dataset[0].data = ratioData;
    chart.labels = ratioLabels;
  }

  prepareRawUsage(chart, data) {
    const percentAvailable = Math.round(
      100 *
        ((data.df.stats.total_bytes - data.df.stats.total_used_raw_bytes) /
          data.df.stats.total_bytes)
    );

    const percentUsed = Math.round(
      100 * (data.df.stats.total_used_raw_bytes / data.df.stats.total_bytes)
    );

    chart.dataset[0].data = [data.df.stats.total_used_raw_bytes, data.df.stats.total_avail_bytes];
    if (chart === 'doughnut') {
      chart.options.cutoutPercentage = 65;
    }
    chart.labels = [
      `${this.dimlessBinary.transform(data.df.stats.total_used_raw_bytes)} ${this.i18n(
        'Used'
      )} (${percentUsed}%)`,
      `${this.dimlessBinary.transform(
        data.df.stats.total_bytes - data.df.stats.total_used_raw_bytes
      )} ${this.i18n('Avail.')} (${percentAvailable}%)`
    ];

    chart.options.title = {
      display: true,
      text: `${this.dimlessBinary.transform(data.df.stats.total_bytes)} total`,
      position: 'bottom'
    };
  }

  preparePgStatus(chart, data) {
    const categoryPgAmount = {};
    chart.colors = [
      {
        backgroundColor: [
          HealthPieColor.DEFAULT_GREEN,
          HealthPieColor.DEFAULT_BLUE,
          HealthPieColor.DEFAULT_ORANGE,
          HealthPieColor.DEFAULT_RED
        ]
      }
    ];

    _.forEach(data.pg_info.statuses, (pgAmount, pgStatesText) => {
      const categoryType = this.pgCategoryService.getTypeByStates(pgStatesText);

      if (_.isUndefined(categoryPgAmount[categoryType])) {
        categoryPgAmount[categoryType] = 0;
      }
      categoryPgAmount[categoryType] += pgAmount;
    });

    chart.dataset[0].data = this.pgCategoryService
      .getAllTypes()
      .map((categoryType) => categoryPgAmount[categoryType]);

    const calcPercentage = (status) =>
      Math.round(((categoryPgAmount[status] || 0) / data.pg_info.pgs_per_osd) * 100) || 0;

    chart.labels = [
      `${this.i18n('Clean')} (${calcPercentage('clean')}%)`,
      `${this.i18n('Working')} (${calcPercentage('working')}%)`,
      `${this.i18n('Warning')} (${calcPercentage('warning')}%)`,
      `${this.i18n('Unknown')} (${calcPercentage('unknown')}%)`
    ];
  }

  isClientReadWriteChartShowable() {
    const readOps = this.healthData.client_perf.read_op_per_sec || 0;
    const writeOps = this.healthData.client_perf.write_op_per_sec || 0;

    return readOps + writeOps > 0;
  }
}
