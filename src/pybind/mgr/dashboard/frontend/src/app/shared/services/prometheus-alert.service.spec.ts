import { HttpClientTestingModule } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';

import { ToastModule } from 'ng2-toastr';
import { of } from 'rxjs';

import {
  configureTestBed,
  i18nProviders,
  PrometheusHelper
} from '../../../testing/unit-test-helper';
import { PrometheusService } from '../api/prometheus.service';
import { NotificationType } from '../enum/notification-type.enum';
import { CdNotificationConfig } from '../models/cd-notification';
import { PrometheusAlert } from '../models/prometheus-alerts';
import { SharedModule } from '../shared.module';
import { NotificationService } from './notification.service';
import { PrometheusAlertFormatter } from './prometheus-alert-formatter';
import { PrometheusAlertService } from './prometheus-alert.service';

describe('PrometheusAlertService', () => {
  let service: PrometheusAlertService;
  let notificationService: NotificationService;
  let alerts: PrometheusAlert[];
  let prometheusService: PrometheusService;
  let prometheus: PrometheusHelper;

  configureTestBed({
    imports: [ToastModule.forRoot(), SharedModule, HttpClientTestingModule],
    providers: [PrometheusAlertService, PrometheusAlertFormatter, i18nProviders]
  });

  beforeEach(() => {
    prometheus = new PrometheusHelper();
  });

  it('should create', () => {
    expect(TestBed.get(PrometheusAlertService)).toBeTruthy();
  });

  describe('test error cases', () => {
    const expectDisabling = (status, expectation) => {
      let disabledSetting = false;
      const resp = { status: status, error: {} };
      service = new PrometheusAlertService(null, ({
        ifAlertmanagerConfigured: (fn) => fn(),
        list: () => ({ subscribe: (fn, err) => err(resp) }),
        disableAlertmanagerConfig: () => (disabledSetting = true)
      } as object) as PrometheusService);
      service.refresh();
      expect(disabledSetting).toBe(expectation);
    };

    it('disables on 504 error which is thrown if the mgr failed', () => {
      expectDisabling(504, true);
    });

    it('disables on 404 error which is thrown if the external api cannot be reached', () => {
      expectDisabling(404, true);
    });

    it('does not disable on 400 error which is thrown if the external api receives unexpected data', () => {
      expectDisabling(400, false);
    });
  });

  describe('refresh', () => {
    beforeEach(() => {
      service = TestBed.get(PrometheusAlertService);
      service['alerts'] = [];
      service['canAlertsBeNotified'] = false;

      spyOn(window, 'setTimeout').and.callFake((fn: Function) => fn());

      notificationService = TestBed.get(NotificationService);
      spyOn(notificationService, 'queueNotifications').and.callThrough();
      spyOn(notificationService, 'show').and.stub();

      prometheusService = TestBed.get(PrometheusService);
      spyOn(prometheusService, 'ifAlertmanagerConfigured').and.callFake((fn) => fn());
      spyOn(prometheusService, 'list').and.callFake(() => of(alerts));

      alerts = [prometheus.createAlert('alert0')];
      service.refresh();
    });

    it('should not notify on first call', () => {
      expect(notificationService.show).not.toHaveBeenCalled();
    });

    it('should not notify with no change', () => {
      service.refresh();
      expect(notificationService.show).not.toHaveBeenCalled();
    });

    it('should notify on alert change', () => {
      alerts = [prometheus.createAlert('alert0', 'suppressed')];
      service.refresh();
      expect(notificationService.queueNotifications).toHaveBeenCalledWith([
        new CdNotificationConfig(
          NotificationType.info,
          'alert0 (suppressed)',
          'alert0 is suppressed ' + prometheus.createLink('http://alert0'),
          undefined,
          'Prometheus'
        )
      ]);
    });

    it('should notify on a new alert', () => {
      alerts = [prometheus.createAlert('alert1'), prometheus.createAlert('alert0')];
      service.refresh();
      expect(notificationService.show).toHaveBeenCalledTimes(1);
      expect(notificationService.show).toHaveBeenCalledWith(
        new CdNotificationConfig(
          NotificationType.error,
          'alert1 (active)',
          'alert1 is active ' + prometheus.createLink('http://alert1'),
          undefined,
          'Prometheus'
        )
      );
    });

    it('should notify a resolved alert if it is not there anymore', () => {
      alerts = [];
      service.refresh();
      expect(notificationService.show).toHaveBeenCalledTimes(1);
      expect(notificationService.show).toHaveBeenCalledWith(
        new CdNotificationConfig(
          NotificationType.success,
          'alert0 (resolved)',
          'alert0 is active ' + prometheus.createLink('http://alert0'),
          undefined,
          'Prometheus'
        )
      );
    });

    it('should call multiple times for multiple changes', () => {
      const alert1 = prometheus.createAlert('alert1');
      alerts.push(alert1);
      service.refresh();
      alerts = [alert1, prometheus.createAlert('alert2')];
      service.refresh();
      expect(notificationService.queueNotifications).toHaveBeenCalledWith([
        new CdNotificationConfig(
          NotificationType.error,
          'alert2 (active)',
          'alert2 is active ' + prometheus.createLink('http://alert2'),
          undefined,
          'Prometheus'
        ),
        new CdNotificationConfig(
          NotificationType.success,
          'alert0 (resolved)',
          'alert0 is active ' + prometheus.createLink('http://alert0'),
          undefined,
          'Prometheus'
        )
      ]);
    });
  });
});
