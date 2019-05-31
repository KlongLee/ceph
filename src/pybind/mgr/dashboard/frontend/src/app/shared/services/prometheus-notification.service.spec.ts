import { HttpClientTestingModule } from '@angular/common/http/testing';
import { fakeAsync, TestBed, tick } from '@angular/core/testing';

import { ToastModule, ToastsManager } from 'ng2-toastr';
import { of } from 'rxjs';

import {
  configureTestBed,
  i18nProviders,
  PrometheusHelper
} from '../../../testing/unit-test-helper';
import { PrometheusService } from '../api/prometheus.service';
import { NotificationType } from '../enum/notification-type.enum';
import { CdNotificationConfig } from '../models/cd-notification';
import { PrometheusNotification } from '../models/prometheus-alerts';
import { SharedModule } from '../shared.module';
import { NotificationService } from './notification.service';
import { PrometheusAlertFormatter } from './prometheus-alert-formatter';
import { PrometheusNotificationService } from './prometheus-notification.service';

describe('PrometheusNotificationService', () => {
  let service: PrometheusNotificationService;
  let notificationService: NotificationService;
  let notifications: PrometheusNotification[];
  let prometheusService: PrometheusService;
  let prometheus: PrometheusHelper;
  let shown: CdNotificationConfig[];

  const toastFakeService = {
    error: () => true,
    info: () => true,
    success: () => true
  };

  configureTestBed({
    imports: [ToastModule.forRoot(), SharedModule, HttpClientTestingModule],
    providers: [
      PrometheusNotificationService,
      PrometheusAlertFormatter,
      i18nProviders,
      { provide: ToastsManager, useValue: toastFakeService }
    ]
  });

  beforeEach(() => {
    prometheus = new PrometheusHelper();

    service = TestBed.get(PrometheusNotificationService);
    service['notifications'] = [];

    notificationService = TestBed.get(NotificationService);
    shown = [];
    spyOn(notificationService, 'show').and.callThrough();
    spyOn(notificationService, 'save').and.callFake((n) => shown.push(n));

    spyOn(window, 'setTimeout').and.callFake((fn: Function) => fn());

    prometheusService = TestBed.get(PrometheusService);
    spyOn(prometheusService, 'getNotifications').and.callFake(() => of(notifications));

    notifications = [prometheus.createNotification()];
  });

  it('should create', () => {
    expect(service).toBeTruthy();
  });

  describe('getLastNotification', () => {
    it('returns an empty object on the first call', () => {
      service.refresh();
      expect(prometheusService.getNotifications).toHaveBeenCalledWith(undefined);
      expect(service['notifications'].length).toBe(1);
    });

    it('returns last notification on any other call', () => {
      service.refresh();
      notifications = [prometheus.createNotification(1, 'resolved')];
      service.refresh();
      expect(prometheusService.getNotifications).toHaveBeenCalledWith(service['notifications'][0]);
      expect(service['notifications'].length).toBe(2);

      notifications = [prometheus.createNotification(2)];
      service.refresh();
      notifications = [prometheus.createNotification(3, 'resolved')];
      service.refresh();
      expect(prometheusService.getNotifications).toHaveBeenCalledWith(service['notifications'][2]);
      expect(service['notifications'].length).toBe(4);
    });
  });

  it('notifies not on the first call', () => {
    service.refresh();
    expect(notificationService.show).not.toHaveBeenCalled();
  });

  describe('looks of fired notifications', () => {
    const asyncRefresh = () => {
      service.refresh();
      tick(20);
    };

    const expectShown = (expected: {}[]) => {
      tick(500);
      expect(shown.length).toBe(expected.length);
      expected.forEach((e, i) =>
        Object.keys(e).forEach((key) => expect(shown[i][key]).toEqual(expected[i][key]))
      );
    };

    beforeEach(() => {
      service.refresh();
    });

    it('notifies on the second call', () => {
      service.refresh();
      expect(notificationService.show).toHaveBeenCalledTimes(1);
    });

    it('notify looks on single notification with single alert like', fakeAsync(() => {
      asyncRefresh();
      expectShown([
        new CdNotificationConfig(
          NotificationType.error,
          'alert0 (active)',
          'alert0 is firing ' + prometheus.createLink('http://alert0'),
          undefined,
          'Prometheus'
        )
      ]);
    }));

    it('raises multiple pop overs for a single notification with multiple alerts', fakeAsync(() => {
      asyncRefresh();
      notifications[0].alerts.push(prometheus.createNotificationAlert('alert1', 'resolved'));
      asyncRefresh();
      expectShown([
        new CdNotificationConfig(
          NotificationType.error,
          'alert0 (active)',
          'alert0 is firing ' + prometheus.createLink('http://alert0'),
          undefined,
          'Prometheus'
        ),
        new CdNotificationConfig(
          NotificationType.success,
          'alert1 (resolved)',
          'alert1 is resolved ' + prometheus.createLink('http://alert1'),
          undefined,
          'Prometheus'
        )
      ]);
    }));

    it('should raise multiple notifications if they do not look like each other', fakeAsync(() => {
      notifications[0].alerts.push(prometheus.createNotificationAlert('alert1'));
      notifications.push(prometheus.createNotification());
      notifications[1].alerts.push(prometheus.createNotificationAlert('alert2'));
      asyncRefresh();
      expectShown([
        new CdNotificationConfig(
          NotificationType.error,
          'alert0 (active)',
          'alert0 is firing ' + prometheus.createLink('http://alert0'),
          undefined,
          'Prometheus'
        ),
        new CdNotificationConfig(
          NotificationType.error,
          'alert1 (active)',
          'alert1 is firing ' + prometheus.createLink('http://alert1'),
          undefined,
          'Prometheus'
        ),
        new CdNotificationConfig(
          NotificationType.error,
          'alert2 (active)',
          'alert2 is firing ' + prometheus.createLink('http://alert2'),
          undefined,
          'Prometheus'
        )
      ]);
    }));

    it('only shows toasties if it got new data', () => {
      service.refresh();
      expect(notificationService.show).toHaveBeenCalledTimes(1);
      notifications = [];
      service.refresh();
      service.refresh();
      expect(notificationService.show).toHaveBeenCalledTimes(1);
      notifications = [prometheus.createNotification()];
      service.refresh();
      expect(notificationService.show).toHaveBeenCalledTimes(2);
      service.refresh();
      expect(notificationService.show).toHaveBeenCalledTimes(3);
    });

    it('filters out duplicated and non user visible changes in notifications', fakeAsync(() => {
      // Return 2 notifications with 3 duplicated alerts and 1 non visible changed alert
      const secondAlert = prometheus.createNotificationAlert('alert0');
      secondAlert.endsAt = new Date().toString(); // Should be ignored as it's not visible
      notifications[0].alerts.push(secondAlert);
      notifications.push(prometheus.createNotification());
      notifications[1].alerts.push(prometheus.createNotificationAlert('alert0'));
      notifications[1].notified = 'by somebody else';
      asyncRefresh();

      expectShown([
        new CdNotificationConfig(
          NotificationType.error,
          'alert0 (active)',
          'alert0 is firing ' + prometheus.createLink('http://alert0'),
          undefined,
          'Prometheus'
        )
      ]);
    }));
  });
});
