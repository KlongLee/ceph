import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';

import { RgwBucketService } from './rgw-bucket.service';
import { configureTestBed, RgwHelper } from '~/testing/unit-test-helper';

describe('RgwBucketService', () => {
  let service: RgwBucketService;
  let httpTesting: HttpTestingController;

  configureTestBed({
    providers: [RgwBucketService],
    imports: [HttpClientTestingModule]
  });

  beforeEach(() => {
    service = TestBed.inject(RgwBucketService);
    httpTesting = TestBed.inject(HttpTestingController);
    RgwHelper.selectDaemon();
  });

  afterEach(() => {
    httpTesting.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should call list', () => {
    service.list().subscribe();
    const req = httpTesting.expectOne(`api/rgw/bucket?${RgwHelper.DAEMON_QUERY_PARAM}&stats=true`);
    expect(req.request.method).toBe('GET');
  });

  it('should call get', () => {
    service.get('foo').subscribe();
    const req = httpTesting.expectOne(`api/rgw/bucket/foo?${RgwHelper.DAEMON_QUERY_PARAM}`);
    expect(req.request.method).toBe('GET');
  });

  it('should call create', () => {
    service
      .create('foo', 'bar', 'default', 'default-placement', false, 'COMPLIANCE', '5')
      .subscribe();
    const req = httpTesting.expectOne(
      `api/rgw/bucket?bucket=foo&uid=bar&zonegroup=default&placement_target=default-placement&lock_enabled=false&lock_mode=COMPLIANCE&lock_retention_period_days=5&${RgwHelper.DAEMON_QUERY_PARAM}`
    );
    expect(req.request.method).toBe('POST');
  });

  it('should call update', () => {
    service
      .update('foo', 'bar', 'baz', 'Enabled', 'Enabled', '1', '223344', 'GOVERNANCE', '10')
      .subscribe();
    const req = httpTesting.expectOne(
      `api/rgw/bucket/foo?${RgwHelper.DAEMON_QUERY_PARAM}&bucket_id=bar&uid=baz&versioning_state=Enabled&mfa_delete=Enabled&mfa_token_serial=1&mfa_token_pin=223344&lock_mode=GOVERNANCE&lock_retention_period_days=10`
    );
    expect(req.request.method).toBe('PUT');
  });

  it('should call delete, with purgeObjects = true', () => {
    service.delete('foo').subscribe();
    const req = httpTesting.expectOne(
      `api/rgw/bucket/foo?${RgwHelper.DAEMON_QUERY_PARAM}&purge_objects=true`
    );
    expect(req.request.method).toBe('DELETE');
  });

  it('should call delete, with purgeObjects = false', () => {
    service.delete('foo', false).subscribe();
    const req = httpTesting.expectOne(
      `api/rgw/bucket/foo?${RgwHelper.DAEMON_QUERY_PARAM}&purge_objects=false`
    );
    expect(req.request.method).toBe('DELETE');
  });

  it('should call exists', () => {
    let result;
    service.exists('foo').subscribe((resp) => {
      result = resp;
    });
    const req = httpTesting.expectOne(`api/rgw/bucket/foo?${RgwHelper.DAEMON_QUERY_PARAM}`);
    expect(req.request.method).toBe('GET');
    req.flush(['foo', 'bar']);
    expect(result).toBe(true);
  });

  it('should convert lock retention period to days', () => {
    expect(service.getLockDays({ lock_retention_period_years: 1000 })).toBe(365242);
    expect(service.getLockDays({ lock_retention_period_days: 5 })).toBe(5);
    expect(service.getLockDays({})).toBe(0);
  });
});
