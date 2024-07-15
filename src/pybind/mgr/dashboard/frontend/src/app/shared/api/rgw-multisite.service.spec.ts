import { HttpClientTestingModule, HttpTestingController } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { configureTestBed } from '~/testing/unit-test-helper';
import { RgwMultisiteService } from './rgw-multisite.service';

const mockSyncPolicyData: any = [
  {
    id: 'test',
    data_flow: {},
    pipes: [],
    status: 'enabled',
    bucketName: 'test'
  },
  {
    id: 'test',
    data_flow: {},
    pipes: [],
    status: 'enabled'
  }
];

describe('RgwMultisiteService', () => {
  let service: RgwMultisiteService;
  let httpTesting: HttpTestingController;

  configureTestBed({
    providers: [RgwMultisiteService],
    imports: [HttpClientTestingModule]
  });

  beforeEach(() => {
    service = TestBed.inject(RgwMultisiteService);
    httpTesting = TestBed.inject(HttpTestingController);
  });

  afterEach(() => {
    httpTesting.verify();
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });

  it('should fetch all the sync policy related or un-related to a bucket', () => {
    service.getSyncPolicy('', '', true).subscribe();
    const req = httpTesting.expectOne('api/rgw/multisite/sync-policy?all_policy=true');
    expect(req.request.method).toBe('GET');
    req.flush(mockSyncPolicyData);
  });

  it('should create Sync Policy Group w/o bucket_name', () => {
    const postData = { group_id: 'test', status: 'enabled' };
    service.createSyncPolicyGroup(postData).subscribe();
    const req = httpTesting.expectOne('api/rgw/multisite/sync-policy-group');
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual(postData);
    req.flush(null);
  });

  it('should create Sync Policy Group with bucket_name', () => {
    const postData = { group_id: 'test', status: 'enabled', bucket_name: 'test' };
    service.createSyncPolicyGroup(postData).subscribe();
    const req = httpTesting.expectOne('api/rgw/multisite/sync-policy-group');
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual(postData);
    req.flush(null);
  });

  it('should modify Sync Policy Group', () => {
    const postData = { group_id: 'test', status: 'enabled', bucket_name: 'test' };
    service.modifySyncPolicyGroup(postData).subscribe();
    const req = httpTesting.expectOne('api/rgw/multisite/sync-policy-group');
    expect(req.request.method).toBe('PUT');
    expect(req.request.body).toEqual(postData);
    req.flush(null);
  });

  it('should remove Sync Policy Group', () => {
    const group_id = 'test';
    service.removeSyncPolicyGroup(group_id).subscribe();
    const req = httpTesting.expectOne('api/rgw/multisite/sync-policy-group/' + group_id);
    expect(req.request.method).toBe('DELETE');
    req.flush(null);
  });

  it('should fetch the sync policy group with given group_id and bucket_name', () => {
    service.getSyncPolicyGroup('test', 'test').subscribe();
    const req = httpTesting.expectOne('api/rgw/multisite/sync-policy-group/test?bucket_name=test');
    expect(req.request.method).toBe('GET');
    req.flush(mockSyncPolicyData[1]);
  });
});
