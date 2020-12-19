import { HttpClientTestingModule } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';

import { NgbNavModule } from '@ng-bootstrap/ng-bootstrap';

import { PerformanceCounterModule } from '~/app/ceph/performance-counter/performance-counter.module';
import { SharedModule } from '~/app/shared/shared.module';
import { configureTestBed } from '~/testing/unit-test-helper';
import { RgwDaemonDetailsComponent } from './rgw-daemon-details.component';

describe('RgwDaemonDetailsComponent', () => {
  let component: RgwDaemonDetailsComponent;
  let fixture: ComponentFixture<RgwDaemonDetailsComponent>;

  configureTestBed({
    declarations: [RgwDaemonDetailsComponent],
    imports: [SharedModule, PerformanceCounterModule, HttpClientTestingModule, NgbNavModule]
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(RgwDaemonDetailsComponent);
    component = fixture.componentInstance;
    component.selection = undefined;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
