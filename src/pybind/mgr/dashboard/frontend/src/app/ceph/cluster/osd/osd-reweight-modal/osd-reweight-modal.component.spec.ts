import { HttpClientTestingModule } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ReactiveFormsModule } from '@angular/forms';

import { BsModalRef } from 'ngx-bootstrap/modal';
import { of } from 'rxjs';

import { configureTestBed } from '../../../../../testing/unit-test-helper';
import { OsdService } from '../../../../shared/api/osd.service';
import { ModalComponent } from '../../../../shared/components/modal/modal.component';
import { SubmitButtonComponent } from '../../../../shared/components/submit-button/submit-button.component';
import { CdFormBuilder } from '../../../../shared/forms/cd-form-builder';
import { OsdReweightModalComponent } from './osd-reweight-modal.component';

describe('OsdReweightModalComponent', () => {
  let component: OsdReweightModalComponent;
  let fixture: ComponentFixture<OsdReweightModalComponent>;

  configureTestBed({
    imports: [ReactiveFormsModule, HttpClientTestingModule],
    declarations: [OsdReweightModalComponent, ModalComponent, SubmitButtonComponent],
    providers: [OsdService, BsModalRef, CdFormBuilder]
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(OsdReweightModalComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should call OsdService::reweight() on submit', () => {
    component.osdId = 1;
    component.reweightForm.get('weight').setValue(0.5);

    const osdServiceSpy = spyOn(TestBed.get(OsdService), 'reweight').and.callFake(() => of(true));
    component.reweight();

    expect(osdServiceSpy.calls.count()).toBe(1);
    expect(osdServiceSpy.calls.first().args).toEqual([1, 0.5]);
  });
});
