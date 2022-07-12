import { HttpClientTestingModule } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ReactiveFormsModule } from '@angular/forms';
import { RouterTestingModule } from '@angular/router/testing';

import { NgbActiveModal } from '@ng-bootstrap/ng-bootstrap';
import { ToastrModule } from 'ngx-toastr';

import { ComponentsModule } from '~/app/shared/components/components.module';
import { PipesModule } from '~/app/shared/pipes/pipes.module';
import { AuthStorageService } from '~/app/shared/services/auth-storage.service';
import { configureTestBed } from '~/testing/unit-test-helper';
import { RbdSnapshotFormModalComponent } from './rbd-snapshot-form-modal.component';

describe('RbdSnapshotFormModalComponent', () => {
  let component: RbdSnapshotFormModalComponent;
  let fixture: ComponentFixture<RbdSnapshotFormModalComponent>;

  configureTestBed({
    imports: [
      ReactiveFormsModule,
      ComponentsModule,
      PipesModule,
      HttpClientTestingModule,
      ToastrModule.forRoot(),
      RouterTestingModule
    ],
    declarations: [RbdSnapshotFormModalComponent],
    providers: [NgbActiveModal, AuthStorageService]
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(RbdSnapshotFormModalComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });

  it('should show "Create" text', () => {
    fixture.detectChanges();

    const header = fixture.debugElement.nativeElement.querySelector('h4');
    expect(header.textContent).toBe('Create RBD Snapshot');

    const button = fixture.debugElement.nativeElement.querySelector('cd-submit-button');
    expect(button.textContent).toBe('Create RBD Snapshot');
  });

  it('should show "Rename" text', () => {
    component.setEditing();

    fixture.detectChanges();

    const header = fixture.debugElement.nativeElement.querySelector('h4');
    expect(header.textContent).toBe('Rename RBD Snapshot');

    const button = fixture.debugElement.nativeElement.querySelector('cd-submit-button');
    expect(button.textContent).toBe('Rename RBD Snapshot');
  });
});
