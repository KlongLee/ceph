import { Component, EventEmitter, Output } from '@angular/core';
import { FormControl, Validators } from '@angular/forms';
import { NgbActiveModal } from '@ng-bootstrap/ng-bootstrap';
import { RgwMultisiteService } from '~/app/shared/api/rgw-multisite.service';
import { RgwRealmService } from '~/app/shared/api/rgw-realm.service';
import { RgwZoneService } from '~/app/shared/api/rgw-zone.service';
import { RgwZonegroupService } from '~/app/shared/api/rgw-zonegroup.service';
import { ActionLabelsI18n } from '~/app/shared/constants/app.constants';
import { CdFormGroup } from '~/app/shared/forms/cd-form-group';
import { ModalService } from '~/app/shared/services/modal.service';
import { NotificationService } from '~/app/shared/services/notification.service';
import { RgwRealm, RgwZonegroup, RgwZone } from '../models/rgw-multisite';
import { NotificationType } from '~/app/shared/enum/notification-type.enum';

@Component({
  selector: 'cd-create-rgw-service-entities',
  templateUrl: './create-rgw-service-entities.component.html',
  styleUrls: ['./create-rgw-service-entities.component.scss']
})
export class CreateRgwServiceEntitiesComponent {
  createMultisiteEntitiesForm: CdFormGroup;
  realm: RgwRealm;
  zonegroup: RgwZonegroup;
  zone: RgwZone;

  @Output()
  submitAction = new EventEmitter();

  constructor(
    public activeModal: NgbActiveModal,
    public actionLabels: ActionLabelsI18n,
    public rgwMultisiteService: RgwMultisiteService,
    public rgwZoneService: RgwZoneService,
    public notificationService: NotificationService,
    public rgwZonegroupService: RgwZonegroupService,
    public rgwRealmService: RgwRealmService,
    public modalService: ModalService
  ) {
    this.createForm();
  }

  createForm() {
    this.createMultisiteEntitiesForm = new CdFormGroup({
      realmName: new FormControl(null, {
        validators: [Validators.required]
      }),
      zonegroupName: new FormControl(null, {
        validators: [Validators.required]
      }),
      zoneName: new FormControl(null, {
        validators: [Validators.required]
      })
    });
  }

  submit() {
    const values = this.createMultisiteEntitiesForm.value;
    this.realm = new RgwRealm();
    this.realm.name = values['realmName'];
    this.zonegroup = new RgwZonegroup();
    this.zonegroup.name = values['zonegroupName'];
    this.zone = new RgwZone();
    this.zone.name = values['zoneName'];
    this.rgwRealmService.create(this.realm, true).subscribe(() => {
      this.rgwZonegroupService.create(this.realm, this.zonegroup, true, true).subscribe(() => {
        this.rgwZoneService
          .create(this.zone, this.zonegroup, true, true, null, '', false, this.zone)
          .subscribe(
            () => {
              this.notificationService.show(
                NotificationType.success,
                $localize`Realm/Zonegroup/Zone created successfully`
              );
              this.submitAction.emit();
              this.activeModal.close();
            },
            () => {
              this.notificationService.show(
                NotificationType.error,
                $localize`Realm/Zonegroup/Zone creation failed`
              );
            }
          );
      });
    });
  }
}
