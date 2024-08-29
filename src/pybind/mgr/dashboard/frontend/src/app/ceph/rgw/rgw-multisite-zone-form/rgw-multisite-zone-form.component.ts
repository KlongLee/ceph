import { Component, Inject, OnInit, Optional } from '@angular/core';
import { UntypedFormControl, Validators } from '@angular/forms';
import _ from 'lodash';
import { RgwMultisiteService } from '~/app/shared/api/rgw-multisite.service';
import { RgwUserService } from '~/app/shared/api/rgw-user.service';
import { RgwZoneService } from '~/app/shared/api/rgw-zone.service';
import { RgwZonegroupService } from '~/app/shared/api/rgw-zonegroup.service';
import { ActionLabelsI18n } from '~/app/shared/constants/app.constants';
import { NotificationType } from '~/app/shared/enum/notification-type.enum';
import { CdFormGroup } from '~/app/shared/forms/cd-form-group';
import { CdValidators } from '~/app/shared/forms/cd-validators';
import { NotificationService } from '~/app/shared/services/notification.service';
import { RgwRealm, RgwZone, RgwZonegroup, SystemKey } from '../models/rgw-multisite';
import { BaseModal } from 'carbon-components-angular';

@Component({
  selector: 'cd-rgw-multisite-zone-form',
  templateUrl: './rgw-multisite-zone-form.component.html',
  styleUrls: ['./rgw-multisite-zone-form.component.scss']
})
export class RgwMultisiteZoneFormComponent extends BaseModal implements OnInit {
  readonly endpoints = /^((https?:\/\/)|(www.))(?:([a-zA-Z]+)|(\d+\.\d+.\d+.\d+)):\d{2,4}$/;
  readonly ipv4Rgx = /^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/i;
  readonly ipv6Rgx = /^(?:[a-f0-9]{1,4}:){7}[a-f0-9]{1,4}$/i;
  multisiteZoneForm: CdFormGroup;
  realm: RgwRealm;
  zonegroup: RgwZonegroup;
  zone: RgwZone;
  zonegroupList: RgwZonegroup[] = [];
  zoneList: RgwZone[] = [];
  zoneNames: string[];
  users: any;
  placementTargets: any;
  zoneInfo: RgwZone;
  poolList: object[] = [];
  storageClassList: object[] = [];
  disableDefault: boolean = false;
  disableMaster: boolean = false;
  isMetadataSync: boolean = false;
  isMasterZone: boolean;
  isDefaultZone: boolean;
  syncStatusTimedOut: boolean = false;
  createSystemUser: boolean = false;
  master_zone_of_master_zonegroup: RgwZone;
  masterZoneUser: any;
  access_key: any;
  master_zonegroup_of_realm: RgwZonegroup;
  compressionTypes = ['lz4', 'zlib', 'snappy'];
  userListReady: boolean = false;

  constructor(
    public actionLabels: ActionLabelsI18n,
    public rgwMultisiteService: RgwMultisiteService,
    public rgwZoneService: RgwZoneService,
    public rgwZoneGroupService: RgwZonegroupService,
    public notificationService: NotificationService,
    public rgwUserService: RgwUserService,

    @Optional() @Inject('action') public action: string,
    @Optional() @Inject('resource') public resource: string,
    @Optional() @Inject('info') public info: any,
    @Optional() @Inject('multisiteInfo') public multisiteInfo: object[],
    @Optional() @Inject('defaultsInfo') public defaultsInfo: string[],
    @Optional() @Inject('editing') public editing: boolean
  ) {
    super();
    this.action = this.editing
      ? this.actionLabels.EDIT
      : this.actionLabels.CREATE;
    this.createForm();
  }

  createForm() {
    this.multisiteZoneForm = new CdFormGroup({
      zoneName: new UntypedFormControl(null, {
        validators: [
          Validators.required,
          CdValidators.custom('uniqueName', (zoneName: string) => {
            return (
              this.action === this.actionLabels.CREATE && this.zoneNames && this.zoneNames.indexOf(zoneName) !== -1
            );
          })
        ]
      }),
      default_zone: new UntypedFormControl(false),
      master_zone: new UntypedFormControl(false),
      selectedZonegroup: new UntypedFormControl(null),
      zone_endpoints: new UntypedFormControl(null, {
        validators: [
          CdValidators.custom('endpoint', (value: string) => {
            if (_.isEmpty(value)) {
              return false;
            } else {
              if (value.includes(',')) {
                value.split(',').forEach((url: string) => {
                  return (
                    !this.endpoints.test(url) && !this.ipv4Rgx.test(url) && !this.ipv6Rgx.test(url)
                  );
                });
              } else {
                return (
                  !this.endpoints.test(value) &&
                  !this.ipv4Rgx.test(value) &&
                  !this.ipv6Rgx.test(value)
                );
              }
              return false;
            }
          }),
          Validators.required
        ]
      }),
      access_key: new UntypedFormControl('', {}),
      secret_key: new UntypedFormControl('', {}),
      placementTarget: new UntypedFormControl(null),
      placementDataPool: new UntypedFormControl(''),
      placementIndexPool: new UntypedFormControl(null),
      placementDataExtraPool: new UntypedFormControl(null),
      storageClass: new UntypedFormControl(null),
      storageDataPool: new UntypedFormControl(null),
      storageCompression: new UntypedFormControl(null)
    });
  }

  onZoneGroupChange(zonegroupName: string) {
    let zg = new RgwZonegroup();
    zg.name = zonegroupName;
    this.rgwZoneGroupService.get(zg).subscribe((zonegroup: RgwZonegroup) => {
      if (_.isEmpty(zonegroup.master_zone)) {
        this.multisiteZoneForm.get('master_zone').setValue(true);
        this.multisiteZoneForm.get('master_zone').disable();
        this.disableMaster = false;
      } else if (!_.isEmpty(zonegroup.master_zone) && this.action === this.actionLabels.CREATE) {
        this.multisiteZoneForm.get('master_zone').setValue(false);
        this.multisiteZoneForm.get('master_zone').disable();
        this.disableMaster = true;
      }
    });
    if (
      this.multisiteZoneForm.getValue('selectedZonegroup') !==
      this.defaultsInfo['defaultZonegroupName']
    ) {
      this.disableDefault = true;
      this.multisiteZoneForm.get('default_zone').disable();
    }
  }

  ngOnInit(): void {
    this.zonegroupList =
      this.multisiteInfo[1] !== undefined && this.multisiteInfo[1].hasOwnProperty('zonegroups')
        ? this.multisiteInfo[1]['zonegroups']
        : [];
    this.zoneList =
      this.multisiteInfo[2] !== undefined && this.multisiteInfo[2].hasOwnProperty('zones')
        ? this.multisiteInfo[2]['zones']
        : [];
    this.zoneNames = this.zoneList.map((zone) => {
      return zone['name'];
    });
    if (this.action === this.actionLabels.CREATE) {
      if (this.defaultsInfo['defaultZonegroupName'] !== undefined) {
        this.multisiteZoneForm
          .get('selectedZonegroup')
          .setValue(this.defaultsInfo['defaultZonegroupName']);
        this.onZoneGroupChange(this.defaultsInfo['defaultZonegroupName']);
      }
    }
    if (this.action === this.actionLabels.EDIT) {
      this.multisiteZoneForm.get('selectedZonegroup').disable();
      this.placementTargets = this.info.parent ? this.info.parent.data.placement_targets : [];
      this.rgwZoneService.getPoolNames().subscribe((pools: object[]) => {
        this.poolList = pools;
      });
      this.multisiteZoneForm.get('zoneName').setValue(this.info.data.name);
      this.multisiteZoneForm.get('selectedZonegroup').setValue(this.info.data.parent);
      this.multisiteZoneForm.get('default_zone').setValue(this.info.data.is_default);
      this.multisiteZoneForm.get('master_zone').setValue(this.info.data.is_master);
      this.multisiteZoneForm.get('zone_endpoints').setValue(this.info.data.endpoints.toString());
      this.multisiteZoneForm.get('access_key').setValue(this.info.data.access_key);
      this.multisiteZoneForm.get('secret_key').setValue(this.info.data.secret_key);
      this.multisiteZoneForm
        .get('placementTarget')
        .setValue(this.info.parent.data.default_placement);
      this.getZonePlacementData(this.multisiteZoneForm.getValue('placementTarget'));
      if (this.info.data.is_default) {
        this.isDefaultZone = true;
        this.multisiteZoneForm.get('default_zone').disable();
      }
      if (this.info.data.is_master) {
        this.isMasterZone = true;
        this.multisiteZoneForm.get('master_zone').disable();
      }
      const zone = new RgwZone();
      zone.name = this.info.data.name;
      this.onZoneGroupChange(this.info.data.parent);
    }
    if (
      this.multisiteZoneForm.getValue('selectedZonegroup') !==
      this.defaultsInfo['defaultZonegroupName']
    ) {
      this.disableDefault = true;
      this.multisiteZoneForm.get('default_zone').disable();
    }
  }

  getZonePlacementData(placementTarget: string) {
    this.zone = new RgwZone();
    this.zone.name = this.info.data.name;
    if (this.placementTargets) {
      this.placementTargets.forEach((placement: any) => {
        if (placement.name === placementTarget) {
          let storageClasses = placement.storage_classes;
          this.storageClassList = Object.entries(storageClasses).map(([key, value]) => ({
            key,
            value
          }));
        }
      });
    }
    this.rgwZoneService.get(this.zone).subscribe((zoneInfo: RgwZone) => {
      this.zoneInfo = zoneInfo;
      if (this.zoneInfo && this.zoneInfo['placement_pools']) {
        this.zoneInfo['placement_pools'].forEach((plc_pool) => {
          if (plc_pool.key === placementTarget) {
            let storageClasses = plc_pool.val.storage_classes;
            let placementDataPool = storageClasses['STANDARD']
              ? storageClasses['STANDARD']['data_pool']
              : '';
            let placementIndexPool = plc_pool.val.index_pool;
            let placementDataExtraPool = plc_pool.val.data_extra_pool;
            this.poolList.push({ poolname: placementDataPool });
            this.poolList.push({ poolname: placementIndexPool });
            this.poolList.push({ poolname: placementDataExtraPool });
            this.multisiteZoneForm.get('storageClass').setValue(this.storageClassList[0]['value']);
            this.multisiteZoneForm.get('storageDataPool').setValue(placementDataPool);
            this.multisiteZoneForm.get('storageCompression').setValue(this.compressionTypes[0]);
            this.multisiteZoneForm.get('placementDataPool').setValue(placementDataPool);
            this.multisiteZoneForm.get('placementIndexPool').setValue(placementIndexPool);
            this.multisiteZoneForm.get('placementDataExtraPool').setValue(placementDataExtraPool);
          }
        });
      }
    });
  }

  getStorageClassData(storageClass: string) {
    let storageClassSelected = this.storageClassList.find((x) => x['value'] == storageClass)[
      'value'
    ];
    this.poolList.push({ poolname: storageClassSelected.data_pool });
    this.multisiteZoneForm.get('storageDataPool').setValue(storageClassSelected.data_pool);
    this.multisiteZoneForm
      .get('storageCompression')
      .setValue(storageClassSelected.compression_type);
  }

  submit() {
    const values = this.multisiteZoneForm.getRawValue();
    if (this.action === this.actionLabels.CREATE) {
      this.zonegroup = new RgwZonegroup();
      this.zonegroup.name = values['selectedZonegroup'];
      this.zone = new RgwZone();
      this.zone.name = values['zoneName'];
      this.zone.endpoints = values['zone_endpoints'];
      this.zone.system_key = new SystemKey();
      this.zone.system_key.access_key = values['access_key'];
      this.zone.system_key.secret_key = values['secret_key'];
      this.rgwZoneService
        .create(
          this.zone,
          this.zonegroup,
          values['default_zone'],
          values['master_zone'],
          this.zone.endpoints
        )
        .subscribe(
          () => {
            this.notificationService.show(
              NotificationType.success,
              $localize`Zone: '${values['zoneName']}' created successfully`
            );
            this.closeModal();
          },
          () => {
            this.multisiteZoneForm.setErrors({ cdSubmitButton: true });
          }
        );
    } else if (this.action === this.actionLabels.EDIT) {
      this.zonegroup = new RgwZonegroup();
      this.zonegroup.name = values['selectedZonegroup'];
      this.zone = new RgwZone();
      this.zone.name = this.info.data.name;
      this.zone.endpoints = values['zone_endpoints'];
      this.zone.system_key = new SystemKey();
      this.zone.system_key.access_key = values['access_key'];
      this.zone.system_key.secret_key = values['secret_key'];
      this.rgwZoneService
        .update(
          this.zone,
          this.zonegroup,
          values['zoneName'],
          values['default_zone'],
          values['master_zone'],
          this.zone.endpoints,
          values['placementTarget'],
          values['placementDataPool'],
          values['placementIndexPool'],
          values['placementDataExtraPool'],
          values['storageClass'],
          values['storageDataPool'],
          values['storageCompression']
        )
        .subscribe(
          () => {
            this.notificationService.show(
              NotificationType.success,
              $localize`Zone: '${values['zoneName']}' updated successfully`
            );
            this.closeModal();
          },
          () => {
            this.multisiteZoneForm.setErrors({ cdSubmitButton: true });
          }
        );
    }
  }
}
