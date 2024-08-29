import { Component, OnInit } from '@angular/core';
import { Location } from '@angular/common';
import { UntypedFormControl, Validators } from '@angular/forms';
import { NgbActiveModal } from '@ng-bootstrap/ng-bootstrap';
import { Subscription, forkJoin } from 'rxjs';
import { ActionLabelsI18n } from '~/app/shared/constants/app.constants';
import { CdFormGroup } from '~/app/shared/forms/cd-form-group';
import { WizardStepModel } from '~/app/shared/models/wizard-steps';
import { WizardStepsService } from '~/app/shared/services/wizard-steps.service';
import { RgwDaemonService } from '~/app/shared/api/rgw-daemon.service';
import { RgwDaemon } from '../models/rgw-daemon';
import { MultiClusterService } from '~/app/shared/api/multi-cluster.service';
import { RgwMultisiteService } from '~/app/shared/api/rgw-multisite.service';
import { Icons } from '~/app/shared/enum/icons.enum';
import { SelectOption } from '~/app/shared/components/select/select-option.model';
import _ from 'lodash';
import { SelectMessages } from '~/app/shared/components/select/select-messages.model';
import { NotificationType } from '~/app/shared/enum/notification-type.enum';
import { NotificationService } from '~/app/shared/services/notification.service';
import { Router } from '@angular/router';
import { map, switchMap } from 'rxjs/operators';
import { SummaryService } from '~/app/shared/services/summary.service';
import { ExecutingTask } from '~/app/shared/models/executing-task';
import {
  STEP_TITLES_MULTI_CLUSTER_CONFIGURED,
  STEP_TITLES_SINGLE_CLUSTER
} from '~/app/shared/enum/multisite-wizard-steps.enum';

@Component({
  selector: 'cd-rgw-multisite-wizard',
  templateUrl: './rgw-multisite-wizard.component.html',
  styleUrls: ['./rgw-multisite-wizard.component.scss']
})
export class RgwMultisiteWizardComponent implements OnInit {
  multisiteSetupForm: CdFormGroup;
  currentStep: WizardStepModel;
  currentStepSub: Subscription;
  permissions: Permissions;
  stepTitles = STEP_TITLES_MULTI_CLUSTER_CONFIGURED;
  stepsToSkip: { [steps: string]: boolean } = {};
  daemons: RgwDaemon[] = [];
  selectedCluster = '';
  clusterDetailsArray: any;
  isMultiClusterConfigured = false;
  exportTokenForm: CdFormGroup;
  realms: any;
  loading = false;
  pageURL: string;
  icons = Icons;
  rgwEndpoints: { value: any[]; options: any[]; messages: any };
  executingTask: ExecutingTask;
  setupCompleted = false;

  constructor(
    private wizardStepsService: WizardStepsService,
    public activeModal: NgbActiveModal,
    public actionLabels: ActionLabelsI18n,
    private rgwDaemonService: RgwDaemonService,
    private multiClusterService: MultiClusterService,
    private rgwMultisiteService: RgwMultisiteService,
    public notificationService: NotificationService,
    private router: Router,
    private summaryService: SummaryService,
    private location: Location
  ) {
    this.pageURL = 'rgw/multisite/configuration';
    this.currentStepSub = this.wizardStepsService
      .getCurrentStep()
      .subscribe((step: WizardStepModel) => {
        this.currentStep = step;
      });
    this.currentStep.stepIndex = 1;
    this.createForm();
    this.rgwEndpoints = {
      value: [],
      options: [],
      messages: new SelectMessages({
        empty: $localize`There are no endpoints.`,
        filter: $localize`Select endpoints`
      })
    };
  }

  ngOnInit(): void {
    this.rgwDaemonService
      .list()
      .pipe(
        switchMap((daemons) => {
          this.daemons = daemons;
          const daemonStatsObservables = daemons.map((daemon) =>
            this.rgwDaemonService.get(daemon.id).pipe(
              map((daemonStats) => ({
                hostname: daemon.server_hostname,
                port: daemon.port,
                frontendConfig: daemonStats['rgw_metadata']['frontend_config#0']
              }))
            )
          );
          return forkJoin(daemonStatsObservables);
        })
      )
      .subscribe((daemonStatsArray) => {
        this.rgwEndpoints.value = daemonStatsArray.map((daemonStats) => {
          const protocol = daemonStats.frontendConfig.includes('ssl_port') ? 'https' : 'http';
          return `${protocol}://${daemonStats.hostname}:${daemonStats.port}`;
        });
        const options: SelectOption[] = this.rgwEndpoints.value.map(
          (endpoint: string) => new SelectOption(false, endpoint, '')
        );
        this.rgwEndpoints.options = [...options];
      });

    this.multiClusterService.getCluster().subscribe((clusters) => {
      this.clusterDetailsArray = Object.values(clusters['config'])
        .flat()
        .filter((cluster) => cluster['cluster_alias'] !== 'local-cluster');
      this.isMultiClusterConfigured = this.clusterDetailsArray.length > 0;
      if (!this.isMultiClusterConfigured) {
        this.stepTitles = STEP_TITLES_SINGLE_CLUSTER;
      } else {
        this.selectedCluster = this.clusterDetailsArray[0]['name'];
      }
      this.wizardStepsService.setTotalSteps(this.stepTitles.length);
    });

    this.summaryService.subscribe((summary) => {
      this.executingTask = summary.executing_tasks.filter((tasks) =>
        tasks.name.includes('progress/Multisite-Setup')
      )[0];
    });
  }

  createForm() {
    this.multisiteSetupForm = new CdFormGroup({
      realmName: new UntypedFormControl('default_realm', {
        validators: [Validators.required]
      }),
      zonegroupName: new UntypedFormControl('default_zonegroup', {
        validators: [Validators.required]
      }),
      zonegroup_endpoints: new UntypedFormControl(null, [Validators.required]),
      zoneName: new UntypedFormControl('default_zone', {
        validators: [Validators.required]
      }),
      zone_endpoints: new UntypedFormControl(null, {
        validators: [Validators.required]
      }),
      username: new UntypedFormControl('default_system_user', {
        validators: [Validators.required]
      }),
      cluster: new UntypedFormControl(null, {
        validators: [Validators.required]
      })
    });

    if (!this.isMultiClusterConfigured) {
      this.exportTokenForm = new CdFormGroup({});
    }
  }

  showSubmitButtonLabel() {
    if (this.wizardStepsService.isLastStep()) {
      if (!this.setupCompleted) {
        if (this.isMultiClusterConfigured) {
          return $localize`Configure Multi-Site`;
        } else {
          return $localize`Export Multi-Site token`;
        }
      } else {
        return $localize`Close`;
      }
    } else {
      return $localize`Next`;
    }
  }

  showCancelButtonLabel() {
    return !this.wizardStepsService.isFirstStep()
      ? this.actionLabels.BACK
      : this.actionLabels.CANCEL;
  }

  onNextStep() {
    if (!this.wizardStepsService.isLastStep()) {
      this.wizardStepsService.moveToNextStep();
    } else {
      if (this.setupCompleted) {
        this.refreshMultisitePage();
      } else {
        this.onSubmit();
      }
    }
  }

  onSubmit() {
    this.loading = true;
    const values = this.multisiteSetupForm.value;
    const realmName = values['realmName'];
    const zonegroupName = values['zonegroupName'];
    const zonegroupEndpoints = this.rgwEndpoints.value.join(',');
    const zoneName = values['zoneName'];
    const zoneEndpoints = this.rgwEndpoints.value.join(',');
    const username = values['username'];
    if (!this.isMultiClusterConfigured) {
      this.rgwMultisiteService
        .setUpMultisiteReplication(
          realmName,
          zonegroupName,
          zonegroupEndpoints,
          zoneName,
          zoneEndpoints,
          username
        )
        .subscribe((data: object[]) => {
          this.setupCompleted = true;
          this.loading = false;
          this.realms = data;
          this.showSuccessNotification();
        });
    } else {
      const cluster = values['cluster'];
      this.rgwMultisiteService
        .setUpMultisiteReplication(
          realmName,
          zonegroupName,
          zonegroupEndpoints,
          zoneName,
          zoneEndpoints,
          username,
          cluster
        )
        .subscribe(
          () => {
            this.setupCompleted = true;
            this.loading = false;
            this.showSuccessNotification();
          },
          () => {
            this.multisiteSetupForm.setErrors({ cdSubmitButton: true });
          }
        );
    }
  }

  showSuccessNotification() {
    this.notificationService.show(
      NotificationType.success,
      $localize`Multi-site setup completed successfully.`
    );
  }

  refreshMultisitePage() {
    const currentRoute = this.router.url.split('?')[0];
    const navigateTo = currentRoute.includes('multisite') ? '/pool' : '/';
    this.router.navigateByUrl(navigateTo, { skipLocationChange: true }).then(() => {
      this.router.navigate(['/' + this.pageURL]);
    });
  }

  onPreviousStep() {
    if (!this.wizardStepsService.isFirstStep()) {
      this.wizardStepsService.moveToPreviousStep();
    } else {
      this.location.back();
    }
  }
}
