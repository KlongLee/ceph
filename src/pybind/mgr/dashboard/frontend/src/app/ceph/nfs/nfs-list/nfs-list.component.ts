import { Component, OnDestroy, OnInit, TemplateRef, ViewChild } from '@angular/core';
import { Router, RoutesRecognized } from '@angular/router';

import { NgbModalRef } from '@ng-bootstrap/ng-bootstrap';
import _ from 'lodash';
import { Subscription } from 'rxjs';
import { filter, pairwise } from 'rxjs/operators';

import { NfsService } from '~/app/shared/api/nfs.service';
import { ListWithDetails } from '~/app/shared/classes/list-with-details.class';
import { CriticalConfirmationModalComponent } from '~/app/shared/components/critical-confirmation-modal/critical-confirmation-modal.component';
import { ActionLabelsI18n } from '~/app/shared/constants/app.constants';
import { TableComponent } from '~/app/shared/datatable/table/table.component';
import { CellTemplate } from '~/app/shared/enum/cell-template.enum';
import { Icons } from '~/app/shared/enum/icons.enum';
import { ViewCacheStatus } from '~/app/shared/enum/view-cache-status.enum';
import { CdTableAction } from '~/app/shared/models/cd-table-action';
import { CdTableColumn } from '~/app/shared/models/cd-table-column';
import { CdTableSelection } from '~/app/shared/models/cd-table-selection';
import { FinishedTask } from '~/app/shared/models/finished-task';
import { Permission } from '~/app/shared/models/permissions';
import { Task } from '~/app/shared/models/task';
import { AuthStorageService } from '~/app/shared/services/auth-storage.service';
import { ModalService } from '~/app/shared/services/modal.service';
import { TaskListService } from '~/app/shared/services/task-list.service';
import { TaskWrapperService } from '~/app/shared/services/task-wrapper.service';

@Component({
  selector: 'cd-nfs-list',
  templateUrl: './nfs-list.component.html',
  styleUrls: ['./nfs-list.component.scss'],
  providers: [TaskListService]
})
export class NfsListComponent extends ListWithDetails implements OnInit, OnDestroy {
  @ViewChild('nfsState')
  nfsState: TemplateRef<any>;
  @ViewChild('nfsFsal', { static: true })
  nfsFsal: TemplateRef<any>;

  @ViewChild('table', { static: true })
  table: TableComponent;

  columns: CdTableColumn[];
  permission: Permission;
  selection = new CdTableSelection();
  summaryDataSubscription: Subscription;
  viewCacheStatus: any;
  exports: any[];
  tableActions: CdTableAction[];
  isDefaultCluster = false;

  modalRef: NgbModalRef;

  builders = {
    'nfs/create': (metadata: any) => {
      return {
        path: metadata['path'],
        cluster_id: metadata['cluster_id'],
        fsal: metadata['fsal']
      };
    }
  };

  constructor(
    private authStorageService: AuthStorageService,
    private modalService: ModalService,
    private nfsService: NfsService,
    private taskListService: TaskListService,
    private taskWrapper: TaskWrapperService,
    public actionLabels: ActionLabelsI18n,
    private router: Router
  ) {
    super();
    this.permission = this.authStorageService.getPermissions().nfs;
    const getNfsUri = () =>
      this.selection.first() &&
      `${encodeURI(this.selection.first().cluster_id)}/${encodeURI(
        this.selection.first().export_id
      )}`;

    let baseUrl: string = 'file';
    this.router.events
      .pipe(
        filter((e: RoutesRecognized): e is RoutesRecognized => e instanceof RoutesRecognized),
        pairwise()
      )
      .subscribe((events: RoutesRecognized[]) => {
        baseUrl = events?.[0]?.urlAfterRedirects || 'file';
      });
    const createAction: CdTableAction = {
      permission: 'create',
      icon: Icons.add,
      routerLink: () => `${baseUrl}/nfs/create`,
      canBePrimary: (selection: CdTableSelection) => !selection.hasSingleSelection,
      name: this.actionLabels.CREATE
    };

    const editAction: CdTableAction = {
      permission: 'update',
      icon: Icons.edit,
      routerLink: () => `${baseUrl}/nfs/edit/${getNfsUri()}`,
      name: this.actionLabels.EDIT
    };

    const deleteAction: CdTableAction = {
      permission: 'delete',
      icon: Icons.destroy,
      click: () => this.deleteNfsModal(),
      name: this.actionLabels.DELETE
    };

    this.tableActions = [createAction, editAction, deleteAction];
  }

  ngOnInit() {
    this.columns = [
      {
        name: $localize`Path`,
        prop: 'path',
        flexGrow: 2,
        cellTransformation: CellTemplate.executing
      },
      {
        name: $localize`Pseudo`,
        prop: 'pseudo',
        flexGrow: 2
      },
      {
        name: $localize`Cluster`,
        prop: 'cluster_id',
        flexGrow: 2
      },
      {
        name: $localize`Storage Backend`,
        prop: 'fsal',
        flexGrow: 2,
        cellTemplate: this.nfsFsal
      },
      {
        name: $localize`Access Type`,
        prop: 'access_type',
        flexGrow: 2
      }
    ];

    this.taskListService.init(
      () => this.nfsService.list(),
      (resp) => this.prepareResponse(resp),
      (exports) => (this.exports = exports),
      () => this.onFetchError(),
      this.taskFilter,
      this.itemFilter,
      this.builders
    );
  }

  ngOnDestroy() {
    if (this.summaryDataSubscription) {
      this.summaryDataSubscription.unsubscribe();
    }
  }

  prepareResponse(resp: any): any[] {
    let result: any[] = [];
    resp.forEach((nfs: any) => {
      nfs.id = `${nfs.cluster_id}:${nfs.export_id}`;
      nfs.state = 'LOADING';
      result = result.concat(nfs);
    });

    return result;
  }

  onFetchError() {
    this.table.reset(); // Disable loading indicator.
    this.viewCacheStatus = { status: ViewCacheStatus.ValueException };
  }

  itemFilter(entry: any, task: Task) {
    return (
      entry.cluster_id === task.metadata['cluster_id'] &&
      entry.export_id === task.metadata['export_id']
    );
  }

  taskFilter(task: Task) {
    return ['nfs/create', 'nfs/delete', 'nfs/edit'].includes(task.name);
  }

  updateSelection(selection: CdTableSelection) {
    this.selection = selection;
  }

  deleteNfsModal() {
    const cluster_id = this.selection.first().cluster_id;
    const export_id = this.selection.first().export_id;

    this.modalRef = this.modalService.show(CriticalConfirmationModalComponent, {
      itemDescription: $localize`NFS export`,
      itemNames: [`${cluster_id}:${export_id}`],
      submitActionObservable: () =>
        this.taskWrapper.wrapTaskAroundCall({
          task: new FinishedTask('nfs/delete', {
            cluster_id: cluster_id,
            export_id: export_id
          }),
          call: this.nfsService.delete(cluster_id, export_id)
        })
    });
  }
}
