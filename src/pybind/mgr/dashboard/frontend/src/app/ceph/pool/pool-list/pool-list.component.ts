import { Component } from '@angular/core';

import { BsModalRef, BsModalService } from 'ngx-bootstrap';

import { PoolService } from '../../../shared/api/pool.service';
import { DeletionModalComponent } from '../../../shared/components/deletion-modal/deletion-modal.component';
import { CdTableAction } from '../../../shared/models/cd-table-action';
import { CdTableColumn } from '../../../shared/models/cd-table-column';
import { CdTableFetchDataContext } from '../../../shared/models/cd-table-fetch-data-context';
import { CdTableSelection } from '../../../shared/models/cd-table-selection';
import { ExecutingTask } from '../../../shared/models/executing-task';
import { FinishedTask } from '../../../shared/models/finished-task';
import { Permission } from '../../../shared/models/permissions';
import { AuthStorageService } from '../../../shared/services/auth-storage.service';
import { TaskWrapperService } from '../../../shared/services/task-wrapper.service';
import { Pool } from '../pool';

@Component({
  selector: 'cd-pool-list',
  templateUrl: './pool-list.component.html',
  styleUrls: ['./pool-list.component.scss']
})
export class PoolListComponent {
  pools: Pool[] = [];
  columns: CdTableColumn[];
  selection = new CdTableSelection();
  modalRef: BsModalRef;
  executingTasks: ExecutingTask[] = [];
  permission: Permission;
  tableActions: CdTableAction[];

  constructor(
    private poolService: PoolService,
    private taskWrapper: TaskWrapperService,
    private authStorageService: AuthStorageService,
    private modalService: BsModalService
  ) {
    this.permission = this.authStorageService.getPermissions().pool;
    this.tableActions = [
      { permission: 'create', icon: 'fa-plus', routerLink: () => '/pool/add', name: 'Add' },
      {
        permission: 'update',
        icon: 'fa-pencil',
        routerLink: () => '/pool/edit/' + this.selection.first().pool_name,
        name: 'Edit'
      },
      {
        permission: 'delete',
        icon: 'fa-trash-o',
        click: () => this.deletePoolModal(),
        name: 'Delete'
      }
    ];
    this.columns = [
      {
        prop: 'pool_name',
        name: 'Name',
        flexGrow: 3
      },
      {
        prop: 'type',
        name: 'Type',
        flexGrow: 2
      },
      {
        prop: 'application_metadata',
        name: 'Applications',
        flexGrow: 3
      },
      {
        prop: 'pg_placement_num',
        name: 'Placement Groups',
        flexGrow: 1,
        cellClass: 'text-right'
      },
      {
        prop: 'size',
        name: 'Replica Size',
        flexGrow: 1,
        cellClass: 'text-right'
      },
      {
        prop: 'last_change',
        name: 'Last Change',
        flexGrow: 1,
        cellClass: 'text-right'
      },
      {
        prop: 'erasure_code_profile',
        name: 'Erasure Coded Profile',
        flexGrow: 2
      },
      {
        prop: 'crush_rule',
        name: 'Crush Ruleset',
        flexGrow: 2
      }
    ];
  }

  updateSelection(selection: CdTableSelection) {
    this.selection = selection;
  }

  getPoolList(context: CdTableFetchDataContext) {
    this.poolService.getList().subscribe(
      (pools: Pool[]) => {
        this.pools = pools;
      },
      () => {
        context.error();
      }
    );
  }

  deletePoolModal() {
    const name = this.selection.first().pool_name;
    this.modalRef = this.modalService.show(DeletionModalComponent, {
      initialState: {
        itemDescription: 'Pool',
        submitActionObservable: () =>
          this.taskWrapper.wrapTaskAroundCall({
            task: new FinishedTask('pool/delete', { pool_name: name }),
            call: this.poolService.delete(name)
          })
      }
    });
  }
}
