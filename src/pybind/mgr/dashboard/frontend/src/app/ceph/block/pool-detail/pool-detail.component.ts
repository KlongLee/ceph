import { Component, OnDestroy, OnInit } from '@angular/core';
import { ActivatedRoute } from '@angular/router';

import { ViewCacheStatus } from '../../../shared/enum/view-cache-status.enum';
import { CdTableColumn } from '../../../shared/models/cd-table-column';
import { CdTableSelection } from '../../../shared/models/cd-table-selection';
import { DimlessBinaryPipe } from '../../../shared/pipes/dimless-binary.pipe';
import { DimlessPipe } from '../../../shared/pipes/dimless.pipe';
import { RbdService } from '../../../shared/services/rbd.service';

@Component({
  selector: 'cd-pool-detail',
  templateUrl: './pool-detail.component.html',
  styleUrls: ['./pool-detail.component.scss']
})
export class PoolDetailComponent implements OnInit, OnDestroy {
  name: string;
  images: any;
  columns: CdTableColumn[];
  retries: number;
  routeParamsSubscribe: any;
  viewCacheStatus: ViewCacheStatus;
  selection = new CdTableSelection();

  constructor(
    private route: ActivatedRoute,
    private rbdService: RbdService,
    dimlessBinaryPipe: DimlessBinaryPipe,
    dimlessPipe: DimlessPipe
  ) {
    this.columns = [
      {
        name: 'Name',
        prop: 'name',
        flexGrow: 2
      },
      {
        name: 'Size',
        prop: 'size',
        flexGrow: 1,
        cellClass: 'text-right',
        pipe: dimlessBinaryPipe
      },
      {
        name: 'Objects',
        prop: 'num_objs',
        flexGrow: 1,
        cellClass: 'text-right',
        pipe: dimlessPipe
      },
      {
        name: 'Object size',
        prop: 'obj_size',
        flexGrow: 1,
        cellClass: 'text-right',
        pipe: dimlessBinaryPipe
      },
      {
        name: 'Features',
        prop: 'features_name',
        flexGrow: 3
      },
      {
        name: 'Parent',
        prop: 'parent',
        flexGrow: 2
      }
    ];
  }

  ngOnInit() {
    this.routeParamsSubscribe = this.route.params.subscribe((params: { name: string }) => {
      this.name = params.name;
      this.images = [];
      this.retries = 0;
    });
  }

  ngOnDestroy() {
    this.routeParamsSubscribe.unsubscribe();
  }

  loadImages() {
    this.rbdService.getPoolImages(this.name).then(
      resp => {
        this.viewCacheStatus = resp.status;
        this.images = resp.value;
      },
      () => {
        this.viewCacheStatus = ViewCacheStatus.ValueException;
      }
    );
  }

  updateSelection(selection: CdTableSelection) {
    this.selection = selection;
  }
}
