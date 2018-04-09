import { Component, OnInit, TemplateRef, ViewChild } from '@angular/core';

import { CellTemplate } from '../../../../shared/enum/cell-template.enum';
import { CdTableColumn } from '../../../../shared/models/cd-table-column';
import { CdTableSelection } from '../../../../shared/models/cd-table-selection';
import { DimlessBinaryPipe } from '../../../../shared/pipes/dimless-binary.pipe';
import { OsdService } from '../osd.service';

@Component({
  selector: 'cd-osd-list',
  templateUrl: './osd-list.component.html',
  styleUrls: ['./osd-list.component.scss']
})

export class OsdListComponent implements OnInit {
  @ViewChild('statusColor') statusColor: TemplateRef<any>;
  @ViewChild('osdUsageTpl') osdUsageTpl: TemplateRef<any>;

  osds = [];
  columns: CdTableColumn[];
  selection = new CdTableSelection();

  constructor(
    private osdService: OsdService,
    private dimlessBinaryPipe: DimlessBinaryPipe
  ) { }

  ngOnInit() {
    this.columns = [
      {prop: 'host.name', name: 'Host'},
      {prop: 'id', name: 'ID', cellTransformation: CellTemplate.bold},
      {prop: 'collectedStates', name: 'Status', cellTemplate: this.statusColor},
      {prop: 'stats.numpg', name: 'PGs'},
      {prop: 'stats.stat_bytes', name: 'Size', pipe: this.dimlessBinaryPipe},
      {name: 'Usage', cellTemplate: this.osdUsageTpl},
      {
        prop: 'stats_history.out_bytes',
        name: 'Read bytes',
        cellTransformation: CellTemplate.sparkline
      },
      {
        prop: 'stats_history.in_bytes',
        name: 'Writes bytes',
        cellTransformation: CellTemplate.sparkline
      },
      {prop: 'stats.op_r', name: 'Read ops', cellTransformation: CellTemplate.perSecond},
      {prop: 'stats.op_w', name: 'Write ops', cellTransformation: CellTemplate.perSecond}
    ];
  }

  updateSelection(selection: CdTableSelection) {
    this.selection = selection;
  }

  getOsdList() {
    this.osdService.getList().subscribe((data: any[]) => {
      this.osds = data;
      data.map((osd) => {
        osd.collectedStates = this.collectStates(osd);
        osd.stats_history.out_bytes = this.getSpikes(osd.stats_history.op_out_bytes);
        osd.stats_history.in_bytes = this.getSpikes(osd.stats_history.op_in_bytes);
        return osd;
      });
    });
  }

  /**
   * This function will remove the total from the history data through this we are getting spikes in
   * the graph.
   *
   * Each data number array consists of the following two numbers:
   * First number is a timestamp.
   * Second number is the total of read or written bytes until the given time.
   */
  getSpikes(data: number[][]): number[] {
    return data.map((d, i) => {
      if (i === 0) {
        return 0;
      }
      return d[1] - data[i - 1][1];
    }).slice(1);
  }

  collectStates(osd) {
    const select = (onState, offState) => osd[onState] ? onState : offState;
    return [select('up', 'down'), select('in', 'out')];
  }

  beforeShowDetails(selection: CdTableSelection) {
    return selection.hasSingleSelection;
  }
}
