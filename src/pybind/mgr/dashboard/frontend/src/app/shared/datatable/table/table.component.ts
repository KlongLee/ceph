import {
  AfterContentChecked,
  Component,
  EventEmitter,
  Input,
  NgZone,
  OnChanges,
  OnDestroy,
  OnInit,
  Output,
  TemplateRef,
  Type,
  ViewChild
} from '@angular/core';
import {
  DatatableComponent,
  SortDirection,
  SortPropDir,
  TableColumnProp
} from '@swimlane/ngx-datatable';

import * as _ from 'lodash';
import 'rxjs/add/observable/timer';
import { Observable } from 'rxjs/Observable';

import { CellTemplate } from '../../enum/cell-template.enum';
import { CdTableColumn } from '../../models/cd-table-column';
import { CdTableSelection } from '../../models/cd-table-selection';

@Component({
  selector: 'cd-table',
  templateUrl: './table.component.html',
  styleUrls: ['./table.component.scss']
})
export class TableComponent implements AfterContentChecked, OnInit, OnChanges, OnDestroy {
  @ViewChild(DatatableComponent) table: DatatableComponent;
  @ViewChild('tableCellBoldTpl') tableCellBoldTpl: TemplateRef<any>;
  @ViewChild('sparklineTpl') sparklineTpl: TemplateRef<any>;
  @ViewChild('routerLinkTpl') routerLinkTpl: TemplateRef<any>;
  @ViewChild('perSecondTpl') perSecondTpl: TemplateRef<any>;

  // This is the array with the items to be shown.
  @Input() data: any[];
  // Each item -> { prop: 'attribute name', name: 'display name' }
  @Input() columns: CdTableColumn[];
  // Each item -> { prop: 'attribute name', dir: 'asc'||'desc'}
  @Input() sorts?: SortPropDir[];
  // Method used for setting column widths.
  @Input() columnMode ?= 'flex';
  // Display the tool header, including reload button, pagination and search fields?
  @Input() toolHeader ?= true;
  // Display the table header?
  @Input() header ?= true;
  // Display the table footer?
  @Input() footer ?= true;
  // Page size to show. Set to 0 to show unlimited number of rows.
  @Input() limit ?= 10;

  /**
   * Auto reload time in ms - per default every 5s
   * You can set it to 0, undefined or false to disable the auto reload feature in order to
   * trigger 'fetchData' if the reload button is clicked.
   */
  @Input() autoReload: any = 5000;

  // Which row property is unique for a row
  @Input() identifier = 'id';
  // Allows other components to specify which type of selection they want,
  // e.g. 'single' or 'multi'.
  @Input() selectionType: string = undefined;

  /**
   * Should be a function to update the input data if undefined nothing will be triggered
   *
   * Sometimes it's useful to only define fetchData once.
   * Example:
   * Usage of multiple tables with data which is updated by the same function
   * What happens:
   * The function is triggered through one table and all tables will update
   */
  @Output() fetchData = new EventEmitter();

  /**
   * This should be defined if you need access to the selection object.
   *
   * Each time the table selection changes, this will be triggered and
   * the new selection object will be sent.
   *
   * @memberof TableComponent
   */
  @Output() updateSelection = new EventEmitter();

  /**
   * Use this variable to access the selected row(s).
   */
  selection = new CdTableSelection();

  tableColumns: CdTableColumn[];
  cellTemplates: {
    [key: string]: TemplateRef<any>
  } = {};
  search = '';
  rows = [];
  loadingIndicator = true;
  paginationClasses = {
    pagerLeftArrow: 'i fa fa-angle-double-left',
    pagerRightArrow: 'i fa fa-angle-double-right',
    pagerPrevious: 'i fa fa-angle-left',
    pagerNext: 'i fa fa-angle-right'
  };
  private subscriber;
  private updating = false;

  // Internal variable to check if it is necessary to recalculate the
  // table columns after the browser window has been resized.
  private currentWidth: number;

  constructor(private ngZone: NgZone) {}

  ngOnInit() {
    this._addTemplates();
    if (!this.sorts) {
      this.identifier = this.columns.some(c => c.prop === this.identifier) ?
        this.identifier :
        this.columns[0].prop + '';
      this.sorts = this.createSortingDefinition(this.identifier);
    }
    this.columns.map(c => {
      if (c.cellTransformation) {
        c.cellTemplate = this.cellTemplates[c.cellTransformation];
      }
      if (!c.flexGrow) {
        c.flexGrow = c.prop + '' === this.identifier ? 1 : 2;
      }
      if (!c.resizeable) {
        c.resizeable = false;
      }
      return c;
    });
    this.tableColumns = this.columns.filter(c => !c.isHidden);
    if (this.autoReload) {
      // Also if nothing is bound to fetchData nothing will be triggered
      // Force showing the loading indicator because it has been set to False in
      // useData() when this method was triggered by ngOnChanges().
      this.loadingIndicator = true;
      this.ngZone.runOutsideAngular(() => {
        this.subscriber = Observable.timer(0, this.autoReload).subscribe(x => {
          this.ngZone.run(() => {
            return this.reloadData();
          });
        });
      });
    }
  }

  ngOnDestroy() {
    if (this.subscriber) {
      this.subscriber.unsubscribe();
    }
  }

  ngAfterContentChecked() {
    // If the data table is not visible, e.g. another tab is active, and the
    // browser window gets resized, the table and its columns won't get resized
    // automatically if the tab gets visible again.
    // https://github.com/swimlane/ngx-datatable/issues/193
    // https://github.com/swimlane/ngx-datatable/issues/193#issuecomment-329144543
    if (this.table && this.table.element.clientWidth !== this.currentWidth) {
      this.currentWidth = this.table.element.clientWidth;
      this.table.recalculate();
    }
  }

  _addTemplates() {
    this.cellTemplates.bold = this.tableCellBoldTpl;
    this.cellTemplates.sparkline = this.sparklineTpl;
    this.cellTemplates.routerLink = this.routerLinkTpl;
    this.cellTemplates.perSecond = this.perSecondTpl;
  }

  ngOnChanges(changes) {
    this.useData();
  }

  setLimit(e) {
    const value = parseInt(e.target.value, 10);
    if (value > 0) {
      this.limit = value;
    }
  }

  reloadData() {
    if (!this.updating) {
      this.fetchData.emit();
      this.updating = true;
    }
  }

  refreshBtn () {
    this.loadingIndicator = true;
    this.reloadData();
  }

  rowIdentity() {
    return (row) => {
      const id = row[this.identifier];
      if (_.isUndefined(id)) {
        throw new Error(`Wrong identifier "${this.identifier}" -> "${id}"`);
      }
      return id;
    };
  }

  useData() {
    if (!this.data) {
      return; // Wait for data
    }
    this.rows = [...this.data];
    if (this.search.length > 0) {
      this.updateFilter(true);
    }
    this.loadingIndicator = false;
    this.updating = false;
  }

  onSelect() {
    this.selection.update();
    this.updateSelection.emit(_.clone(this.selection));
  }

  toggleColumn($event: any) {
    const prop: TableColumnProp = $event.target.name;
    const hide = !$event.target.checked;
    if (hide && this.tableColumns.length === 1) {
      $event.target.checked = true;
      return;
    }
    _.find(this.columns, (c: CdTableColumn) => c.prop === prop).isHidden = hide;
    this.updateColumns();
  }

  updateColumns () {
    this.tableColumns = this.columns.filter(c => !c.isHidden);
    const sortProp = this.table.sorts[0].prop;
    if (!_.find(this.tableColumns, (c: CdTableColumn) => c.prop === sortProp)) {
      this.table.onColumnSort({sorts: this.createSortingDefinition(this.tableColumns[0].prop)});
    }
    this.table.recalculate();
  }

  createSortingDefinition (prop: TableColumnProp): SortPropDir[] {
    return [
      {
        prop: prop,
        dir: SortDirection.asc
      }
    ];
  }

  updateFilter(event?: any) {
    if (!event) {
      this.search = '';
    }
    let search = this.search.toLowerCase().replace(/,/g, '');
    const columns = this.columns.filter(c => c.cellTransformation !== CellTemplate.sparkline);
    if (search.match(/['"][^'"]+['"]/)) {
      search = search.replace(/['"][^'"]+['"]/g, (match: string) => {
        return match.replace(/(['"])([^'"]+)(['"])/g, '$2').replace(/ /g, '+');
      });
    }
    // update the rows
    this.rows = this.subSearch(this.data, search.split(' ').filter(s => s.length > 0), columns);
    // Whenever the filter changes, always go back to the first page
    this.table.offset = 0;
  }

  subSearch (data: any[], currentSearch: string[], columns: CdTableColumn[]) {
    if (currentSearch.length === 0 || data.length === 0) {
      return data;
    }
    const searchTerms: string[] = currentSearch.pop().replace('+', ' ').split(':');
    const columnsClone = [...columns];
    const dataClone = [...data];
    const filterColumns = (columnName: string) =>
      columnsClone.filter((c) => c.name.toLowerCase().indexOf(columnName) !== -1);
    if (searchTerms.length === 2) {
      columns = filterColumns(searchTerms[0]);
    }
    const searchTerm: string = _.last(searchTerms);
    data = this.basicDataSearch(searchTerm, data, columns);
    // Checks if user searches for column but he is still typing
    if (data.length === 0 && searchTerms.length === 1 && filterColumns(searchTerm).length > 0) {
      data = dataClone;
    }
    return this.subSearch(data, currentSearch, columnsClone);
  }

  basicDataSearch(searchTerm: string, data: any[], columns: CdTableColumn[]) {
    if (searchTerm.length === 0) {
      return data;
    }
    return data.filter(d => {
      return columns.filter(c => {
        let cellValue: any = _.get(d, c.prop);
        if (!_.isUndefined(c.pipe)) {
          cellValue = c.pipe.transform(cellValue);
        }
        if (_.isUndefined(cellValue)) {
          return;
        }
        if (_.isArray(cellValue)) {
          cellValue = cellValue.join(' ');
        } else if (_.isNumber(cellValue)) {
          cellValue = cellValue.toString();
        }
        return cellValue.toLowerCase().indexOf(searchTerm) !== -1;
      }).length > 0;
    });
  }

  getRowClass() {
    // Return the function used to populate a row's CSS classes.
    return () => {
      return {
        clickable: !_.isUndefined(this.selectionType)
      };
    };
  }
}
