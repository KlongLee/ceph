import { Pipe, PipeTransform } from '@angular/core';

import { I18n } from '@ngx-translate/i18n-polyfill';
import * as _ from 'lodash';

@Pipe({
  name: 'mdsSummary'
})
export class MdsSummaryPipe implements PipeTransform {
  constructor(private i18n: I18n) {}

  transform(value: any): any {
    if (!value) {
      return '';
    }

    let contentLine1 = '';
    let contentLine2 = '';
    let standbys = 0;
    let active = 0;
    let standbyReplay = 0;
    _.each(value.standbys, () => {
      standbys += 1;
    });

    if (value.standbys && !value.filesystems) {
      contentLine1 = `${standbys} ${this.i18n('up')}`;
      contentLine2 = this.i18n('no filesystems');
    } else if (value.filesystems.length === 0) {
      contentLine1 = this.i18n('no filesystems');
    } else {
      _.each(value.filesystems, (fs) => {
        _.each(fs.mdsmap.info, (mds) => {
          if (mds.state === 'up:standby-replay') {
            standbyReplay += 1;
          } else {
            active += 1;
          }
        });
      });

      contentLine1 = `${active} ${this.i18n('active')}`;
      contentLine2 = `${standbys + standbyReplay} ${this.i18n('standby')}`;
    }
    const standbyHoverText = value.standbys.map((s: any): string => s.name).join(', ');
    const standbyTitleText = !standbyHoverText
      ? ''
      : `${this.i18n('standby daemons')}: ${standbyHoverText}`;
    const fsLength = value.filesystems ? value.filesystems.length : 0;
    const infoObject = fsLength > 0 ? value.filesystems[0].mdsmap.info : {};
    const activeHoverText = Object.values(infoObject)
      .map((info: any): string => info.name)
      .join(', ');
    let activeTitleText = !activeHoverText
      ? ''
      : `${this.i18n('active daemon')}: ${activeHoverText}`;
    // There is always one standbyreplay to replace active daemon, if active one is down
    if (!active && fsLength > 0) {
      activeTitleText = `${standbyReplay} ${this.i18n('standbyReplay')}`;
    }
    const mgrSummary = [
      {
        content: contentLine1,
        class: 'popover-info',
        titleText: activeTitleText
      }
    ];
    if (contentLine2) {
      mgrSummary.push({
        content: '',
        class: 'card-text-line-break',
        titleText: ''
      });
      mgrSummary.push({
        content: contentLine2,
        class: 'popover-info',
        titleText: standbyTitleText
      });
    }

    return mgrSummary;
  }
}
