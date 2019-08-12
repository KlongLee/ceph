import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';

import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';

import { cdEncode } from '../decorators/cd-encode';
import { RbdConfigurationEntry } from '../models/configuration';
import { RbdConfigurationService } from '../services/rbd-configuration.service';
import { ApiModule } from './api.module';

@cdEncode
@Injectable({
  providedIn: ApiModule
})
export class PoolService {
  apiPath = 'api/pool';

  constructor(private http: HttpClient, private rbdConfigurationService: RbdConfigurationService) {}

  create(pool) {
    return this.http.post(this.apiPath, pool, { observe: 'response' });
  }

  update(pool) {
    let name: string;
    if (pool.hasOwnProperty('srcpool')) {
      name = pool.srcpool;
      delete pool.srcpool;
    } else {
      name = pool.pool;
      delete pool.pool;
    }
    return this.http.put(`${this.apiPath}/${encodeURIComponent(name)}`, pool, {
      observe: 'response'
    });
  }

  delete(name) {
    return this.http.delete(`${this.apiPath}/${name}`, { observe: 'response' });
  }

  get(poolName) {
    return this.http.get(`${this.apiPath}/${poolName}`);
  }

  getList() {
    return this.http.get(`${this.apiPath}?stats=true`);
  }

  getConfiguration(poolName: string): Observable<RbdConfigurationEntry[]> {
    return this.http.get<RbdConfigurationEntry[]>(`${this.apiPath}/${poolName}/configuration`).pipe(
      // Add static data maintained in RbdConfigurationService
      map((values) =>
        values.map((entry) =>
          Object.assign(entry, this.rbdConfigurationService.getOptionByName(entry.name))
        )
      )
    );
  }

  getInfo(pool_name?: string) {
    return this.http.get(`${this.apiPath}/_info` + (pool_name ? `?pool_name=${pool_name}` : ''));
  }

  list(attrs = []) {
    const attrsStr = attrs.join(',');
    return this.http
      .get(`${this.apiPath}?attrs=${attrsStr}`)
      .toPromise()
      .then((resp: any) => {
        return resp;
      });
  }
}
