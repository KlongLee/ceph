import { HttpClient, HttpParams } from '@angular/common/http';
import { Injectable } from '@angular/core';

import _ from 'lodash';
import { forkJoin as observableForkJoin, Observable, of as observableOf } from 'rxjs';
import { catchError, mapTo, mergeMap } from 'rxjs/operators';

import { RgwDaemonService } from '~/app/shared/api/rgw-daemon.service';
import { cdEncode } from '~/app/shared/decorators/cd-encode';

@cdEncode
@Injectable({
  providedIn: 'root'
})
export class RgwUserService {
  private url = 'api/rgw/user';

  constructor(private http: HttpClient, private rgwDaemonService: RgwDaemonService) {}

  /**
   * Get the list of users.
   *
   * @return
   */
  list() {
    return this.enumerate().pipe(
      mergeMap((uids: string[]) => {
        if (uids.length > 0) {
          return observableForkJoin(
            uids.map((uid: string) => this.get(uid))
          );
        }
        return observableOf([]);
      })
    );
  }

  /**
   * Get the list of usernames.
   *
   * @return
   */
  enumerate() {
    return this.rgwDaemonService.request((params: HttpParams) => this.http.get(this.url, { params }));
  }

  enumerateEmail() {
    return this.rgwDaemonService.request((params: HttpParams) => this.http.get(`${this.url}/get_emails`, { params }));
  }

  get(uid: string) {
    return this.rgwDaemonService.request((params: HttpParams) => this.http.get(`${this.url}/${uid}`, { params }));
  }

  getQuota(uid: string) {
    return this.rgwDaemonService.request((params: HttpParams) => this.http.get(`${this.url}/${uid}/quota`, { params }));
  }

  create(args: Record<string, any>) {
    return this.rgwDaemonService.request((params: HttpParams) => {
      _.keys(args).forEach((key) => {
        params = params.append(key, args[key]);
      });
      return this.http.post(this.url, null, { params });
    });
  }

  update(uid: string, args: Record<string, any>) {
    return this.rgwDaemonService.request((params: HttpParams) => {
      _.keys(args).forEach((key) => {
        params = params.append(key, args[key]);
      });
      return this.http.put(`${this.url}/${uid}`, null, { params });
    });
  }

  updateQuota(uid: string, args: Record<string, string>) {
    return this.rgwDaemonService.request((params: HttpParams) => {
      _.keys(args).forEach((key) => {
        params = params.append(key, args[key]);
      });
      return this.http.put(`${this.url}/${uid}/quota`, null, { params });
    });
  }

  delete(uid: string) {
    return this.rgwDaemonService.request((params: HttpParams) => this.http.delete(`${this.url}/${uid}`, { params }));
  }

  createSubuser(uid: string, args: Record<string, string>) {
    return this.rgwDaemonService.request((params: HttpParams) => {
      _.keys(args).forEach((key) => {
        params = params.append(key, args[key]);
      });
      return this.http.post(`${this.url}/${uid}/subuser`, null, { params });
    });
  }

  deleteSubuser(uid: string, subuser: string) {
    return this.rgwDaemonService.request((params: HttpParams) => this.http.delete(`${this.url}/${uid}/subuser/${subuser}`, { params }));
  }

  addCapability(uid: string, type: string, perm: string) {
    return this.rgwDaemonService.request((params: HttpParams) => {
      params = params.append('type', type);
      params = params.append('perm', perm);
      return this.http.post(`${this.url}/${uid}/capability`, null, { params });
    });
  }

  deleteCapability(uid: string, type: string, perm: string) {
    return this.rgwDaemonService.request((params: HttpParams) => {
      params = params.append('type', type);
      params = params.append('perm', perm);
      return this.http.delete(`${this.url}/${uid}/capability`, { params });
    });
  }

  addS3Key(uid: string, args: Record<string, string>) {
    return this.rgwDaemonService.request((params: HttpParams) => {
      params = params.append('key_type', 's3');
      _.keys(args).forEach((key) => {
        params = params.append(key, args[key]);
      });
      return this.http.post(`${this.url}/${uid}/key`, null, { params });
    });
  }

  deleteS3Key(uid: string, accessKey: string) {
    return this.rgwDaemonService.request((params: HttpParams) => {
      params = params.append('key_type', 's3');
      params = params.append('access_key', accessKey);
      return this.http.delete(`${this.url}/${uid}/key`, { params });
    });
  }

  /**
   * Check if the specified user ID exists.
   *
   * @param uid The user ID to check.
   * @return
   */
  exists(uid: string): Observable<boolean> {
    return this.get(uid).pipe(
      mapTo(true),
      catchError((error: Event) => {
        if (_.isFunction(error.preventDefault)) {
          error.preventDefault();
        }
        return observableOf(false);
      })
    );
  }

  // Using @cdEncodeNot would be the preferred way here, but this
  // causes an error: https://tracker.ceph.com/issues/37505
  // Use decodeURIComponent as workaround.
  // emailExists(@cdEncodeNot email: string): Observable<boolean> {
  emailExists(email: string): Observable<boolean> {
    email = decodeURIComponent(email);
    return this.enumerateEmail().pipe(
      mergeMap((resp: any[]) => {
        const index = _.indexOf(resp, email);
        return observableOf(-1 !== index);
      })
    );
  }
}
