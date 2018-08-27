import { CommonModule } from '@angular/common';
import { NgModule } from '@angular/core';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { RouterModule } from '@angular/router';

import { BsDropdownModule, PopoverModule, TabsModule } from 'ngx-bootstrap';

import { SharedModule } from '../../shared/shared.module';
import { LoginComponent } from './login/login.component';
import { LogoutComponent } from './logout/logout.component';
import { UserCloneModalComponent } from './user-clone-modal/user-clone-modal.component';
import { UserFormComponent } from './user-form/user-form.component';
import { UserListComponent } from './user-list/user-list.component';

@NgModule({
  entryComponents: [UserCloneModalComponent],
  imports: [
    BsDropdownModule.forRoot(),
    CommonModule,
    FormsModule,
    PopoverModule.forRoot(),
    ReactiveFormsModule,
    SharedModule,
    TabsModule.forRoot(),
    RouterModule
  ],
  declarations: [
    LoginComponent,
    LogoutComponent,
    UserListComponent,
    UserFormComponent,
    UserCloneModalComponent
  ],
  exports: [LogoutComponent]
})
export class AuthModule {}
