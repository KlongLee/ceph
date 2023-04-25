import { ValidatorFn } from '@angular/forms';
import { FormlyFieldConfig } from '@ngx-formly/core';
import { forEach } from 'lodash';
import { formlyAsyncJsonValidator } from './validators/json-validator';
import { formlyRgwRoleNameValidator, formlyRgwRolePath } from './validators/rgw-role-validator';

export function getFieldState(field: FormlyFieldConfig, uiSchema: any[] = undefined) {
  const formState: any[] = uiSchema || field.options?.formState;
  if (formState) {
    return formState.find((element) => element.key == field.key);
  }
  return {};
}

export function setupValidators(field: FormlyFieldConfig, uiSchema: any[]) {
  const fieldState = getFieldState(field, uiSchema);
  let validators: ValidatorFn[] = [];
  forEach(fieldState.validators, (validatorStr) => {
    switch (validatorStr) {
      case 'json': {
        validators.push(formlyAsyncJsonValidator);
        break;
      }
      case 'rgwRoleName': {
        validators.push(formlyRgwRoleNameValidator);
        break;
      }
      case 'rgwRolePath': {
        validators.push(formlyRgwRolePath);
        break;
      }
    }
  });
  field.asyncValidators = { validation: validators };
}
