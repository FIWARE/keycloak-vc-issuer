import{F as u}from"./index.esm.68aaf060.js";import{F as d}from"./FormAccess.7ed5d8eb.js";import{K as p}from"./KeyValueInput.8d334a75.js";import{u as b,h as e,j as t,q as n}from"./index.2ecf13ca.js";import{A as h}from"./FormGroup.24d2e56a.js";const S=({form:o,reset:a,save:r,fineGrainedAccess:m})=>{const{t:i}=b("roles"),c=!r&&!a,{formState:{isDirty:s},handleSubmit:l}=o;return e(d,{role:"manage-realm",onSubmit:r?l(r):void 0,fineGrainedAccess:m,children:[t(u,{...o,children:t(p,{name:"attributes"})}),!c&&e(h,{className:"kc-attributes__action-group",children:[t(n,{"data-testid":"save-attributes",variant:"primary",type:"submit",isDisabled:!s,children:i("common:save")}),t(n,{onClick:a,variant:"link",isDisabled:!s,children:i("common:revert")})]})]})};export{S as A};
//# sourceMappingURL=AttributeForm.417b4170.js.map