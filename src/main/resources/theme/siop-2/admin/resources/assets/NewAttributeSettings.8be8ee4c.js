import{u as C,j as e,az as X,r as V,aZ as K,K as me,h as c,F,G as j,aB as ue,q as P,g as pe,ad as he,ax as be,aA as ge,P as ve,b3 as fe,cT as Z,aX as Ve,aC as qe,d0 as Ce}from"./index.2ecf13ca.js";import{a as M,b as L,C as I,u as Y,F as ee}from"./index.esm.68aaf060.js";import{S as Ne}from"./ScrollForm.6573b3d3.js";import{V as ke}from"./ViewHeader.67577dd4.js";import{u as B}from"./useParams.921239aa.js";import{F as U}from"./FormAccess.7ed5d8eb.js";import{K as ye}from"./KeyValueInput.8d334a75.js";/* empty css                               */import{a as b,F as ae,A as Se}from"./FormGroup.24d2e56a.js";import{G as te,a as _}from"./GridItem.a22d8cac.js";import{H as x}from"./HelpItem.49be9c4e.js";import{K as $}from"./KeycloakTextInput.97e36976.js";import{C as z}from"./Checkbox.56efba4a.js";import{u as Te}from"./ConfirmDialog.b43fd344.js";import{u as re}from"./useToggle.97c716af.js";import{D as Ae}from"./DynamicComponents.16b222ec.js";import{M as se,a as le}from"./Modal.2c72168d.js";import{T as ie,a as ne,b as G,c as R,d as oe,e as D}from"./Td.ff2a9f66.js";import{T as de,a as ce}from"./Text.441b2f8e.js";import{P as Ie}from"./plus-circle-icon.f1969120.js";import{U as xe}from"./UserProfileContext.1a5ea02c.js";import{i as we}from"./isEqual.7e8157bd.js";import{S as H,b as W,a as O}from"./Select.5d6f6214.js";import{R as w}from"./Radio.9cf26071.js";import"./FormPanel.3fe898ae.js";import"./CardHeader.2467be54.js";import"./Card.3271e4cd.js";import"./CardTitle.ab8f9378.js";import"./CardBody.8e0a3a4b.js";import"./copy-icon.06155c15.js";import"./FlexItem.2ee8dfc9.js";import"./minus-circle-icon.e9e185f2.js";import"./ActionListItem.c90af00f.js";import"./check.51c67984.js";import"./ClientSelect.95a4ec0e.js";import"./FileUpload.005327fa.js";import"./CodeEditor.0b7c4c70.js";import"./EmptyStateBody.25bf6e38.js";import"./EmptyStateSecondaryActions.3ed74a6a.js";import"./GroupPickerDialog.38947607.js";import"./ListEmptyState.94d606ed.js";import"./TableToolbar.f167c244.js";import"./DataListItemRow.7402b99a.js";import"./data-list.f7ff2ea7.js";import"./grip-vertical-icon.6efe1939.js";import"./MultiLineInput.7867bd1a.js";import"./PasswordInput.4caf2dff.js";import"./AddRoleMappingModal.c7175fba.js";import"./KeycloakDataTable.5c9a6c7c.js";import"./useLocaleSort.377bcdf5.js";import"./resource.09062762.js";import"./joinPath.69b856b1.js";import"./filter-icon.f568e30b.js";import"./KeycloakTextArea.2947a089.js";import"./star-icon.648ddb2a.js";const Re=()=>{const{t:a}=C("realm-settings");return e(U,{role:"manage-realm",isHorizontal:!0,children:e(b,{hasNoPaddingTop:!0,label:a("annotations"),fieldId:"kc-annotations",className:"kc-annotations-label",children:e(te,{className:"kc-annotations",children:e(_,{children:e(ye,{name:"annotations"})})})})})},J=[{label:"requiredForLabel.both",value:["admin","user"]},{label:"requiredForLabel.users",value:["user"]},{label:"requiredForLabel.admins",value:["admin"]}],De=()=>{const{t:a}=C("realm-settings"),{adminClient:n}=X(),l=M(),[r,d]=V.exports.useState(),[m,p]=V.exports.useState(),[h,u]=V.exports.useState(!1),[v,f]=V.exports.useState(!1),[o,i]=V.exports.useState(!1),{attributeName:k}=B(),y=!!k,S=L({control:l.control,name:"selector.scopes",defaultValue:[]}),T=L({control:l.control,name:"required.scopes",defaultValue:[]}),A=L({control:l.control,name:"isRequired",defaultValue:!1});return K(()=>n.clientScopes.find(),d,[]),K(()=>n.users.getProfile(),p,[]),r?c(U,{role:"manage-realm",isHorizontal:!0,children:[e(b,{label:a("attributeName"),labelIcon:e(x,{helpText:"realm-settings-help:attributeNameHelp",fieldLabelId:"realm-settings:attributeName"}),fieldId:"kc-attribute-name",isRequired:!0,validated:l.formState.errors.name?"error":"default",helperTextInvalid:l.formState.errors.name?.message,children:e($,{isRequired:!0,id:"kc-attribute-name",defaultValue:"","data-testid":"attribute-name",isDisabled:y,validated:l.formState.errors.name?"error":"default",...l.register("name",{required:{value:!0,message:a("validateName")}})})}),e(b,{label:a("attributeDisplayName"),labelIcon:e(x,{helpText:"realm-settings-help:attributeDisplayNameHelp",fieldLabelId:"realm-settings:attributeDisplayName"}),fieldId:"kc-attribute-display-name",children:e($,{id:"kc-attribute-display-name",defaultValue:"","data-testid":"attribute-display-name",...l.register("displayName")})}),e(b,{label:a("attributeGroup"),labelIcon:e(x,{helpText:"realm-setting-help:attributeGroupHelp",fieldLabelId:"realm-setting:attributeGroup"}),fieldId:"kc-attribute-group",children:e(I,{name:"group",defaultValue:"",control:l.control,render:({field:s})=>e(H,{toggleId:"kc-attributeGroup",onToggle:()=>i(!o),isOpen:o,onSelect:(t,g)=>{s.onChange(g.toString()),i(!1)},selections:[s.value||a("common:none")],variant:W.single,children:[e(O,{value:"",children:a("common:none")},"empty"),...m?.groups?.map(t=>e(O,{value:t.name,children:t.name},t.name))||[]]})})}),!Ge.includes(k)&&c(F,{children:[e(j,{}),c(b,{label:a("enabledWhen"),fieldId:"enabledWhen",hasNoPaddingTop:!0,children:[e(w,{id:"always","data-testid":"always",isChecked:S.length===r.length,name:"enabledWhen",label:a("always"),onChange:s=>{s?l.setValue("selector.scopes",r.map(t=>t.name)):l.setValue("selector.scopes",[])},className:"pf-u-mb-md"}),e(w,{id:"scopesAsRequested","data-testid":"scopesAsRequested",isChecked:S.length!==r.length,name:"enabledWhen",label:a("scopesAsRequested"),onChange:s=>{s?l.setValue("selector.scopes",[]):l.setValue("selector.scopes",r.map(t=>t.name))},className:"pf-u-mb-md"})]}),e(b,{fieldId:"kc-scope-enabled-when",children:e(I,{name:"selector.scopes",control:l.control,defaultValue:r.map(s=>s.name),render:({field:s})=>e(H,{name:"scopes","data-testid":"enabled-when-scope-field",variant:W.typeaheadMulti,typeAheadAriaLabel:"Select",chipGroupProps:{numChips:3,expandedText:a("common:hide"),collapsedText:a("common:showRemaining")},onToggle:t=>u(t),selections:s.value,onSelect:(t,g)=>{const q=g.toString();let N=[""];s.value?N=s.value.includes(q)?s.value.filter(E=>E!==q):[...s.value,q]:N=[q],s.onChange(N)},onClear:t=>{t.stopPropagation(),s.onChange([])},isOpen:h,isDisabled:S.length===r.length,"aria-labelledby":"scope",children:r.map(t=>e(O,{value:t.name},t.name))})})}),e(j,{}),e(b,{label:a("required"),labelIcon:e(x,{helpText:"realm-settings-help:requiredHelp",fieldLabelId:"realm-settings:required"}),fieldId:"kc-required",hasNoPaddingTop:!0,children:e(I,{name:"isRequired","data-testid":"required",defaultValue:!1,control:l.control,render:({field:s})=>e(ue,{id:"kc-required",onChange:s.onChange,isChecked:s.value,label:a("common:on"),labelOff:a("common:off"),"aria-label":a("required")})})}),A&&c(F,{children:[e(b,{label:a("requiredFor"),fieldId:"requiredFor",hasNoPaddingTop:!0,children:e(I,{name:"required.roles","data-testid":"requiredFor",defaultValue:J[0].value,control:l.control,render:({field:s})=>e("div",{className:"kc-requiredFor",children:J.map(t=>e(w,{id:t.label,"data-testid":t.label,isChecked:we(s.value,t.value),name:"roles",onChange:()=>{s.onChange(t.value)},label:a(t.label),className:"kc-requiredFor-option"},t.label))})})}),c(b,{label:a("requiredWhen"),fieldId:"requiredWhen",hasNoPaddingTop:!0,children:[e(w,{id:"requiredAlways","data-testid":"requiredAlways",isChecked:T.length===r.length,name:"requiredWhen",label:a("always"),onChange:s=>{s?l.setValue("required.scopes",r.map(t=>t.name)):l.setValue("required.scopes",[])},className:"pf-u-mb-md"}),e(w,{id:"requiredScopesAsRequested","data-testid":"requiredScopesAsRequested",isChecked:T.length!==r.length,name:"requiredWhen",label:a("scopesAsRequested"),onChange:s=>{s?l.setValue("required.scopes",[]):l.setValue("required.scopes",r.map(t=>t.name))},className:"pf-u-mb-md"})]}),e(b,{fieldId:"kc-scope-required-when",children:e(I,{name:"required.scopes",control:l.control,defaultValue:[],render:({field:s})=>e(H,{name:"scopeRequired","data-testid":"required-when-scope-field",variant:W.typeaheadMulti,typeAheadAriaLabel:"Select",chipGroupProps:{numChips:3,expandedText:a("common:hide"),collapsedText:a("common:showRemaining")},onToggle:t=>f(t),selections:s.value,onSelect:(t,g)=>{const q=g.toString();let N=[""];s.value?N=s.value.includes(q)?s.value.filter(E=>E!==q):[...s.value,q]:N=[q],s.onChange(N)},onClear:t=>{t.stopPropagation(),s.onChange([])},isOpen:v,isDisabled:T.length===r.length,"aria-labelledby":"scope",children:r.map(t=>e(O,{value:t.name},t.name))})})})]})]})]}):e(me,{})},Q=({name:a})=>{const{t:n}=C("realm-settings"),{control:l}=M();return e(te,{children:e(I,{name:`permissions.${a}`,control:l,defaultValue:[],render:({field:r})=>c(F,{children:[e(_,{lg:4,sm:6,children:e(z,{id:`user-${a}`,label:n("user"),value:"user","data-testid":`user-${a}`,isChecked:r.value.includes("user"),onChange:()=>{const d="user",m=r.value.includes(d)?r.value.filter(p=>p!==d):[...r.value,d];r.onChange(m)}})}),e(_,{lg:8,sm:6,children:e(z,{id:`admin-${a}`,label:n("admin"),value:"admin","data-testid":`admin-${a}`,isChecked:r.value.includes("admin"),onChange:()=>{const d="admin",m=r.value.includes(d)?r.value.filter(p=>p!==d):[...r.value,d];r.onChange(m)}})})]})})})},Fe=()=>{const{t:a}=C("realm-settings");return c(U,{role:"manage-realm",isHorizontal:!0,children:[e(b,{hasNoPaddingTop:!0,label:a("whoCanEdit"),labelIcon:e(x,{helpText:"realm-settings-help:whoCanEditHelp",fieldLabelId:"realm-settings:whoCanEdit"}),fieldId:"kc-who-can-edit",children:e(Q,{name:"edit"})}),e(b,{hasNoPaddingTop:!0,label:a("whoCanView"),labelIcon:e(x,{helpText:"realm-settings-help:whoCanViewHelp",fieldLabelId:"realm-settings:whoCanView"}),fieldId:"kc-who-can-view",children:e(Q,{name:"view"})})]})},Pe=({open:a,toggleDialog:n,onConfirm:l,selected:r})=>{const{t:d}=C("realm-settings"),m=Y(),{handleSubmit:p}=m,h=r,u=v=>{l({...v,id:r.id}),n()};return e(se,{variant:le.small,title:d("addValidatorRole",{validatorName:h.id}),description:h.helpText,isOpen:a,onClose:n,actions:[e(P,{"data-testid":"save-validator-role-button",variant:"primary",onClick:()=>p(u)(),children:d("common:save")},"save"),e(P,{"data-testid":"cancel-validator-role-button",variant:"link",onClick:n,children:d("common:cancel")},"cancel")],children:e(ae,{children:e(ee,{...m,children:e(Ae,{properties:h.properties})})})})},Oe=({selectedValidators:a,toggleDialog:n,onConfirm:l})=>{const{t:r}=C("realm-settings"),[d,m]=V.exports.useState(),p=pe().componentTypes?.["org.keycloak.validate.Validator"]||[],[h,u]=V.exports.useState(p.filter(({id:o})=>!a.map(({key:i})=>i).includes(o))),[v,f]=re();return c(F,{children:[v&&e(Pe,{onConfirm:o=>{l(o),u(h.filter(({id:i})=>i!==o.id))},open:v,toggleDialog:f,selected:d}),e(se,{variant:le.small,title:r("addValidator"),isOpen:!0,onClose:n,children:h.length!==0?c(ie,{children:[e(ne,{children:c(G,{children:[e(R,{children:r("validatorDialogColNames.colName")}),e(R,{children:r("validatorDialogColNames.colDescription")})]})}),e(oe,{children:h.map(o=>c(G,{onRowClick:()=>{m(o),f()},isHoverable:!0,children:[e(D,{dataLabel:r("validatorDialogColNames.colName"),children:o.id}),e(D,{dataLabel:r("validatorDialogColNames.colDescription"),children:o.helpText})]},o.id))})]}):e(de,{className:"kc-emptyValidators",component:ce.h6,children:r("realm-settings:emptyValidators")})})]})},Le=()=>{const{t:a}=C("realm-settings"),[n,l]=re(),[r,d]=V.exports.useState(),{setValue:m,control:p,register:h}=M(),u=L({name:"validations",control:p,defaultValue:[]});V.exports.useEffect(()=>{h("validations")},[]);const[v,f]=Te({titleKey:a("deleteValidatorConfirmTitle"),messageKey:a("deleteValidatorConfirmMsg",{validatorName:r}),continueButtonLabel:"common:delete",continueButtonVariant:he.danger,onConfirm:async()=>{const o=u.filter(i=>i.key!==r);m("validations",[...o])}});return c(F,{children:[n&&e(Oe,{selectedValidators:u,onConfirm:o=>{m("validations",[...u,{key:o.id,value:o.config}])},toggleDialog:l}),e(f,{}),c("div",{className:"kc-attributes-validations",children:[e(P,{id:"addValidator",onClick:()=>l(),variant:"link","data-testid":"addValidator",className:"kc--attributes-validations--add-validation-button",icon:e(Ie,{}),children:a("realm-settings:addValidator")}),e(j,{}),u.length!==0?c(ie,{children:[e(ne,{children:c(G,{children:[e(R,{children:a("validatorColNames.colName")}),e(R,{children:a("validatorColNames.colConfig")}),e(R,{})]})}),e(oe,{children:u.map(o=>c(G,{children:[e(D,{dataLabel:a("validatorColNames.colName"),children:o.key}),e(D,{dataLabel:a("validatorColNames.colConfig"),children:JSON.stringify(o.value)}),e(D,{className:"kc--attributes-validations--action-cell",children:e(P,{variant:"link","data-testid":"deleteValidator",onClick:()=>{v(),d(o.key)},children:a("common:delete")},"validator")})]},o.key))})]}):e(de,{className:"kc-emptyValidators",component:ce.h6,children:a("realm-settings:emptyValidators")})]})]})},Ge=["username","email"],Me=({save:a})=>{const{t:n}=C("realm-settings"),l=M(),{realm:r,attributeName:d}=B(),m=!!d;return c(xe,{children:[e(Ne,{sections:[{title:n("generalSettings"),panel:e(De,{})},{title:n("permission"),panel:e(Fe,{})},{title:n("validations"),panel:e(Le,{})},{title:n("annotations"),panel:e(Re,{})}]}),e(ae,{onSubmit:l.handleSubmit(a),children:c(Se,{className:"keycloak__form_actions",children:[e(P,{variant:"primary",type:"submit","data-testid":"attribute-create",children:n(m?"common:save":"common:create")}),e(fe,{to:Z({realm:r,tab:"attributes"}),"data-testid":"attribute-cancel",className:"kc-attributeCancel",children:n("common:cancel")})]})})]})};function Ha(){const{realm:a,attributeName:n}=B(),{adminClient:l}=X(),r=Y(),{t:d}=C("realm-settings"),m=be(),{addAlert:p,addError:h}=ge(),[u,v]=V.exports.useState(null),f=!!n;K(()=>l.users.getProfile(),i=>{v(i);const{annotations:k,validations:y,permissions:S,selector:T,required:A,...s}=i.attributes.find(t=>t.name===n)||{};qe(s,r.setValue),Object.entries(Ce.flatten({permissions:S,selector:T,required:A},{safe:!0})).map(([t,g])=>r.setValue(t,g)),r.setValue("annotations",Object.entries(k||{}).map(([t,g])=>({key:t,value:g}))),r.setValue("validations",Object.entries(y||{}).map(([t,g])=>({key:t,value:g}))),r.setValue("isRequired",A!==void 0)},[]);const o=async i=>{const k=i.validations.reduce((s,t)=>(s[t.key]=t.value?.length===0?{}:t.value,s),{}),y=i.annotations.reduce((s,t)=>Object.assign(s,{[t.key]:t.value}),{}),A=f?(()=>u?.attributes.map(s=>s.name!==n?s:(delete s.required,Object.assign({...s,name:n,displayName:i.displayName,selector:i.selector,permissions:i.permissions,annotations:y,validations:k},i.isRequired?{required:i.required}:void 0,i.group?{group:i.group}:{group:null}))))():(()=>u?.attributes.concat([Object.assign({name:i.name,displayName:i.displayName,required:i.isRequired?i.required:{},selector:i.selector,permissions:i.permissions,annotations:y},i.isRequired?{required:i.required}:void 0,i.group?{group:i.group}:void 0)]))();try{await l.users.updateProfile({...u,attributes:A,realm:a}),m(Z({realm:a,tab:"attributes"})),p(d("realm-settings:createAttributeSuccess"),Ve.success)}catch(s){h("realm-settings:createAttributeError",s)}};return c(ee,{...r,children:[e(ke,{titleKey:f?n:d("createAttribute"),subKey:f?"":d("createAttributeSubTitle")}),e(ve,{variant:"light",children:e(Me,{save:()=>r.handleSubmit(o)()})})]})}export{Ge as USERNAME_EMAIL,Ha as default};
//# sourceMappingURL=NewAttributeSettings.8be8ee4c.js.map