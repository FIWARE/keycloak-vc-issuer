import{r as f,az as N,ax as U,l as z,u as $,aA as W,aZ as X,ad as Z,aX as K,d4 as L,j as e,K as _,h as l,F as J,ao as D,P as Q,aw as P,q,aD as Y,aC as ee}from"./index.2ecf13ca.js";import{u as re,b as te,C as ae,F as oe}from"./index.esm.68aaf060.js";import{u as pe}from"./ConfirmDialog.b43fd344.js";import{D as ne}from"./DynamicComponents.16b222ec.js";import{F as ie}from"./FormAccess.7ed5d8eb.js";import{H as v}from"./HelpItem.49be9c4e.js";import{K as c}from"./KeycloakTextInput.97e36976.js";import{V as se}from"./ViewHeader.67577dd4.js";import{u as de}from"./useParams.921239aa.js";import{a as g,F as me,A as le}from"./FormGroup.24d2e56a.js";import{S as ce,b as ue,a as ye}from"./Select.5d6f6214.js";import"./Modal.2c72168d.js";import"./ClientSelect.95a4ec0e.js";import"./FileUpload.005327fa.js";import"./CodeEditor.0b7c4c70.js";import"./copy-icon.06155c15.js";import"./EmptyStateBody.25bf6e38.js";import"./EmptyStateSecondaryActions.3ed74a6a.js";import"./GroupPickerDialog.38947607.js";import"./ListEmptyState.94d606ed.js";import"./TableToolbar.f167c244.js";import"./plus-circle-icon.f1969120.js";import"./DataListItemRow.7402b99a.js";import"./data-list.f7ff2ea7.js";import"./grip-vertical-icon.6efe1939.js";import"./ActionListItem.c90af00f.js";import"./FlexItem.2ee8dfc9.js";import"./minus-circle-icon.e9e185f2.js";import"./MultiLineInput.7867bd1a.js";import"./PasswordInput.4caf2dff.js";import"./useToggle.97c716af.js";import"./AddRoleMappingModal.c7175fba.js";import"./KeycloakDataTable.5c9a6c7c.js";import"./Td.ff2a9f66.js";import"./star-icon.648ddb2a.js";import"./check.51c67984.js";import"./Checkbox.56efba4a.js";import"./useLocaleSort.377bcdf5.js";import"./resource.09062762.js";import"./joinPath.69b856b1.js";import"./filter-icon.f568e30b.js";import"./KeycloakTextArea.2947a089.js";import"./GridItem.a22d8cac.js";import"./Text.441b2f8e.js";function pr(){const o=re(),[n,O]=f.exports.useState(),[h,H]=f.exports.useState(),{adminClient:d}=N(),{id:k,mapperId:p}=de(),u=U(),{realm:I}=z(),{t:a}=$("user-federation"),{addAlert:S,addError:T}=W(),[w,C]=f.exports.useState(!1),[F,M]=f.exports.useState(0),E=()=>M(F+1);X(async()=>{const r=await d.components.listSubComponents({id:k,type:"org.keycloak.storage.ldap.mappers.LDAPStorageMapper"});if(p&&p!=="new"){const t=await d.components.findOne({id:p});return{components:r,fetchedMapper:t}}return{components:r}},({components:r,fetchedMapper:t})=>{if(O(t),H(r),p!=="new"&&!t)throw new Error(a("common:notFound"));t&&x(t)},[]);const x=r=>{ee(r,o.setValue)},G=async r=>{const t=Y(r),m={...t,config:Object.entries(t.config||{}).reduce((y,[B,b])=>(y[B]=Array.isArray(b)?b:[b],y),{})};try{p==="new"?(await d.components.create(m),u(L({realm:I,id:r.parentId,tab:"mappers"}))):await d.components.update({id:p},m),x(m),S(a(p==="new"?"common:mappingCreatedSuccess":"common:mappingUpdatedSuccess"),K.success)}catch(y){T(p==="new"?"common:mappingCreatedError":"common:mappingUpdatedError",y)}},A=async r=>{try{const t=await d.userStorageProvider.mappersSync({parentId:n?.parentId||"",id:p,direction:r});S(a("syncLDAPGroupsSuccessful",{result:t.status}))}catch(t){T("user-federation:syncLDAPGroupsError",t)}E()},[R,j]=pe({titleKey:"common:deleteMappingTitle",messageKey:"common:deleteMappingConfirm",continueButtonLabel:"common:delete",continueButtonVariant:Z.danger,onConfirm:async()=>{try{await d.components.del({id:n.id}),S(a("common:mappingDeletedSuccess"),K.success),u(L({id:k,realm:I,tab:"mappers"}))}catch(r){T("common:mappingDeletedError",r)}}}),V=te({control:o.control,name:"providerId"});if(!h)return e(_,{});const i=p==="new",s=h.find(r=>r.id===V);return l(J,{children:[e(j,{}),e(se,{titleKey:n?n.name:a("common:createNewMapper"),dropdownItems:i?void 0:[e(D,{onClick:R,children:a("common:delete")},"delete"),s?.metadata.fedToKeycloakSyncSupported&&e(D,{onClick:()=>A("fedToKeycloak"),children:a("syncLDAPGroupsToKeycloak")},"fedSync"),s?.metadata.keycloakToFedSyncSupported&&e(D,{onClick:()=>{A("keycloakToFed")},children:a("syncKeycloakGroupsToLDAP")},"ldapSync")]},F),l(Q,{variant:"light",isFilled:!0,children:[l(ie,{role:"manage-realm",isHorizontal:!0,children:[!i&&e(g,{label:a("common:id"),fieldId:"kc-ldap-mapper-id",children:e(c,{isDisabled:!0,id:"kc-ldap-mapper-id","data-testid":"ldap-mapper-id",...o.register("id")})}),l(g,{label:a("common:name"),labelIcon:e(v,{helpText:"user-federation-help:nameHelp",fieldLabelId:"name"}),fieldId:"kc-ldap-mapper-name",isRequired:!0,children:[e(c,{isDisabled:!i,isRequired:!0,id:"kc-ldap-mapper-name","data-testid":"ldap-mapper-name",validated:o.formState.errors.name?P.error:P.default,...o.register("name",{required:!0})}),e(c,{hidden:!0,defaultValue:i?k:n?n.parentId:"",id:"kc-ldap-parentId","data-testid":"ldap-mapper-parentId",...o.register("parentId")}),e(c,{hidden:!0,defaultValue:"org.keycloak.storage.ldap.mappers.LDAPStorageMapper",id:"kc-ldap-provider-type","data-testid":"ldap-mapper-provider-type",...o.register("providerType")})]}),i?e(g,{label:a("common:mapperType"),labelIcon:e(v,{helpText:s?.helpText?s.helpText:a("user-federation-help:mapperTypeHelp"),fieldLabelId:"mapperType"}),fieldId:"kc-providerId",isRequired:!0,children:e(ae,{name:"providerId",defaultValue:"",control:o.control,"data-testid":"ldap-mapper-type-select",render:({field:r})=>e(ce,{toggleId:"kc-providerId",required:!0,onToggle:()=>C(!w),isOpen:w,onSelect:(t,m)=>{r.onChange(m),C(!1)},selections:r.value,variant:ue.typeahead,children:h.map(t=>e(ye,{value:t.id},t.id))})})}):e(g,{label:a("common:mapperType"),labelIcon:e(v,{helpText:s?.helpText?s.helpText:a("user-federation-help:mapperTypeHelp"),fieldLabelId:"mapperType"}),fieldId:"kc-ldap-mapper-type",isRequired:!0,children:e(c,{isDisabled:!i,isRequired:!0,id:"kc-ldap-mapper-type","data-testid":"ldap-mapper-type-fld",...o.register("providerId")})}),e(oe,{...o,children:!!V&&e(ne,{properties:s?.properties})})]}),e(me,{onSubmit:o.handleSubmit(()=>G(o.getValues())),children:l(le,{children:[e(q,{isDisabled:!o.formState.isDirty,variant:"primary",type:"submit","data-testid":"ldap-mapper-save",children:a("common:save")}),e(q,{variant:"link",onClick:()=>u(i?-1:`/${I}/user-federation/ldap/${n.parentId}/mappers`),"data-testid":"ldap-mapper-cancel",children:a("common:cancel")})]})})]})]})}export{pr as default};
//# sourceMappingURL=LdapMapperDetails.c63ddb48.js.map