import{u as R,g as v,r as c,h as C,T as V,j as e,q as b,ad as E,F as $,am as q,aG as G,ag as N,ao as A,b3 as W}from"./index.2ecf13ca.js";import{L as B}from"./ListEmptyState.94d606ed.js";import{K as O}from"./KeycloakDataTable.5c9a6c7c.js";import{u as z,m as k}from"./useLocaleSort.377bcdf5.js";import{M as H,a as J}from"./Modal.2c72168d.js";import{T as P,a as Q}from"./Text.441b2f8e.js";import{e as U,D as w,a as K,c as F,d as I}from"./DataListItemRow.7402b99a.js";const X=o=>{const{t:a}=R("client-scopes"),y=v(),f=o.protocol,n=y.protocolMapperTypes[f],d=y.builtinProtocolMappers[f],[g,l]=c.exports.useState([]),[u,h]=c.exports.useState([]),M=z(),p=c.exports.useMemo(()=>M(d,k("name")).map(t=>{const i=n.filter(s=>s.id===t.protocolMapper)[0];return{item:t,name:t.name,description:i.helpText}}),[d,n]),[m,L]=c.exports.useState(p);if(o.filter&&o.filter.length!==g.length){l(o.filter);const t=o.filter.map(i=>i.name);L([...p.filter(i=>!t.includes(i.item.name))])}const D=c.exports.useMemo(()=>M(n,k("name")),[n]),r=!!o.filter,T=[a("common:name"),a("common:description")];return C(H,{"aria-label":a(r?"addPredefinedMappers":"emptySecondaryAction"),variant:J.medium,header:C(V,{role:"dialog","aria-label":a(r?"addPredefinedMappers":"emptySecondaryAction"),children:[e(P,{component:Q.h1,children:a(r?"addPredefinedMappers":"emptySecondaryAction")}),e(P,{children:a(r?"predefinedMappingDescription":"configureMappingDescription")})]}),isOpen:o.open,onClose:o.toggleDialog,actions:r?[e(b,{id:"modal-confirm","data-testid":"confirm",isDisabled:m.length===0||u.length===0,onClick:()=>{o.onConfirm(u.map(({item:t})=>t)),o.toggleDialog()},children:a("common:add")},"confirm"),e(b,{id:"modal-cancel","data-testid":"cancel",variant:E.link,onClick:()=>{o.toggleDialog()},children:a("common:cancel")},"cancel")]:[],children:[!r&&C(U,{onSelectDataListItem:t=>{const i=n.find(s=>s.id===t);o.onConfirm(i),o.toggleDialog()},"aria-label":a("addPredefinedMappers"),isCompact:!0,children:[e(w,{"aria-label":a("headerName"),id:"header",children:e(K,{children:e(F,{dataListCells:T.map(t=>e(I,{style:{fontWeight:700},children:t},t))})})}),D.map(t=>e(w,{"aria-label":t.name,id:t.id,children:e(K,{children:e(F,{dataListCells:[e(I,{children:t.name},`name-${t.id}`),e(I,{children:t.helpText},`helpText-${t.id}`)]})})},t.id))]}),r&&e(O,{loader:m,onSelect:h,canSelectAll:!0,ariaLabelKey:"client-scopes:addPredefinedMappers",searchPlaceholderKey:"common:searchForMapper",columns:[{name:"name",displayKey:"common:name"},{name:"description",displayKey:"common:description"}],emptyState:e(B,{message:a("common:emptyMappers"),instructions:a("client-scopes:emptyBuiltInMappersInstructions")})})]})},ne=({model:o,onAdd:a,onDelete:y,detailLink:f})=>{const{t:n}=R("client-scopes"),[d,g]=c.exports.useState(!1),l=o.protocolMappers,u=v().protocolMapperTypes[o.protocol],[h,M]=c.exports.useState(0);c.exports.useEffect(()=>M(h+1),[l]);const[p,m]=c.exports.useState(!1),[L,D]=c.exports.useState(o.protocolMappers),r=i=>{D(i?l||[]:void 0),m(!p)},T=async()=>l?l.reduce((s,S)=>{const x=u.find(({id:j})=>j===S.protocolMapper);return x?s.concat({...S,category:x.category,type:x.name,priority:x.priority}):s},[]).sort((s,S)=>s.priority-S.priority):[],t=({id:i,name:s})=>e(W,{to:f(i),children:s});return C($,{children:[e(X,{protocol:o.protocol,filter:L,onConfirm:a,open:p,toggleDialog:()=>m(!p)}),e(O,{loader:T,ariaLabelKey:"client-scopes:clientScopeList",searchPlaceholderKey:"common:searchForMapper",toolbarItem:e(q,{onSelect:()=>g(!1),toggle:e(G,{isPrimary:!0,id:"mapperAction",onToggle:()=>g(!d),toggleIndicator:N,children:n("common:addMapper")}),isOpen:d,dropdownItems:[e(A,{onClick:()=>r(!0),children:n("fromPredefinedMapper")},"predefined"),e(A,{onClick:()=>r(!1),children:n("byConfiguration")},"byConfiguration")]}),actions:[{title:n("common:delete"),onRowClick:y}],columns:[{name:"name",cellRenderer:t},{name:"category"},{name:"type"},{name:"priority"}],emptyState:e(B,{message:n("common:emptyMappers"),instructions:n("common:emptyMappersInstructions"),secondaryActions:[{text:n("common:emptyPrimaryAction"),onClick:()=>r(!0)},{text:n("emptySecondaryAction"),onClick:()=>r(!1)}]})},h)]})};export{ne as M};
//# sourceMappingURL=MapperList.edc4ba6e.js.map