import{u as D,by as E,az as $,aA as w,aX as a,h as b,F as A,j as o,ao as c,an as F}from"./index.2ecf13ca.js";import{u as l}from"./ConfirmDialog.b43fd344.js";import{H as x}from"./SettingsCache.66c6a7d0.js";import{a as P,b as K}from"./index.esm.68aaf060.js";const N=({provider:m,editMode:d,save:f,noDivider:U=!1})=>{const{t:s}=D("user-federation"),{id:r}=E(),{adminClient:i}=$(),{addAlert:n,addError:t}=w(),{control:y}=P(),u=K({name:"config.importEnabled",control:y,defaultValue:["true"]})[0],[g,p]=l({titleKey:"user-federation:userFedUnlinkUsersConfirmTitle",messageKey:"user-federation:userFedUnlinkUsersConfirm",continueButtonLabel:"user-federation:unlinkUsers",onConfirm:()=>I()}),[v,C]=l({titleKey:s("removeImportedUsers"),messageKey:s("removeImportedUsersMessage"),continueButtonLabel:"common:remove",onConfirm:async()=>{try{h(),n(s("removeImportedUsersSuccess"),a.success)}catch(e){t("user-federation:removeImportedUsersError",e)}}}),h=async()=>{try{r&&await i.userStorageProvider.removeImportedUsers({id:r}),n(s("removeImportedUsersSuccess"),a.success)}catch(e){t("user-federation:removeImportedUsersError",e)}},k=async()=>{try{if(r){const e=await i.userStorageProvider.sync({id:r,action:"triggerChangedUsersSync"});e.ignored?n(`${e.status}.`,a.warning):n(s("syncUsersSuccess")+`${e.added} users added, ${e.updated} users updated, ${e.removed} users removed, ${e.failed} users failed.`,a.success)}}catch(e){t("user-federation:syncUsersError",e)}},S=async()=>{try{if(r){const e=await i.userStorageProvider.sync({id:r,action:"triggerFullSync"});e.ignored?n(`${e.status}.`,a.warning):n(s("syncUsersSuccess")+`${e.added} users added, ${e.updated} users updated, ${e.removed} users removed, ${e.failed} users failed.`,a.success)}}catch(e){t("user-federation:syncUsersError",e)}},I=async()=>{try{r&&await i.userStorageProvider.unlinkUsers({id:r}),n(s("unlinkUsersSuccess"),a.success)}catch(e){t("user-federation:unlinkUsersError",e)}};return b(A,{children:[o(p,{}),o(C,{}),o(x,{provider:m,noDivider:U,save:f,dropdownItems:[o(c,{onClick:k,isDisabled:u==="false",children:s("syncChangedUsers")},"sync"),o(c,{onClick:S,isDisabled:u==="false",children:s("syncAllUsers")},"syncall"),o(c,{isDisabled:d?!d.includes("UNSYNCED"):!1,onClick:g,children:s("unlinkUsers")},"unlink"),o(c,{onClick:v,children:s("removeImported")},"remove"),o(F,{},"separator")]})]})};export{N as E};
//# sourceMappingURL=ExtendedHeader.b33bedff.js.map