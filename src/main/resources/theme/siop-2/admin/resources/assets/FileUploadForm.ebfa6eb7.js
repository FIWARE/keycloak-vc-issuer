import{u as v,r as L,h as U,F as D,j as l,q as u}from"./index.7cbfb18a.js";import{F as f}from"./FileUpload.c211f5c1.js";import{M as T,a as k}from"./Modal.11970fe7.js";import{a as R}from"./FormGroup.60c77f60.js";import{C as b}from"./CodeEditor.5b99e2f5.js";const M=({id:o,onChange:s,helpText:g="common-help:helpFileUpload",unWrap:d=!1,language:C,extension:F,...t})=>{const{t:n}=v(),c={value:"",filename:"",isLoading:!1,modal:!1},[e,a]=L.exports.useState(c),m=()=>a({...e,modal:!1}),p=(r,x)=>{a({...e,filename:x.name})},i=r=>{a({...e,value:r}),s(r)},h=()=>{a({...e,modal:!0})};return U(D,{children:[e.modal&&l(T,{variant:k.small,title:n("clearFile"),isOpen:!0,onClose:m,actions:[l(u,{variant:"primary","data-testid":"clear-button",onClick:()=>{a(c),s("")},children:n("clear")},"confirm"),l(u,{"data-testid":"cancel",variant:"link",onClick:m,children:n("cancel")},"cancel")],children:n("clearFileExplain")}),d&&l(f,{id:o,...t,type:"text",value:e.value,filename:e.filename,onFileInputChange:p,onDataChange:i,onTextChange:i,onClearClick:h,onReadStarted:()=>a({...e,isLoading:!0}),onReadFinished:()=>a({...e,isLoading:!1}),isLoading:e.isLoading,dropzoneProps:{accept:{"application/text":[F]}}}),!d&&l(R,{label:n("resourceFile"),fieldId:o,helperText:n(g),children:l(f,{"data-testid":o,id:o,...t,type:"text",value:e.value,filename:e.filename,onFileInputChange:p,onDataChange:i,onTextChange:i,onClearClick:h,onReadStarted:()=>a({...e,isLoading:!0}),onReadFinished:()=>a({...e,isLoading:!1}),isLoading:e.isLoading,hideDefaultPreview:!0,children:!t.hideDefaultPreview&&l(b,{isLineNumbersVisible:!0,code:e.value,language:C,height:"128px",onChange:i,isReadOnly:!t.allowEditingUploadedText})})})]})};export{M as F};
//# sourceMappingURL=FileUploadForm.ebfa6eb7.js.map