import{a as b}from"./index.esm.1e7ace95.js";import{H as t}from"./HelpItem.719382e8.js";import{K as r}from"./KeycloakTextInput.9afb01cd.js";import{M as d}from"./MultiLineInput.091fd21a.js";import{u as I,l as u,h as n,F as c,j as e,bz as h,m as U}from"./index.7cbfb18a.js";import{a as l}from"./FormGroup.60c77f60.js";const x=({protocol:s="openid-connect"})=>{const{t:i}=I("clients"),{register:a,watch:m}=b(),{realm:p}=u(),o=m("attributes.saml_idp_initiated_sso_url_name");return n(c,{children:[e(l,{label:i("rootUrl"),fieldId:"kc-root-url",labelIcon:e(t,{helpText:"clients-help:rootURL",fieldLabelId:"clients:rootUrl"}),children:e(r,{id:"kc-root-url",type:"url",...a("rootUrl")})}),e(l,{label:i("homeURL"),fieldId:"kc-home-url",labelIcon:e(t,{helpText:"clients-help:homeURL",fieldLabelId:"clients:homeURL"}),children:e(r,{id:"kc-home-url",type:"url",...a("baseUrl")})}),e(l,{label:i("validRedirectUri"),fieldId:"kc-redirect",labelIcon:e(t,{helpText:"clients-help:validRedirectURIs",fieldLabelId:"clients:validRedirectUri"}),children:e(d,{id:"kc-redirect",name:"redirectUris","aria-label":i("validRedirectUri"),addButtonLabel:"clients:addRedirectUri"})}),e(l,{label:i("validPostLogoutRedirectUri"),fieldId:"kc-postLogoutRedirect",labelIcon:e(t,{helpText:"clients-help:validPostLogoutRedirectURIs",fieldLabelId:"clients:validPostLogoutRedirectUri"}),children:e(d,{id:"kc-postLogoutRedirect",name:h("attributes.post.logout.redirect.uris"),"aria-label":i("validPostLogoutRedirectUri"),addButtonLabel:"clients:addPostLogoutRedirectUri",stringify:!0})}),s==="saml"&&n(c,{children:[e(l,{label:i("idpInitiatedSsoUrlName"),fieldId:"idpInitiatedSsoUrlName",labelIcon:e(t,{helpText:"clients-help:idpInitiatedSsoUrlName",fieldLabelId:"clients:idpInitiatedSsoUrlName"}),helperText:o!==""&&i("idpInitiatedSsoUrlNameHelp",{url:`${U.authServerUrl}/realms/${p}/protocol/saml/clients/${o}`}),children:e(r,{id:"idpInitiatedSsoUrlName","data-testid":"idpInitiatedSsoUrlName",...a("attributes.saml_idp_initiated_sso_url_name")})}),e(l,{label:i("idpInitiatedSsoRelayState"),fieldId:"idpInitiatedSsoRelayState",labelIcon:e(t,{helpText:"clients-help:idpInitiatedSsoRelayState",fieldLabelId:"clients:idpInitiatedSsoRelayState"}),children:e(r,{id:"idpInitiatedSsoRelayState","data-testid":"idpInitiatedSsoRelayState",...a("attributes.saml_idp_initiated_sso_relay_state")})}),e(l,{label:i("masterSamlProcessingUrl"),fieldId:"masterSamlProcessingUrl",labelIcon:e(t,{helpText:"clients-help:masterSamlProcessingUrl",fieldLabelId:"clients:masterSamlProcessingUrl"}),children:e(r,{id:"masterSamlProcessingUrl",type:"url","data-testid":"masterSamlProcessingUrl",...a("adminUrl")})})]}),s!=="saml"&&e(l,{label:i("webOrigins"),fieldId:"kc-web-origins",labelIcon:e(t,{helpText:"clients-help:webOrigins",fieldLabelId:"clients:webOrigins"}),children:e(d,{id:"kc-web-origins",name:"webOrigins","aria-label":i("webOrigins"),addButtonLabel:"clients:addWebOrigins"})})]})};export{x as L};
//# sourceMappingURL=LoginSettings.498d8554.js.map