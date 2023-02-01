import{U as u}from"./index.7cbfb18a.js";function m(){const{whoAmI:o}=u();return function(n,e){const a=o.getLocale();return[...n].sort((s,l)=>{const r=e(s),c=e(l);return r===void 0||c===void 0?0:r.localeCompare(c,a)})}}const f=o=>t=>t[o];export{f as m,m as u};
//# sourceMappingURL=useLocaleSort.b8a659bb.js.map
