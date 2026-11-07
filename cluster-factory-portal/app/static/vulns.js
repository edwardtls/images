// Security > Vulnerabilities. Renders the report from the JSON API and checks
// for a newer report every minute, so the page never needs a reload.
(()=>{
const root=document.getElementById('vulns');
if(!root)return;
const view=root.dataset.view,id=root.dataset.id;
const SEVERITIES=['Critical','High','Medium','Low','Negligible','Unknown'];
const PAGE=100;
const state={severities:new Set(['Critical','High','Medium','Low']),kev:false,fixable:false,query:'',limit:PAGE,softwareQuery:'',softwareLimit:PAGE};
let generated=null;

const el=(tag,attrs={},...children)=>{
  const node=document.createElement(tag);
  for(const [key,value] of Object.entries(attrs)){
    if(value===null||value===undefined||value===false)continue;
    if(key==='class')node.className=value;
    else if(key.startsWith('on'))node.addEventListener(key.slice(2),value);
    else node.setAttribute(key,value===true?'':value);
  }
  for(const child of children.flat()){
    if(child===null||child===undefined||child===false)continue;
    node.append(child instanceof Node?child:document.createTextNode(String(child)));
  }
  return node;
};
const ago=value=>{
  if(!value)return '—';
  const seconds=Math.max(0,(Date.now()-new Date(value).getTime())/1000);
  if(seconds<90)return 'just now';
  if(seconds<5400)return `${Math.round(seconds/60)} min ago`;
  if(seconds<129600)return `${Math.round(seconds/3600)} h ago`;
  return `${Math.round(seconds/86400)} days ago`;
};
const when=value=>el('time',{datetime:value,title:value?new Date(value).toLocaleString():'' ,'data-ago':value||''},ago(value));
const systemLink=(system,name)=>el('a',{href:`/security/vulnerabilities/systems/${encodeURIComponent(system)}`},name||system);
const vulnLink=vuln=>el('a',{class:'mono',href:`/security/vulnerabilities/vulnerabilities/${encodeURIComponent(vuln)}`},vuln);
const badge=severity=>el('span',{class:`vuln-severity ${String(severity||'Unknown').toLowerCase()}`},severity||'Unknown');
const kevBadge=kev=>kev?el('span',{class:'vuln-kev',title:'On the CISA list of known exploited vulnerabilities'},'Known exploited'):null;
const percent=value=>typeof value==='number'?`${(value*100).toFixed(value<0.01?2:1)}%`:'—';
const safeUrl=value=>{try{const url=new URL(value);return ['https:','http:'].includes(url.protocol)?url.href:null}catch(_e){return null}};
const counts=c=>el('span',{class:'vuln-counts'},
  ...['critical','high','medium','low'].map(key=>el('b',{class:`${key}${c&&c[key]?'':' zero'}`,title:`${key} vulnerabilities`},c?c[key]||0:0)),
  c&&c.kev?el('span',{class:'vuln-kev'},`${c.kev} exploited`):null);
const cell=(label,...children)=>el('span',{'data-label':label},...children);
const fetchJson=async path=>{
  const response=await fetch(path,{headers:{Accept:'application/json'},cache:'no-store'});
  if(response.status===404)throw new Error('This item is not in the latest report. It may have been fixed or the system was removed.');
  if(!response.ok)throw new Error('The vulnerability report is temporarily unavailable.');
  return response.json();
};
const showError=message=>{root.replaceChildren(el('section',{class:'warning'},el('strong',{},'Report unavailable.'),el('span',{},message)))};
const stamp=report=>el('p',{class:'vuln-stamp muted'},'Report built ',when(report.generated_at),report.database&&report.database.built?[' · vulnerability data from ',when(report.database.built)]:null,' · checks for updates every minute');

const filters=(onChange)=>{
  const chips=el('nav',{class:'security-window vuln-filters','aria-label':'Severity filter'},
    ...SEVERITIES.map(severity=>el('a',{href:'#',class:state.severities.has(severity)?'active':'','aria-pressed':String(state.severities.has(severity)),
      onclick:event=>{event.preventDefault();state.severities.has(severity)?state.severities.delete(severity):state.severities.add(severity);state.limit=PAGE;onChange()}},severity)),
    el('a',{href:'#',class:state.kev?'active':'','aria-pressed':String(state.kev),onclick:event=>{event.preventDefault();state.kev=!state.kev;state.limit=PAGE;onChange()}},'Known exploited only'),
    el('a',{href:'#',class:state.fixable?'active':'','aria-pressed':String(state.fixable),onclick:event=>{event.preventDefault();state.fixable=!state.fixable;state.limit=PAGE;onChange()}},'Fix available only'));
  const search=el('input',{type:'search',placeholder:'Search by ID or package',value:state.query,'aria-label':'Search vulnerabilities',
    oninput:event=>{state.query=event.target.value.trim().toLowerCase();state.limit=PAGE;onChange(true)}});
  return el('div',{class:'vuln-toolbar'},chips,search);
};
const matches=item=>state.severities.has(item.severity)&&(!state.kev||item.kev)&&(!state.fixable||item.fixable)
  &&(!state.query||item.id.toLowerCase().includes(state.query)||(item.aliases||[]).some(a=>a.toLowerCase().includes(state.query))
     ||(item.packages||[]).some(p=>p.toLowerCase().includes(state.query))||(item.package||'').toLowerCase().includes(state.query));
const more=(shown,total,onMore)=>shown<total?el('button',{class:'secondary vuln-more',type:'button',onclick:onMore},`Show more (${total-shown} hidden)`):null;

function overview(report){
  const systems=report.systems||[],vulns=report.vulnerabilities||[];
  const failed=systems.filter(s=>s.status!=='ok'&&!(s.error||'').includes('container images'));
  const withFindings=systems.filter(s=>s.counts&&s.counts.total);
  const total=key=>vulns.filter(v=>v.severity===key).length;
  const metrics=el('section',{class:'metrics vuln-metrics'},
    el('article',{},el('span',{},'Systems scanned'),el('strong',{},systems.length-failed.length),el('small',{},failed.length?`${failed.length} failed or unreachable`:'all answered')),
    el('article',{},el('span',{},'Systems with findings'),el('strong',{},withFindings.length),el('small',{},`of ${systems.length}`)),
    el('article',{},el('span',{},'Critical / High'),el('strong',{},`${total('Critical')} / ${total('High')}`),el('small',{},`${vulns.length} vulnerabilities in total`)),
    el('article',{class:vulns.some(v=>v.kev)?'vuln-alert':''},el('span',{},'Known exploited'),el('strong',{},vulns.filter(v=>v.kev).length),el('small',{},'on the CISA KEV list')));

  const list=el('div');
  const renderList=(keepFocus)=>{
    const shown=vulns.filter(matches);
    const rows=shown.slice(0,state.limit).map(v=>el('div',{class:'tr'},
      cell('Vulnerability',vulnLink(v.id),v.aliases&&v.aliases.length?el('small',{class:'mono'},v.aliases.join(' · ')):null,el('small',{},v.summary||'')),
      cell('Severity',badge(v.severity),kevBadge(v.kev)),
      cell('Risk',el('strong',{},v.risk?v.risk.toFixed(1):'—'),el('small',{},`CVSS ${v.cvss??'—'} · EPSS ${percent(v.epss)}`)),
      cell('Packages',el('span',{class:'mono'},(v.packages||[]).join(', '))),
      cell('Systems',el('strong',{},v.systems)),
      cell('Fix',v.fixable?el('span',{class:'status ready'},'available'):el('span',{class:'status'},'none yet'))));
    const search=list.querySelector('input');const caret=search&&search.selectionStart;
    list.replaceChildren(
      el('div',{class:'section-head'},el('div',{},el('h2',{},'Vulnerabilities'),el('p',{},`${shown.length} of ${vulns.length} match the filters. Highest risk first. Open one to see the affected systems.`))),
      filters(renderList),
      shown.length?el('div',{class:'table vuln-table'},el('div',{class:'tr th'},el('span',{},'Vulnerability'),el('span',{},'Severity'),el('span',{},'Risk'),el('span',{},'Packages'),el('span',{},'Systems'),el('span',{},'Fix')),...rows)
        :el('div',{class:'empty'},vulns.length?'No vulnerabilities match these filters.':'No known vulnerabilities in any scanned system.'),
      more(Math.min(state.limit,shown.length),shown.length,()=>{state.limit+=PAGE;renderList()}));
    if(keepFocus){const input=list.querySelector('input');input.focus();if(caret!==null)input.setSelectionRange(caret,caret)}
  };
  if(vulns.length)renderList();

  const systemRows=systems.map(s=>el('div',{class:'tr'},
    cell('System',systemLink(s.id,s.name),el('small',{},[s.kind,s.cluster?`cluster ${s.cluster}`:null].filter(Boolean).join(' · '))),
    cell('OS / address',s.os||'—',el('small',{class:'mono'},s.address||'')),
    cell('Last scan',when(s.scanned_at),s.status==='ok'?null:el('small',{class:'vuln-error'},s.error||s.status)),
    cell('Software',`${s.packages} packages`,s.images?el('small',{},`${s.images} container images`):null),
    cell('Findings',counts(s.counts))));
  const skipped=(report.skipped||[]).length?el('section',{class:'panel vuln-skipped'},el('h2',{},'Not scanned'),
    el('div',{class:'mini-list'},...report.skipped.map(s=>el('div',{},el('span',{},`${s.name} `,el('small',{class:'mono'},`${s.node}/${s.vmid}`)),el('span',{class:'muted'},s.reason))))):null;

  root.replaceChildren(stamp(report),metrics,
    vulns.length?list:el('section',{class:'empty'},'No known vulnerabilities in any scanned system. The systems and their software are listed below.'),
    el('section',{},el('div',{class:'section-head'},el('div',{},el('h2',{},'Systems'),el('p',{},'Systems scanned in the last 7 days. Open one to see its software and findings.'))),
      el('div',{class:'table vuln-systems'},el('div',{class:'tr th'},el('span',{},'System'),el('span',{},'OS / address'),el('span',{},'Last scan'),el('span',{},'Software'),el('span',{},'Critical · High · Medium · Low')),...systemRows)),
    skipped);
}

function findingsTable(findings,{showVia=true}={}){
  const wrap=el('div');
  const render=(keepFocus)=>{
    const shown=findings.filter(f=>matches({...f,fixable:f.fix_state==='fixed'}));
    const search=wrap.querySelector('input');const caret=search&&search.selectionStart;
    wrap.replaceChildren(filters(render),
      shown.length?el('div',{class:'table vuln-findings'},el('div',{class:'tr th'},el('span',{},'Vulnerability'),el('span',{},'Severity'),el('span',{},'Package'),el('span',{},'Fixed in'),el('span',{},'Found in')),
        ...shown.slice(0,state.limit).map(f=>el('div',{class:'tr'},
          cell('Vulnerability',vulnLink(f.id),el('small',{},`risk ${f.risk?f.risk.toFixed(1):'—'} · CVSS ${f.cvss??'—'}`)),
          cell('Severity',badge(f.severity),kevBadge(f.kev)),
          cell('Package',el('span',{class:'mono'},f.package),el('small',{class:'mono'},f.version)),
          cell('Fixed in',f.fixed_in&&f.fixed_in.length?el('span',{class:'mono'},f.fixed_in.join(', ')):el('span',{class:'muted'},f.fix_state==='wont-fix'?'will not be fixed':'no fix yet')),
          cell('Found in',showVia?(f.via==='host'?'host software':el('small',{class:'mono'},f.via)):'image'))))
      :el('div',{class:'empty'},'No findings match these filters.'),
      more(Math.min(state.limit,shown.length),shown.length,()=>{state.limit+=PAGE;render()}));
    if(keepFocus){const input=wrap.querySelector('input');input.focus();if(caret!==null)input.setSelectionRange(caret,caret)}
  };
  render();
  return wrap;
}

function softwareTable(software,title){
  const wrap=el('section');
  const render=(keepFocus)=>{
    const shown=software.filter(p=>!state.softwareQuery||p.name.toLowerCase().includes(state.softwareQuery));
    wrap.replaceChildren(el('div',{class:'section-head'},el('div',{},el('h2',{},title),el('p',{},`${software.length} packages`))),
      el('input',{type:'search',placeholder:'Filter by name',value:state.softwareQuery,'aria-label':'Filter software',
        oninput:event=>{state.softwareQuery=event.target.value.trim().toLowerCase();state.softwareLimit=PAGE;render(true)}}),
      shown.length?el('div',{class:'table vuln-software'},el('div',{class:'tr th'},el('span',{},'Name'),el('span',{},'Version'),el('span',{},'Type')),
        ...shown.slice(0,state.softwareLimit).map(p=>el('div',{class:'tr'},cell('Name',el('span',{class:'mono'},p.name)),cell('Version',el('span',{class:'mono'},p.version)),cell('Type',p.type))))
      :el('div',{class:'empty'},software.length?'No software matches.':'No software was found.'),
      more(Math.min(state.softwareLimit,shown.length),shown.length,()=>{state.softwareLimit+=PAGE;render()}));
    if(keepFocus){const input=wrap.querySelector('input');input.focus()}
  };
  render();
  return wrap;
}

function imageRow(image){
  const details=el('details',{class:'vuln-image'});
  details.append(el('summary',{},el('span',{class:'mono'},image.ref),' ',counts(image.counts),el('small',{},`${image.packages} packages · ${image.workloads.join(', ')}`),image.error?el('small',{class:'vuln-error'},image.error):null));
  details.addEventListener('toggle',async()=>{
    if(!details.open||details.dataset.loaded)return;
    details.dataset.loaded='1';
    const body=el('div',{class:'empty'},'Loading the image software…');details.append(body);
    try{
      const data=await fetchJson(`/api/security/vulnerabilities/image/${encodeURIComponent(image.key)}`);
      body.replaceWith(el('div',{},data.findings.length?findingsTable(data.findings,{showVia:false}):null,softwareTable(data.software,'Image software')));
    }catch(error){body.textContent=error.message;delete details.dataset.loaded}
  });
  return details;
}

function system(data){
  const findings=data.findings||[];
  root.replaceChildren(
    el('p',{class:'vuln-back'},el('a',{href:'/security/vulnerabilities'},'← All systems')),
    el('section',{class:'section-head'},el('div',{},el('h2',{},data.name),el('p',{},[data.kind,data.os,data.address,data.source&&data.source!=='inventory'?`Proxmox ${data.source}`:null,data.cluster?`cluster ${data.cluster}`:null].filter(Boolean).join(' · ')))),
    el('p',{class:'muted'},'Last scan ',when(data.scanned_at),data.status==='ok'?null:el('span',{class:'vuln-error'},` · last attempt failed: ${data.error||data.status}`)),
    el('section',{class:'metrics vuln-metrics'},
      el('article',{},el('span',{},'Vulnerabilities'),el('strong',{},data.counts.total),el('small',{},`${data.counts.fixable} with a fix`)),
      el('article',{},el('span',{},'Critical / High'),el('strong',{},`${data.counts.critical} / ${data.counts.high}`)),
      el('article',{class:data.counts.kev?'vuln-alert':''},el('span',{},'Known exploited'),el('strong',{},data.counts.kev)),
      el('article',{},el('span',{},'Software'),el('strong',{},data.packages),el('small',{},`${data.images} container images`))),
    findings.length?el('section',{},el('div',{class:'section-head'},el('div',{},el('h2',{},'Findings'),el('p',{},'Highest risk first.'))),findingsTable(findings)):el('div',{class:'empty'},'No known vulnerabilities on this system.'),
    (data.container_images||[]).length?el('section',{},el('div',{class:'section-head'},el('div',{},el('h2',{},'Container images'),el('p',{},'Running on this system. Open one for its software.'))),...data.container_images.map(imageRow)):null,
    data.images_only?null:softwareTable(data.software||[],'Installed software'));
}

function vulnerability(data){
  const urls=(data.urls||[]).map(safeUrl).filter(Boolean);
  const bySystem=new Map();
  for(const row of data.affected||[]){if(!bySystem.has(row.system))bySystem.set(row.system,[]);bySystem.get(row.system).push(row)}
  root.replaceChildren(
    el('p',{class:'vuln-back'},el('a',{href:'/security/vulnerabilities'},'← All vulnerabilities')),
    el('section',{class:'section-head'},el('div',{},el('h2',{class:'mono'},data.id),data.aliases&&data.aliases.length?el('p',{class:'mono'},data.aliases.join(' · ')):null)),
    el('section',{class:'metrics vuln-metrics'},
      el('article',{},el('span',{},'Severity'),el('strong',{},data.severity)),
      el('article',{},el('span',{},'Risk / CVSS'),el('strong',{},`${data.risk?data.risk.toFixed(1):'—'} / ${data.cvss??'—'}`)),
      el('article',{},el('span',{},'EPSS'),el('strong',{},percent(data.epss)),el('small',{},data.epss_percentile?`higher than ${Math.round(data.epss_percentile*100)}% of all CVEs`:'')),
      el('article',{class:data.kev?'vuln-alert':''},el('span',{},'Known exploited'),el('strong',{},data.kev?'Yes':'No'))),
    el('section',{class:'panel'},el('h2',{},'Description'),el('p',{},data.description||'No description was published.'),
      urls.length?el('ul',{class:'vuln-links'},...urls.map(url=>el('li',{},el('a',{href:url,rel:'noopener noreferrer',target:'_blank'},url)))):null),
    el('section',{},el('div',{class:'section-head'},el('div',{},el('h2',{},'Affected systems'),el('p',{},`${bySystem.size} systems`))),
      el('div',{class:'table vuln-affected'},el('div',{class:'tr th'},el('span',{},'System'),el('span',{},'Package'),el('span',{},'Fixed in'),el('span',{},'Found in')),
        ...[...bySystem.entries()].flatMap(([system,rows])=>rows.map(row=>el('div',{class:'tr'},
          cell('System',systemLink(system,row.system_name)),
          cell('Package',el('span',{class:'mono'},row.package),el('small',{class:'mono'},row.version)),
          cell('Fixed in',row.fixed_in&&row.fixed_in.length?el('span',{class:'mono'},row.fixed_in.join(', ')):el('span',{class:'muted'},'no fix yet')),
          cell('Found in',row.via==='host'?'host software':el('small',{class:'mono'},row.via))))))));
}

const load=async()=>{
  try{
    const report=await fetchJson('/api/security/vulnerabilities');
    if(report.generated_at===generated){root.querySelectorAll('[data-ago]').forEach(node=>{node.textContent=ago(node.dataset.ago)});return}
    const data=view==='overview'?report:await fetchJson(`/api/security/vulnerabilities/${view}/${encodeURIComponent(id)}`);
    const first=generated===null;generated=report.generated_at;
    ({overview,system,vulnerability})[view](data);
    if(!first)root.prepend(el('p',{class:'vuln-updated'},'A new scan arrived and the page was updated.'));
  }catch(error){if(generated===null)showError(error.message)}
};
load();setInterval(load,60000);
})();
