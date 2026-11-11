document.querySelectorAll('[data-dialog]').forEach(b=>b.addEventListener('click',()=>document.getElementById(b.dataset.dialog).showModal()));
document.querySelectorAll('[data-close]').forEach(b=>b.addEventListener('click',()=>b.closest('dialog').close()));
document.addEventListener('submit',e=>{const f=e.target.closest('[data-confirm]');if(f&&!confirm(f.dataset.confirm))e.preventDefault()});

const mcpTab=document.querySelector('[data-mcp-tab]');
if(mcpTab){
  const storageKey='factory:mcp:last-seen';
  const dot=mcpTab.querySelector('.mcp-unseen-dot');
  const setUnseen=unseen=>{dot.hidden=!unseen;mcpTab.classList.toggle('has-unseen',unseen);mcpTab.title=unseen?'New MCP honeypot activity':''};
  const latest=async()=>{
    const response=await fetch('/api/security/mcp/latest',{headers:{Accept:'application/json'},cache:'no-store'});
    if(!response.ok)return null;
    return (await response.json()).cursor;
  };
  const check=async()=>{
    try{
      const cursor=await latest();
      if(!cursor){setUnseen(false);return}
      const content=document.getElementById('security-content');
      if(content&&content.dataset.view==='mcp'){localStorage.setItem(storageKey,cursor);setUnseen(false);return}
      const seen=localStorage.getItem(storageKey);
      if(seen===null){localStorage.setItem(storageKey,cursor);setUnseen(false);return}
      setUnseen(seen!==cursor);
    }catch(_error){/* A telemetry outage must not disrupt the security page. */}
  };
  check();setInterval(check,30000);
}
const log=document.getElementById('log');
if(log){
  const limit=3000;let lines=[],pending=[],received=false,flushTimer=null;
  const flush=()=>{flushTimer=null;if(!pending.length)return;const follow=log.scrollHeight-log.scrollTop-log.clientHeight<80;lines.push(...pending);pending=[];if(lines.length>limit)lines.splice(0,lines.length-limit);log.textContent=lines.join('\n')+'\n';if(follow||!received)log.scrollTop=log.scrollHeight;received=true};
  const enqueue=(incoming,reset=false)=>{if(reset){lines=[];pending=[];received=false}pending.push(...incoming);if(!flushTimer)flushTimer=setTimeout(flush,100)};
  const source=new EventSource(`/api/jobs/${log.dataset.job}/stream`);
  source.onopen=()=>{if(document.getElementById('job-state').textContent==='Reconnecting…')document.getElementById('job-state').textContent='Running'};
  source.addEventListener('logs',event=>{const payload=JSON.parse(event.data);enqueue(payload.lines||[],Boolean(payload.reset))});
  source.addEventListener('stage',event=>{const line=JSON.parse(event.data);document.getElementById('stage').textContent=line.replace(/^.*FACTORY_STAGE\s+/, '').replaceAll('-',' ')});
  source.addEventListener('stream-error',event=>{document.getElementById('job-state').textContent='Reconnecting…';enqueue([`Log stream unavailable: ${JSON.parse(event.data)}`])});
  source.addEventListener('done',event=>{flush();document.getElementById('job-state').textContent=JSON.parse(event.data);source.close()});
  source.onerror=()=>{document.getElementById('job-state').textContent='Reconnecting…'};
}

const initSecurityChart=(root=document)=>{
  const securityChart=root.querySelector('#security-trend-chart');
  if(!securityChart)return;
  const trend=JSON.parse(securityChart.dataset.trend);
  const points=trend.points||[];
  const tooltip=securityChart.parentElement.querySelector('.security-chart-tooltip');
  const series=[
    {key:'total',label:'Total',color:'#071622',width:3},
    {key:'ssh',label:'SSH',color:'#287a68',width:2},
    {key:'rdp',label:'RDP',color:'#d87832',width:2},
    {key:'http',label:'HTTP/S',color:'#c44949',width:2}
  ];
  let geometry=null;
  const dateLabel=value=>new Intl.DateTimeFormat(undefined,{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'}).format(new Date(value));
  const draw=()=>{
    const rect=securityChart.getBoundingClientRect();
    if(!rect.width||!rect.height||!points.length)return;
    const ratio=Math.min(window.devicePixelRatio||1,2);
    securityChart.width=Math.round(rect.width*ratio);securityChart.height=Math.round(rect.height*ratio);
    const context=securityChart.getContext('2d');context.setTransform(ratio,0,0,ratio,0,0);context.clearRect(0,0,rect.width,rect.height);
    const margin={top:14,right:12,bottom:34,left:42};
    const width=rect.width-margin.left-margin.right,height=rect.height-margin.top-margin.bottom;
    const maximum=Math.max(1,...points.map(point=>point.total));
    const ceiling=Math.max(5,Math.ceil(maximum/5)*5);
    const x=index=>margin.left+(points.length===1?width/2:index*width/(points.length-1));
    const y=value=>margin.top+height-(value/ceiling)*height;
    context.font='11px ui-monospace, monospace';context.textBaseline='middle';
    for(let line=0;line<=4;line++){
      const value=Math.round(ceiling*(4-line)/4),position=margin.top+height*line/4;
      context.strokeStyle='#d9d8d1';context.lineWidth=1;context.beginPath();context.moveTo(margin.left,position);context.lineTo(rect.width-margin.right,position);context.stroke();
      context.fillStyle='#65727a';context.textAlign='right';context.fillText(String(value),margin.left-8,position);
    }
    const labelIndexes=[0,Math.floor((points.length-1)/2),points.length-1].filter((value,index,array)=>array.indexOf(value)===index);
    context.textBaseline='bottom';
    labelIndexes.forEach((index,labelIndex)=>{context.fillStyle='#65727a';context.textAlign=labelIndex===0?'left':labelIndex===labelIndexes.length-1?'right':'center';context.fillText(dateLabel(points[index].timestamp),x(index),rect.height-2)});
    [...series].reverse().forEach(item=>{
      context.strokeStyle=item.color;context.lineWidth=item.width;context.lineJoin='round';context.lineCap='round';context.beginPath();
      points.forEach((point,index)=>{const px=x(index),py=y(point[item.key]);if(index===0)context.moveTo(px,py);else context.lineTo(px,py)});context.stroke();
    });
    geometry={rect,x,y};
  };
  const showPoint=event=>{
    if(!geometry||!points.length)return;
    const bounds=securityChart.getBoundingClientRect();
    const localX=Math.max(0,Math.min(bounds.width,event.clientX-bounds.left));
    const plotStart=42,plotWidth=bounds.width-54;
    const index=Math.max(0,Math.min(points.length-1,Math.round(((localX-plotStart)/plotWidth)*(points.length-1))));
    const point=points[index],left=geometry.x(index),top=geometry.y(point.total);
    tooltip.textContent=`${dateLabel(point.timestamp)}\nTotal ${point.total} · SSH ${point.ssh}\nRDP ${point.rdp} · HTTP/S ${point.http}`;
    tooltip.style.left=`${Math.max(78,Math.min(bounds.width-78,left))}px`;tooltip.style.top=`${Math.max(86,top)}px`;tooltip.hidden=false;
  };
  securityChart.addEventListener('pointermove',showPoint);securityChart.addEventListener('pointerdown',showPoint);
  securityChart.addEventListener('pointerleave',()=>{tooltip.hidden=true});
  new ResizeObserver(draw).observe(securityChart);draw();
};

const securityContent=document.getElementById('security-content');
if(securityContent){
  const tabs=document.querySelector('[data-security-tabs]');
  const windows=document.querySelector('[data-security-windows]');
  // Vulnerabilities is a third view of this page (static/vulns.js), so every
  // tab switch happens in place.
  const vulnsPane=document.getElementById('vulns-pane');
  const markTab=view=>tabs.querySelectorAll('[data-security-nav]').forEach(link=>{
    const active=link.dataset.view===view;link.classList.toggle('active',active);
    if(active)link.setAttribute('aria-current','page');else link.removeAttribute('aria-current');
  });
  const showPane=vulns=>{securityContent.hidden=vulns;windows.hidden=vulns;if(vulnsPane)vulnsPane.hidden=!vulns};
  const openVulns=(path,{history=true}={})=>{
    if(!vulnsPane||!window.factoryVulns)return false;
    showPane(true);markTab('vulns');
    window.factoryVulns.open(path,{history});
    return true;
  };
  const loadSecurity=async(view,range,{history=true}={})=>{
    if(view==='vulns'&&openVulns('/security/vulnerabilities',{history}))return;
    showPane(false);
    securityContent.setAttribute('aria-busy','true');
    try{
      const query=new URLSearchParams({view,window:range});
      const response=await fetch(`/api/security/view?${query}`,{headers:{Accept:'text/html'},cache:'no-store'});
      if(!response.ok)throw new Error(`Security telemetry returned ${response.status}`);
      securityContent.innerHTML=await response.text();
      securityContent.dataset.view=view;securityContent.dataset.window=range;
      markTab(view);
      tabs.querySelectorAll('[data-security-nav]:not([data-view="vulns"])').forEach(link=>{
        const target=new URL(link.href);target.searchParams.set('window',range);link.href=target.pathname+target.search;
      });
      windows.querySelectorAll('[data-security-nav]').forEach(link=>{
        const active=link.dataset.window===range;link.classList.toggle('active',active);
        if(active)link.setAttribute('aria-current','page');else link.removeAttribute('aria-current');
        const target=new URL(link.href);target.searchParams.set('view',view);link.href=target.pathname+target.search;
      });
      if(view==='mcp'){
        const marker=securityContent.querySelector('[data-mcp-latest]');
        if(marker&&marker.dataset.mcpLatest)localStorage.setItem('factory:mcp:last-seen',marker.dataset.mcpLatest);
        const dot=document.querySelector('.mcp-unseen-dot');if(dot)dot.hidden=true;
      }
      initSecurityChart(securityContent);
      if(history)window.history.pushState({view,range},'',`/security?${query}`);
    }catch(error){const warning=document.createElement('section');warning.className='warning';const strong=document.createElement('strong');strong.textContent='Security telemetry is temporarily unavailable.';const detail=document.createElement('span');detail.textContent=error.message;warning.append(strong,detail);securityContent.replaceChildren(warning)}
    finally{securityContent.removeAttribute('aria-busy')}
  };
  document.addEventListener('click',event=>{
    const link=event.target.closest('[data-security-nav]');if(!link)return;
    event.preventDefault();
    loadSecurity(link.dataset.view||securityContent.dataset.view,link.dataset.window||securityContent.dataset.window);
  });
  window.addEventListener('popstate',()=>{
    if(location.pathname.startsWith('/security/vulnerabilities')&&openVulns(location.pathname,{history:false}))return;
    const query=new URLSearchParams(location.search);loadSecurity(query.get('view')||'edge',query.get('window')||'today',{history:false});
  });
  initSecurityChart(securityContent);
}

// Sub-tabs (Clusters, Home network): every tab is a real link to its own URL,
// so this only switches panes in place and keeps the address bar in sync. It
// never builds markup; it toggles `hidden` and ARIA state on server-rendered panes.
(()=>{
  const nav=document.querySelector('[data-subtabs]');if(!nav)return;
  const tabs=[...nav.querySelectorAll('[role="tab"]')];
  const pathOf=link=>new URL(link.getAttribute('href'),location.origin).pathname;
  const byPath=new Map(tabs.map(tab=>[pathOf(tab),tab]));
  const show=tab=>{
    tabs.forEach(item=>{
      const on=item===tab,pane=document.getElementById(item.getAttribute('aria-controls'));
      item.classList.toggle('active',on);item.setAttribute('aria-selected',on?'true':'false');item.tabIndex=on?0:-1;
      if(pane)pane.hidden=!on;
    });
    if(tab.dataset.title)document.title=tab.dataset.title;
  };
  const open=(tab,push)=>{
    show(tab);
    const path=pathOf(tab);
    if(push&&(location.pathname!==path||location.search))history.pushState({subtab:path},'',path);
  };
  document.addEventListener('click',event=>{
    const link=event.target.closest('a[href]');
    if(!link||event.defaultPrevented||event.button!==0||event.metaKey||event.ctrlKey||event.shiftKey||event.altKey||link.target)return;
    const url=new URL(link.href,location.href);
    // Only plain same-origin links to a tab of this page; anything with a
    // query (e.g. a PS5 report date) or another path is a normal navigation.
    if(url.origin!==location.origin||url.search||url.hash)return;
    const tab=byPath.get(url.pathname);if(!tab)return;
    event.preventDefault();open(tab,true);
    if(link!==tab)nav.scrollIntoView({block:'start'});
  });
  nav.addEventListener('keydown',event=>{
    const index=tabs.indexOf(document.activeElement);if(index<0)return;
    const next={ArrowRight:tabs[(index+1)%tabs.length],ArrowLeft:tabs[(index-1+tabs.length)%tabs.length],
                Home:tabs[0],End:tabs[tabs.length-1]}[event.key];
    if(!next)return;
    event.preventDefault();open(next,true);next.focus();
  });
  window.addEventListener('popstate',()=>{const tab=byPath.get(location.pathname);if(tab)show(tab)});
})();

// New build: make the selected distribution the visual and functional context.
// The server still owns validation; this layer removes irrelevant choices and
// prevents platform-bundled services from being submitted as optional add-ons.
(()=>{
  const select=document.querySelector('[data-build-profile]');if(!select)return;
  const form=select.closest('form');
  const choices=[...form.querySelectorAll('[data-platform-choice]')];
  const details=form.querySelector('[data-build-details]');
  const storage=form.querySelector('[data-build-storage]');
  const monitoring=form.querySelector('input[name="monitoring"]');
  const metrics=form.querySelector('input[name="metrics_server"]');
  const versionFields=[...form.querySelectorAll('[data-version-component]')];
  const platformCopy={
    kubernetes:{logo:'kubernetes',alt:'Kubernetes logo',kicker:'Vanilla Kubernetes',title:'Build a Kubernetes cluster',badge:'kubeadm',summary:'Flexible kubeadm foundation with Factory-managed GitOps and optional observability.',topology:'Choose 1, 3 or 5 control planes and 1–6 workers.',services:'Argo CD, Traefik, cert-manager and storage are installed by the Factory.'},
    rke2:{logo:'rancher',alt:'Rancher logo',kicker:'Rancher / RKE2',title:'Build a Rancher cluster',badge:'RKE2',summary:'A hardened RKE2 foundation with Rancher Manager and GitOps.',topology:'Choose 1, 3 or 5 RKE2 server nodes and 3–6 workers.',services:'RKE2 includes Kubernetes and Metrics Server. The Factory adds Rancher Manager, Argo CD, ingress, certificates and storage.'},
    openshift:{logo:'openshift',alt:'Red Hat OpenShift logo',kicker:'Red Hat OpenShift',title:'Build an OpenShift cluster',badge:'OCP',summary:'An opinionated OpenShift platform using its native GitOps and monitoring operators.',topology:'Choose 3 control planes and 2–6 workers, or the compact 1-control-plane/2-worker shape.',services:'OpenShift GitOps, cluster monitoring, ingress and core platform services are supplied by OpenShift.'}
  };
  let previousPlatform='';let storedStorage='nfs';
  const assetVersion=encodeURIComponent(form.dataset.assetVersion||'dev');
  const check=(name,value)=>{const input=form.querySelector(`input[name="${name}"][value="${value}"]`);if(input)input.checked=true};
  const availability=(input,available)=>{input.disabled=!available;input.closest('.choice-box')?.classList.toggle('unavailable',!available)};
  const filterProfiles=platform=>{
    const matching=[...select.options].filter(option=>option.dataset.platform===platform);
    [...select.options].forEach(option=>{const visible=option.dataset.platform===platform;option.hidden=!visible;option.disabled=!visible});
    if(!matching.some(option=>option.selected)&&matching[0])select.value=matching[0].value;
  };
  const updateTopology=(platform,platformChanged=false)=>{
    const cp=[...form.querySelectorAll('input[name="control_planes"]')];
    const workers=[...form.querySelectorAll('input[name="workers"]')];
    cp.forEach(input=>availability(input,platform!=='openshift'||input.value!=='5'));
    if(platformChanged){check('control_planes',platform==='openshift'?'3':'1');check('workers','3')}
    const selectedCp=Number(form.querySelector('input[name="control_planes"]:checked')?.value||1);
    workers.forEach(input=>{
      const count=Number(input.value);
      const available=platform==='rke2'?count>=3:platform==='openshift'?(selectedCp===1?count===2:count>=2):true;
      availability(input,available);
    });
    const current=form.querySelector('input[name="workers"]:checked');
    if(!current||current.disabled)check('workers',platform==='openshift'&&selectedCp===1?'2':'3');
  };
  const updateVersions=(platform)=>{
    const selectedStorage=storage?.value||'nfs';
    const visible=new Set(platform==='openshift'?['openshift']:
      platform==='rke2'?['rke2','rancher_chart','argocd_chart']:
      ['kubernetes','containerd','calico','argocd_chart','metallb_chart','traefik_chart','cert_manager_chart']);
    if(platform!=='openshift'){
      if(selectedStorage==='nfs'||selectedStorage==='both')visible.add('nfs_provisioner_chart');
      if(selectedStorage==='ceph'||selectedStorage==='both')visible.add('ceph_csi');
      if(platform==='kubernetes'&&metrics?.checked)visible.add('metrics_server_chart');
      if(monitoring?.checked)visible.add('kube_prometheus_stack_chart');
    }
    versionFields.forEach(field=>{field.hidden=!visible.has(field.dataset.versionComponent)});
  };
  const update=platform=>{
    if(!platform){details.hidden=true;document.body.removeAttribute('data-build-platform');return}
    const openshift=platform==='openshift';
    const rancher=platform==='rke2';
    const platformChanged=Boolean(previousPlatform&&previousPlatform!==platform);
    const copy=platformCopy[platform];
    document.body.dataset.buildPlatform=platform;
    form.dataset.platformTheme=platform;
    form.querySelectorAll('[data-openshift-only]').forEach(item=>{item.hidden=!openshift});
    form.querySelectorAll('[data-rancher-only]').forEach(item=>{item.hidden=!rancher});
    const logo=form.querySelector('[data-platform-logo]');
    if(logo){logo.src=`/static/platform-${copy.logo}.svg?v=${assetVersion}`;logo.alt=copy.alt}
    ['kicker','title','summary','badge'].forEach(key=>{const target=form.querySelector(`[data-platform-${key}]`);if(target)target.textContent=copy[key]});
    const guidance=form.querySelector('[data-topology-guidance]');if(guidance)guidance.textContent=copy.topology;
    const servicesTitle=form.querySelector('[data-included-title]');if(servicesTitle)servicesTitle.textContent=`Included with ${copy.kicker}`;
    const servicesCopy=form.querySelector('[data-included-copy]');if(servicesCopy)servicesCopy.textContent=copy.services;
    const storageControl=form.querySelector('[data-storage-control]');if(storageControl)storageControl.hidden=openshift;
    if(storage){
      if(openshift){if(previousPlatform!=='openshift')storedStorage=storage.value;storage.value='ceph'}
      else if(previousPlatform==='openshift')storage.value=storedStorage;
    }
    if(metrics){metrics.disabled=platform!=='kubernetes';if(metrics.disabled)metrics.checked=false;else if(platformChanged)metrics.checked=true}
    if(monitoring){monitoring.disabled=openshift;if(openshift)monitoring.checked=false}
    form.querySelector('[data-addon="metrics-server"]')?.toggleAttribute('hidden',platform!=='kubernetes');
    form.querySelector('[data-addon="monitoring"]')?.toggleAttribute('hidden',openshift);
    updateTopology(platform,platformChanged);
    updateVersions(platform);
    previousPlatform=platform;
  };
  const selectedPlatform=()=>choices.find(choice=>choice.checked)?.value||'';
  const revealDetails=()=>{
    const reducedMotion=window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    details.hidden=false;
    if(reducedMotion)return;
    details.animate([
      {opacity:0,transform:'translateY(-18px)'},
      {opacity:1,transform:'translateY(0)'}
    ],{duration:420,easing:'cubic-bezier(.22,1,.36,1)'});
    requestAnimationFrame(()=>requestAnimationFrame(()=>{
      const comfortableTop=window.innerHeight*.58;
      const nudge=Math.min(150,Math.max(0,details.getBoundingClientRect().top-comfortableTop));
      if(nudge)window.scrollBy({top:nudge,behavior:'smooth'});
    }));
  };
  const choose=platform=>{
    if(!platform)return;
    const firstSelection=details.hidden;
    filterProfiles(platform);update(platform);
    if(firstSelection)revealDetails();
  };
  choices.forEach(choice=>choice.addEventListener('change',()=>choose(choice.value)));
  select.addEventListener('change',()=>update(selectedPlatform()||select.selectedOptions[0]?.dataset.platform));
  form.querySelectorAll('input[name="control_planes"]').forEach(input=>input.addEventListener('change',()=>updateTopology(selectedPlatform())));
  storage?.addEventListener('change',()=>updateVersions(selectedPlatform()));
  monitoring?.addEventListener('change',()=>updateVersions(selectedPlatform()));
  metrics?.addEventListener('change',()=>updateVersions(selectedPlatform()));
  const initial=selectedPlatform();if(initial)choose(initial);else update('');
})();
