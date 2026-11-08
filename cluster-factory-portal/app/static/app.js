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
