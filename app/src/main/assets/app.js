'use strict';
const $=s=>document.querySelector(s);
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const paths={Dashboard:'M3 11 12 3l9 8v10h-6v-7H9v7H3z',Library:'M3 4h5v16H3z M11 4h4v16h-4z M17 5l3-1 3 15-3 1z',Performance:'M2 13h5l3-8 4 15 3-9 2 2h3',Graphics:'M3 4h18v13H3z M8 21h8 M12 17v4',Controller:'M7 7h10c3 0 4 3 5 10 0 3-3 4-5 1l-2-2H9l-2 2c-2 3-5 2-5-1 1-7 2-10 5-10z M6 11v4 M4 13h4 M16 12h.1 M19 14h.1',Settings:'M4 6h7m4 0h5 M4 12h2m4 0h10 M4 18h10m4 0h2 M11 3v6 M7 9v6 M15 15v6',Diagnostics:'M3 4h18v16H3z M6 9l3 3-3 3m5 0h6',About:'M12 2a10 10 0 1 0 .01 0 M12 10v7m0-11v1',Play:'m8 4 12 8-12 8z',Import:'M12 3v12m-5-5 5 5 5-5 M4 16v5h16v-5',Star:'m12 2 3 6 7 1-5 5 1 7-6-3-6 3 1-7-5-5 7-1z',Details:'M5 4h14v16H5z M8 8h8m-8 4h8m-8 4h5',Clock:'M12 2a10 10 0 1 0 .01 0 M12 6v6l4 2'};
const icon=k=>'<svg class="glyph" viewBox="0 0 24 24" aria-hidden="true"><path d="'+paths[k]+'"/></svg>';
const action=(label,key,cls='',extra='')=>'<button class="'+cls+'" data-act="'+key+'" '+extra+'>'+label+'</button>';
const pageButton=(page,label=page,cls='quick')=>'<button class="'+cls+'" data-page="'+page+'">'+icon(page)+' '+esc(label)+'</button>';
const stamp=n=>new Date(n).toLocaleString();
const bytes=n=>n>=1048576?(n/1048576).toFixed(1)+' MiB':(n/1024).toFixed(1)+' KiB';
const gib=n=>(n/1073741824).toFixed(1);
const base=JSON.parse(Genesis.snapshot());
function readPreferences(){try{return JSON.parse(localStorage.getItem('preferences')||'{}')||{};}catch(error){return {};}}
let prefs=Object.assign({theme:'teal',motion:true,haptic:true,large:false,compact:base.compact,view:'grid',favorites:[],budget:100000,sort:'name',mapping:{}},readPreferences());
let data=base, metrics=JSON.parse(Genesis.metrics()), page='Dashboard', selected='doors',filter='all',query='',busy=false,bind='',lastKey='',timer;
const historyStack=[];
const main=$('#main'),dialog=$('#modal');
const pages=['Dashboard','Library','Performance','Graphics','Controller','Settings','Diagnostics','About'];
function save(){localStorage.setItem('preferences',JSON.stringify(prefs));apply();}
function apply(){
 document.documentElement.dataset.theme=prefs.theme;
 document.body.classList.toggle('animate',prefs.motion);
 document.body.classList.toggle('large',prefs.large);
 document.body.classList.toggle('compact',prefs.compact);
}
function game(){return data.games.find(g=>g.id===selected)||data.games[0];}
function recent(id){return data.logs.find(l=>l.label===id);}
function status(g){if(g.id==='doors')return 'Playable homebrew';let l=recent(g.id);return !l?'Loadable · untested':l.text.includes('Guest breakpoint')?'Reached breakpoint':'Execution stopped';}
function artStyle(g){return g.art?' style="background-image:linear-gradient(90deg,#07111699,transparent),url(art/'+encodeURIComponent(g.id)+'?v='+Number(g.art)+')"':'';}
function row(k,v){return '<div class="stat"><span>'+esc(k)+'</span><b>'+esc(v)+'</b></div>';}
function panel(title,html){return '<section class="panel"><h2>'+esc(title)+'</h2>'+html+'</section>';}
function nav(){
 $('#nav').innerHTML=pages.map((p,i)=>(i===0?'<span class="group">WORKSPACE</span>':i===2?'<span class="group">SYSTEM</span>':'')+
 '<button aria-label="'+p+'" data-page="'+p+'" class="'+((page===p||(page==='Details'&&p==='Library'))?'active':'')+'">'+icon(p)+'<span class="label">'+(p==='Library'?'Game library':p)+'</span></button>').join('');
 $('#engine').textContent=data.diag.includes('PASS')?'ONLINE':data.diag.includes('FAIL')?'FAULT':'PROBING';
}
function jump(p,push=true){
 if(!pages.includes(p)&&p!=='Details')return;
 if(push&&p!==page)historyStack.push({page,selected});
 page=p;bind='';render();main.scrollTop=0;main.focus({preventScroll:true});
}
function details(id){if(page!=='Details')historyStack.push({page,selected});selected=id;jump('Details',false);}
function goBack(){
 if(dialog.open){if(!busy)dialog.close();return true;}
 if(bind){bind='';render();return true;}
 const prev=historyStack.pop();if(prev){selected=prev.selected;jump(prev.page,false);return true;}
 if(page!=='Dashboard'){jump('Dashboard',false);return true;}return false;
}
function card(g){
 return '<button class="tile" data-detail="'+g.id+'"><div class="art"'+artStyle(g)+'></div><div class="caption"><b>'+esc(g.name)+'</b><small>'+esc(status(g))+'</small></div></button>';
}
function telemetry(){
 let pct=metrics.total?Math.round((metrics.total-metrics.avail)*100/metrics.total):0;
 return '<div class="kicker">HOST TELEMETRY</div><h2>System monitor</h2><strong>'+gib(metrics.avail)+' <small>GiB free</small></strong><div class="meter"><div style="width:'+pct+'%"></div></div>'+
 row('Process CPU',metrics.cpu<0?'Sampling…':metrics.cpu+'%')+row('Thermal',metrics.thermal)+row('Host cores',metrics.cores);
}
function dashboard(){
 let g=data.games[0],logs=data.logs.filter(l=>data.games.some(g=>g.id===l.label));
 let recentIds=[...new Set(logs.map(l=>l.label))].slice(0,3);
 return '<div class="dashboard"><section class="hero"'+artStyle(g)+'><span class="kicker">FEATURED HOMEBREW</span><h2>Alien Doors</h2><p>Three vaults. One hidden visitor.</p><div class="actions">'+action(icon('Play')+' Play','play','primary','data-id="doors"')+action('Details','featured','soft')+'</div></section><section class="panel tele" id="tele">'+telemetry()+'</section></div>'+
 '<section class="lower"><div class="section-title"><h2>Game library <small>'+data.games.length+'</small></h2>'+action('View library →','library','link')+'</div><div class="games">'+data.games.slice(0,4).map(card).join('')+
 '<button class="empty" data-act="import">'+icon('Import')+' Import homebrew</button></div></section>'+
 '<div class="shortcuts">'+['Graphics','Controller','Diagnostics'].map(p=>pageButton(p)).join('')+'</div>'+
 panel('Recent activity',recentIds.length?recentIds.map(id=>action(esc(data.games.find(g=>g.id===id).name)+' · '+esc(stamp(recent(id).time)),'recent','soft','data-id="'+id+'"')).join(' '):'<p>Run homebrew to see your recent sessions.</p>');
}
function options(values,current){return values.map(([v,label])=>'<option value="'+v+'" '+(String(current)===String(v)?'selected':'')+'>'+label+'</option>').join('');}
function filtered(){
 let list=data.games.filter(g=>g.name.toLowerCase().includes(query.toLowerCase())&&(filter==='all'||(filter==='fav'?prefs.favorites.includes(g.id):g.id!=='doors')));
 list.sort((a,b)=>prefs.sort==='recent'?(recent(b.id)?.time||0)-(recent(a.id)?.time||0):prefs.sort==='added'?b.added-a.added:a.name.localeCompare(b.name));
 return list.length?list.map(card).join(''):'<p class="empty">No matching homebrew.</p>';
}
function library(){return '<div class="filters"><input id="search" type="search" aria-label="Search library" placeholder="Search library" value="'+esc(query)+'"><select id="filter" aria-label="Filter">'+options([['all','All titles'],['fav','Favorites'],['imports','Imported']],filter)+'</select><select id="sort" aria-label="Sort">'+options([['name','Title A–Z'],['recent','Recently played'],['added','Newest imports']],prefs.sort)+'</select>'+action(prefs.view==='grid'?'List view':'Grid view','view')+action('+ Import','import','primary')+'</div><div id="games" class="games '+prefs.view+'">'+filtered()+'</div>';}
function info(){
 let g=game(),r=recent(g.id);
 return '<section class="hero details"'+artStyle(g)+'><span class="kicker">'+(g.id==='doors'?'BUNDLED HOMEBREW':'IMPORTED HOMEBREW')+'</span><h2>'+esc(g.name)+'</h2><div class="actions">'+action(icon('Play')+' Launch','play','primary','data-id="'+g.id+'"')+action(icon('Star')+' '+(prefs.favorites.includes(g.id)?'Favorited':'Favorite'),'favorite','soft')+action('Set artwork','art','soft')+'</div></section><div class="columns">'+panel('File information',row('Format','AMD64 PE32+')+row('File size',bytes(g.size))+row('Compatibility',status(g))+row('Source',g.id==='doors'?'Bundled asset':'Private app copy')+(g.added?row('Imported',stamp(g.added)):''))+panel('Last execution',r?'<small>'+esc(stamp(r.time))+'</small><pre>'+esc(r.text)+'</pre>':'<p>No recorded launch.</p>')+'</div>';
}
function selectSetting(key,label,values){return '<label class="setting"><span>'+label+'</span><select data-pref="'+key+'">'+options(values,prefs[key])+'</select></label>';}
function toggle(key,label){return '<div class="setting"><span>'+label+'</span>'+action(prefs[key]?'Enabled':'Disabled','toggle','','data-key="'+key+'" aria-label="'+label+'" aria-pressed="'+!!prefs[key]+'"')+'</div>';}
function perf(){return '<div class="columns">'+panel('Host resources', '<div id="resources">'+resourceRows()+'</div>')+panel('Runtime',row('Device',data.device)+row('OS','Android '+data.android)+row('Architecture',data.abi)+row('Guest frame rate','Unavailable')+'<p>Process CPU is sampled across available cores. Execution time is recorded per launch in Diagnostics.</p>')+'</div>';}
function resourceRows(){return row('Available RAM',gib(metrics.avail)+' GiB')+row('Physical RAM',gib(metrics.total)+' GiB')+row('Java heap used',bytes(metrics.heap))+row('Available cores',metrics.cores)+row('Process CPU',metrics.cpu<0?'Sampling…':metrics.cpu+'%')+row('Thermal status',metrics.thermal);}
function graphics(){return '<div class="columns">'+panel('Vulkan device', '<pre>'+esc(data.diag.split('\n').filter(l=>/Vulkan|GPU:|extension/i.test(l)).join('\n')||data.diag)+'</pre>'+action('Refresh probe','probe'))+panel('Display',toggle('motion','Dashboard transitions')+row('Guest GPU renderer','Unavailable')+'<p>Resolution scaling and shader compilation require a guest graphics backend.</p>')+'</div>';}
function controllers(){return '<div class="columns">'+panel('Connected controllers','<div id="pads">'+esc(metrics.pads.join(', ')||'No Android gamepad detected')+'</div><p>Press a controller button to test it.</p><pre id="padkey">'+esc(lastKey||'Waiting for input…')+'</pre>')+panel('Dashboard mapping',['Confirm','Back'].map(a=>'<div class="setting"><span>'+a+'</span>'+action(bind===a?'Press a button…':esc(prefs.mapping[a]||(a==='Confirm'?'BUTTON_A':'BUTTON_B')),'bind','','data-key="'+a+'"')+'</div>').join('')+action('Reset mappings','resetMap')+'<p>D-pad moves focus. Mapping applies to the dashboard and door choices.</p>')+'</div>';}
function settings(){return '<div class="columns">'+panel('Appearance',selectSetting('theme','Visual theme',[['teal','Alien Teal'],['violet','Cyber Violet'],['gold','Obsidian Gold']])+toggle('compact','Compact spacing')+toggle('large','Larger controls')+toggle('motion','Animated transitions'))+panel('Execution & storage',toggle('haptic','Touch feedback')+selectSetting('budget','Instruction limit',[[1000,'1,000'],[10000,'10,000'],[100000,'100,000']])+row('Private game files',bytes(data.games.filter(g=>g.id!=='doors').reduce((n,g)=>n+g.size,0)))+action('Import executable','import'))+'</div>';}
function diagnostics(){return '<div class="columns">'+panel('Native diagnostics','<pre>'+esc(data.diag)+'</pre>'+action('Refresh probe','probe')+' '+action('Export JSON','export'))+panel('Execution log',data.logs.length?data.logs.map(l=>'<details><summary>'+esc(data.games.find(g=>g.id===l.label)?.name||l.label)+' · '+esc(stamp(l.time))+'</summary><pre>'+esc(l.text)+'</pre></details>').join(''):'<p>No launches or errors recorded.</p>')+'</div>';}
function about(){return '<div class="columns">'+panel('Project Genesis',row('Version','0.3.0 / build 4')+row('Edition','Alien Teal Ultimate')+row('Build','Android debug · '+data.abi)+row('Implemented','Alien Doors homebrew')+row('Experimental','AMD64 PE32+ interpreter')+row('Planned','Guest memory and stack')+row('Unavailable','Xbox Series X|S retail titles'))+panel('Licenses & credits','<p>Genesis uses the Android platform WebView, NDK C++ runtime and Vulkan system loader. The bundled Alien Doors assembly and interface are project assets. No third-party emulator engine is bundled.</p><p>Xbox is a Microsoft trademark. ALIEN XBOX is an independent research project.</p>'+action('Runtime notices','licenses'))+'</div>';}
const screens={Dashboard:dashboard,Library:library,Details:info,Performance:perf,Graphics:graphics,Controller:controllers,Settings:settings,Diagnostics:diagnostics,About:about};
function render(){
 nav();main.innerHTML='<div class="heading"><h1>'+esc(page==='Dashboard'?'Command center':page==='Library'?'Game library':page==='Details'?'Game details':page)+'</h1><span class="meta">'+(page==='Dashboard'?'GENESIS / DASHBOARD': 'PROJECT GENESIS')+'</span></div>'+screens[page]();
}
function showModal(html){
 $('#dialogbody').innerHTML=html;$('#closeModal').disabled=busy;
 if(!dialog.open)dialog.showModal();
}
function launch(id){
 if(busy)return;
 if(id==='doors'){showModal('<div class="kicker">ALIEN DOORS</div><h2>Choose a vault</h2><p>One door hides the alien.</p><div class="actions">'+[1,2,3].map(n=>action('Door '+n,'door','primary','data-num="'+n+'"')).join('')+'</div>');}
 else run(id,0);
}
function run(id,n){busy=true;showModal('<div class="loading">Executing guest program…</div>');Genesis.run(id,n,prefs.budget);}
function toast(t){$('#toast').textContent=t;$('#toast').className='show';clearTimeout(timer);timer=setTimeout(()=>$('#toast').className='',2200);}
function focusMove(dir){
 let list=[...(dialog.open?dialog:document).querySelectorAll('button:not(:disabled),input,select,summary')].filter(b=>b.offsetWidth);
 let active=document.activeElement,center=b=>{let r=b.getBoundingClientRect();return [r.x+r.width/2,r.y+r.height/2];};
 if(!list.includes(active)){list[0]?.focus();return;}
 let [x,y]=center(active),best=null,score=Infinity;
 for(let b of list){let [dx,dy]=center(b);dx-=x;dy-=y;let forward={LEFT:-dx,RIGHT:dx,UP:-dy,DOWN:dy}[dir],side=/LEFT|RIGHT/.test(dir)?Math.abs(dy):Math.abs(dx);
 if(forward>2&&forward+side*3<score){score=forward+side*3;best=b;}}
 best?.focus();
}
function receive(kind,value){
 if(kind==='pad'){
  lastKey=value.replace('KEYCODE_','');if($('#padkey'))$('#padkey').textContent=lastKey;
  if(lastKey.startsWith('DPAD_')){focusMove(lastKey.slice(5));return;}
  if(bind){let other=bind==='Confirm'?'Back':'Confirm';if(lastKey===(prefs.mapping[other]||(other==='Confirm'?'BUTTON_A':'BUTTON_B'))){toast('Choose a different button');return;}prefs.mapping[bind]=lastKey;bind='';save();render();return;}
  if(lastKey===(prefs.mapping.Confirm||'BUTTON_A'))document.activeElement?.click();
  if(lastKey===(prefs.mapping.Back||'BUTTON_B'))goBack();return;
 }
 data=JSON.parse(Genesis.snapshot());
 if(kind==='result'||kind==='error'){busy=false;showModal('<h2>'+(kind==='error'?'Document or execution error':'Execution result')+'</h2><pre>'+esc(value)+'</pre>');}
 if(kind==='updated'&&value)toast(value);render();
}
document.addEventListener('click',e=>{
 let b=e.target.closest('button');if(!b)return;if(prefs.haptic)Genesis.haptic();
 if(b.dataset.page)return jump(b.dataset.page);
 if(b.dataset.detail)return details(b.dataset.detail);
 switch(b.dataset.act){
 case 'library':jump('Library');break;case 'featured':details('doors');break;
 case 'recent':details(b.dataset.id);break;case 'play':launch(b.dataset.id);break;
 case 'door':run('doors',Number(b.dataset.num));break;
 case 'import':Genesis.pick('game','');break;case 'art':Genesis.pick('art',selected);break;
 case 'favorite':prefs.favorites=prefs.favorites.includes(selected)?prefs.favorites.filter(x=>x!==selected):[...prefs.favorites,selected];save();render();break;
 case 'view':prefs.view=prefs.view==='grid'?'list':'grid';save();render();break;
 case 'probe':Genesis.probe();break;case 'export':Genesis.exportReport();break;
 case 'toggle':prefs[b.dataset.key]=!prefs[b.dataset.key];save();render();break;
 case 'bind':bind=b.dataset.key;render();break;case 'resetMap':prefs.mapping={};bind='';save();render();break;
 case 'licenses':showModal('<h2>Runtime notices</h2><pre id="notice">Loading…</pre>');$('#notice').textContent=Genesis.notices();break;
 }
});
document.addEventListener('change',e=>{let t=e.target;if(t.dataset.pref){prefs[t.dataset.pref]=t.dataset.pref==='budget'?Number(t.value):t.value;save();render();}
 if(t.id==='sort'){prefs.sort=t.value;save();$('#games').innerHTML=filtered();}if(t.id==='filter'){filter=t.value;$('#games').innerHTML=filtered();}});
document.addEventListener('input',e=>{if(e.target.id==='search'){query=e.target.value;$('#games').innerHTML=filtered();}});
document.addEventListener('keydown',e=>{if(e.key.startsWith('Arrow')&&!['SELECT','INPUT'].includes(e.target.tagName)){e.preventDefault();focusMove(e.key.slice(5).toUpperCase());}});
dialog.addEventListener('cancel',e=>{if(busy)e.preventDefault();});
$('#closeModal').onclick=()=>dialog.close();
$('#gear').innerHTML=icon('Settings');
apply();render();
setInterval(()=>{if(document.hidden||!['Controller','Dashboard','Performance'].includes(page))return;
 metrics=JSON.parse(Genesis.metrics());if($('#tele'))$('#tele').innerHTML=telemetry();
 if($('#resources'))$('#resources').innerHTML=resourceRows();
 if($('#pads'))$('#pads').textContent=metrics.pads.join(', ')||'No Android gamepad detected';
},2500);
