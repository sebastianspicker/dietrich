import {createBrowser} from './browser.js';
import {countLabels,inspectionMetadata,isWindowsPath,joinPath,optionsFrom,outputDefault,phaseSteps,protectionChoices,splitPath,technicalEntries} from './model.js';
const $ = selector=>document.querySelector(selector);
const fragment = location.hash.slice(1);
const token = fragment.startsWith('token=')?new URLSearchParams(fragment).get('token'):fragment;
const state = {screen:'choose',inspection:null,source:'',output:'',operation:null,dependencies:{},home:'',browsePath:'',recent:[],polling:false};
async function api(action,body={}) {
  const response=await fetch(`/api/${action}`,{method:'POST',headers:{'Content-Type':'application/json','X-Dietrich-Token':token||''},body:JSON.stringify(body),cache:'no-store'});
  let value;
  try {value=await response.json();} catch {throw new Error('The local application returned an unexpected response. Open the address printed by dietrich-gui.');}
  if(!response.ok){const error=new Error(value.error||`Local request failed (${response.status}).`);error.status=response.status;throw error;}
  return value;
}
const browse=createBrowser(api);
function announce(message){$('#announcement').textContent=message;}
function showError(reason){$('#error').textContent=typeof reason==='string'?reason:reason.message;$('#error').hidden=false;$('#error').focus();}
function clearError(){$('#error').hidden=true;$('#error').textContent='';}
function screen(name,focus=true){
  state.screen=name;
  for(const id of ['choose','review','processing','result'])$(`#${id}`).hidden=id!==name;
  const step=name==='processing'?(state.operation?.kind==='inspect'?'choose':'review'):name;
  const index=['choose','review','result'].indexOf(step);
  document.querySelectorAll('[data-step]').forEach((node,i)=>{node.classList.toggle('active',i===index);node.classList.toggle('complete',i<index);if(i===index)node.setAttribute('aria-current','step');else node.removeAttribute('aria-current');node.querySelector('span').textContent=i<index?'✓':String(i+1);});
  if(focus)$(`#${name}-title`).focus();
}
function addText(parent,tag,value,className=''){
  const node=document.createElement(tag);node.textContent=value;if(className)node.className=className;parent.append(node);return node;
}
function renderRecent(){
  const list=$('#recent-list');list.replaceChildren();$('#recent').hidden=!state.recent.length;
  for(const path of state.recent){const item=document.createElement('li'),button=addText(item,'button',path);button.type='button';button.addEventListener('click',()=>inspect(path));list.append(item);}
}
function reset(){
  state.inspection=null;state.source='';state.output='';state.operation=null;
  $('#create-form').reset();$('#source-path').value='';$('#hash-output').value='';$('#hash-output').hidden=true;$('#hash-label').hidden=true;
  document.querySelectorAll('#review details').forEach(node=>node.open=false);
  clearError();screen('choose');
}
function renderFindings(inspection){
  const container=$('#findings');container.replaceChildren();const dl=document.createElement('dl');
  for(const [label,value] of technicalEntries(inspection,state.dependencies)){addText(dl,'dt',label);addText(dl,'dd',value);}container.append(dl);
  for(const [label,values] of [
    ['Detected package parts',(inspection.soft_protections||[]).map(part=>`${part.path} · ${part.kind} · ${part.count}`)],
    ['Capabilities',(inspection.capabilities||[]).map(item=>`${item.code}: ${item.detail}`)],
    ['Blockers',(inspection.blockers||[]).map(item=>`${item.code}: ${item.detail}`)],
    ['Notes',inspection.notes||[]],['Strategies',inspection.strategies||[]],
  ]){if(!values.length)continue;addText(container,'h3',label);const list=document.createElement('ul');for(const value of values)addText(list,'li',value);container.append(list);}
}
function renderInspection(inspection){
  state.inspection=inspection;state.source=inspection.input_path;state.browsePath=state.source;
  $('#file-type').textContent=({excel_ooxml:'X',word_ooxml:'W',powerpoint_ooxml:'P',pdf:'P'})[inspection.document_format]||'D';
  $('#file-name').textContent=splitPath(state.source).name;$('#file-meta').textContent=inspectionMetadata(inspection);$('#file-path').textContent=state.source;
  const output=outputDefault(state.source);$('#output-name').value=output.name;$('#output-folder').value=output.folder;
  const options=$('#protection-options');options.replaceChildren();
  const choices=protectionChoices(inspection);
  for(const choice of choices){
    const label=document.createElement('label');label.className='check';const input=document.createElement('input');input.type='checkbox';input.name=choice.key;input.checked=true;
    if(choice.fixed){input.disabled=true;const fixed=document.createElement('input');fixed.type='hidden';fixed.name=choice.key;fixed.value='on';label.append(fixed);}
    const text=document.createElement('span');text.textContent=choice.label;
    addText(text,'small',choice.detail||(choice.count===null?'Apply if detected after decryption.':`${choice.count} protection ${choice.count===1?'element':'elements'} detected`));
    label.append(input,text);options.append(label);
  }
  const legacy=inspection.document_format==='legacy_cfbf'&&!inspection.encrypted;
  $('#empty-findings').hidden=choices.length>0;
  $('#empty-findings').textContent=legacy?'Legacy Office copying applies all supported binary protection changes together; category selection is unavailable.':'No supported editing restrictions detected. A copy may contain no changes.';
  $('#password-section').hidden=!(inspection.encrypted||inspection.user_password_required);
  $('#signature-option').hidden=!(inspection.signed||inspection.document_format==='encrypted_ooxml');$('#vba-option').hidden=!(inspection.vba_project_present||inspection.document_format==='encrypted_ooxml');
  if(inspection.signed){$('#signature-option').closest('details').open=true;}
  const blockers=inspection.blockers||[];$('#blockers').hidden=!blockers.length;$('#blockers').textContent=blockers.map(item=>item.detail).join(' ');
  $('#create').disabled=!!blockers.length;
  $('#export-hash').disabled=!!blockers.length||!(inspection.capabilities||[]).some(item=>item.code==='export_password_hash');
  const required=[];
  if(inspection.document_format==='pdf')required.push('pdf');
  if(inspection.document_format==='encrypted_ooxml'||(inspection.document_format==='legacy_cfbf'&&inspection.encrypted))required.push('crypto');
  if(inspection.document_format==='legacy_cfbf')required.push('legacy');
  const missing=required.filter(key=>state.dependencies[key]===false);
  $('#dependency-note').hidden=!missing.length;$('#dependency-note').textContent=`Unavailable local components: ${missing.join(', ')}. Install the corresponding Dietrich extras before creating this copy.`;
  if(missing.length)$('#create').disabled=true;
  renderFindings(inspection);screen('review');
}
async function inspect(path){
  if(state.operation)return;
  if(!path.trim())return;
  $('#create-form').reset();$('#hash-output').hidden=true;$('#hash-label').hidden=true;$('#hash-output').value='';
  state.inspection=null;state.source=path;state.output='';
  state.recent=[path,...state.recent.filter(value=>value!==path)].slice(0,12);renderRecent();
  await start('inspect',{path});
}
function renderOperation(operation){
  state.operation=operation;
  const kind=operation.kind;
  $('#processing-title').textContent=kind==='inspect'?'Checking your document':kind==='export'?'Preparing recovery material':'Checking the working copy';
  $('#processing-subtitle').textContent=kind==='create'?'The output is available only after validation and saving.':kind==='inspect'?'Reading the document’s protection features.':'Exporting a hash for your local recovery tools.';
  $('#processing-source').textContent=operation.path||state.source;
  $('#processing-output').textContent=operation.output||state.output;
  $('#processing-output').hidden=kind!=='create';$('#processing-output-label').hidden=kind!=='create';
  const phase=operation.phase||'starting';const phaseLabel=phase==='publishing'?'Saving working copy':phase;
  if($('#phase').textContent!==phaseLabel)$('#phase').textContent=phaseLabel;
  $('#cancel').disabled=!operation.cancellable||phase==='cancelling';$('#cancel').textContent=phase==='cancelling'?'Cancelling…':'Cancel';
  $('#phase-help').textContent=phase==='publishing'?'Saving has begun. Cancellation is no longer available.':phase==='cancelling'?'Waiting for the current operation and cleanup to finish.':'Dietrich reports the current phase; no time estimate is available.';
  $('#phase-steps').hidden=kind!=='create';
  const stage=phaseSteps(phase);
  document.querySelectorAll('#phase-steps li').forEach((node,index)=>{node.classList.toggle('done',index<stage);node.classList.toggle('current',index===stage);node.querySelector('span').textContent=index<stage?'✓':index===stage?'▪':'□';});
}
function newRequestId(){
  if(typeof crypto.randomUUID==='function')return crypto.randomUUID();
  return Array.from(crypto.getRandomValues(new Uint8Array(16)),byte=>byte.toString(16).padStart(2,'0')).join('');
}
function unavailableOutcome(message){
  state.operation=null;$('#reconnect').hidden=true;$('#cancel').disabled=true;
  screen(state.inspection?'review':'choose');
  showError(message);
}
async function start(kind,payload){
  const requestId=newRequestId();
  clearError();state.operation={kind,request_id:requestId,status:'running',phase:'starting',cancellable:false};renderOperation(state.operation);screen('processing');
  try{const operation=await api(kind,{...payload,request_id:requestId});await monitor(operation);}catch(reason){
    if(reason.status){state.operation=null;screen(state.inspection?'review':'choose');showError(reason);}
    else{$('#reconnect').hidden=false;$('#cancel').disabled=true;showError(`The connection was interrupted before confirmation. The operation may have started. Reconnect to check the local application. ${reason.message}`);}
  }
}
async function monitor(initial){
  if(state.polling)return;
  state.polling=true;$('#reconnect').hidden=true;
  let operation=initial;
  try{
    while(operation.status==='running'){
      renderOperation(operation);
      await new Promise(resolve=>setTimeout(resolve,200));
      operation=await api('status',{id:operation.id});
    }
    finishOperation(operation);
  }catch(reason){
    if(reason.status===409){
      unavailableOutcome('This operation’s status is no longer available. Another tab may have started a new operation. Check the destination before retrying, or choose another file.');
    }else{
      $('#reconnect').hidden=false;$('#cancel').disabled=true;
      showError(`Connection interrupted. The operation may still be running. ${reason.message} Reconnect to check its result.`);
    }
  }finally{state.polling=false;}
}
function finishOperation(operation){
  state.operation=null;
  if(operation.status==='completed'){
    clearError();
    if(operation.kind==='inspect')renderInspection(operation.result);
    else if(operation.kind==='create')renderResult(operation.result);
    else renderHash(operation.result.hash);
  }else{
    screen(state.inspection?'review':'choose');
    const message=operation.status==='cancelled'?'Operation cancelled. No output was published.':operation.error||'The operation failed. Check the source and destination before retrying.';
    showError(message);
  }
}
function renderHash(hash){
  if(state.inspection){
    screen('review');$('#hash-output').value=hash;$('#hash-output').hidden=false;$('#hash-label').hidden=false;$('#hash-controls').closest('details').open=true;$('#hash-output').focus();
  }else{
    $('#copy-result').hidden=true;$('#export-result').hidden=false;$('#result').setAttribute('aria-labelledby','export-result-title');$('#resumed-hash').value=hash;screen('result',false);$('#resumed-hash').focus();
  }
  announce('Password-recovery hash exported.');
}
function renderResult(result){
  $('#copy-result').hidden=false;$('#export-result').hidden=true;$('#result').setAttribute('aria-labelledby','result-title');
  $('#password').value='';state.output=result.output_path;
  $('#result-name').textContent=splitPath(result.output_path).name;$('#result-path').textContent=result.output_path;
  const counts=$('#result-counts');counts.replaceChildren();let total=0;
  for(const [key,label] of Object.entries(countLabels)){const count=result.removed?.[key]||0;if(!count)continue;total+=count;const row=document.createElement('div');addText(row,'dt',label);addText(row,'dd',String(count));counts.append(row);}
  if(!total){const row=document.createElement('div');addText(row,'dt','No protection elements removed');addText(row,'dd','0');counts.append(row);}
  $('#result-warnings').hidden=!result.warnings?.length;$('#result-warnings').textContent=(result.warnings||[]).join(' ');
  screen('result');announce('Working copy saved.');
}
$('#choose-file').addEventListener('click',async()=>{try{const path=await browse(state.browsePath||state.home);if(path)await inspect(path);}catch(reason){showError(reason);}});
$('#source-form').addEventListener('submit',event=>{event.preventDefault();inspect($('#source-path').value);});
$('#choose-folder').addEventListener('click',async()=>{try{const path=await browse($('#output-folder').value||state.home,'folder');if(path)$('#output-folder').value=path;}catch(reason){showError(reason);}});
$('#back').addEventListener('click',reset);$('#another').addEventListener('click',reset);
$('#create-form').addEventListener('invalid',event=>{const disclosure=event.target.closest('details');if(disclosure)disclosure.open=true;},true);
$('#create-form').addEventListener('submit',async event=>{
  event.preventDefault();if(state.operation)return;clearError();
  const name=$('#output-name').value,folder=$('#output-folder').value;
  if(!name.trim()||!folder.trim()||(isWindowsPath(folder)?/[\\/]/:/\//).test(name)||name==='.'||name==='..'){showError('Enter a file name without folder separators and choose a separate output folder.');return;}
  state.output=joinPath(folder,name);if(state.output===state.source){showError('Choose a different destination. The source file cannot be replaced.');return;}
  const options=optionsFrom($('#create-form'));
  if(Boolean(options.resign_cert)!==Boolean(options.resign_key)){showError('Provide both a certificate PEM path and a private key PEM path to re-sign the copy.');return;}
  if(state.inspection?.signed&&!options.strip_signatures){showError('This package is signed. Explicitly select “Create an unsigned copy” in Advanced options to continue.');return;}
  await start('create',{path:state.source,output:state.output,options});
});
$('#export-hash').addEventListener('click',()=>{if(!state.operation)start('export',{path:state.source,format:$('#hash-format').value});});
$('#cancel').addEventListener('click',async()=>{
  if(!state.operation?.id)return;$('#cancel').disabled=true;
  try{const operation=await api('cancel',{id:state.operation.id});if(state.operation)renderOperation(operation);}catch(reason){showError(reason);}
});
$('#reconnect').addEventListener('click',async()=>{
  clearError();if(!state.operation)return;
  if(state.operation.id){await monitor(state.operation);return;}
  const requestId=state.operation.request_id;$('#reconnect').disabled=true;
  try{
    const info=await api('info');const operation=info.active_operation;
    if(requestId&&operation?.request_id===requestId){
      if(operation.status==='running')await monitor(operation);
      else finishOperation(operation);
    }else{
      unavailableOutcome('The local application no longer has a result for this request. Check the destination before retrying, or choose another file. A different operation will not be treated as this request’s result.');
    }
  }catch(reason){showError(reason);}
  finally{$('#reconnect').disabled=false;}
});
async function connect(){
  screen('choose',false);
  try{
    if(!token)throw new Error('The connection token is missing.');
    const info=await api('info');state.home=info.home;state.browsePath=info.browse_path||info.home;state.dependencies=info.dependencies||{};
    $('#choose-file').disabled=false;$('#inspect-path').disabled=false;$('#connection').textContent='Connected to the local application.';$('#connection').className='sr-only';
    if(info.active_operation){
      const operation=info.active_operation;state.source=operation.path||info.path||'';state.output=operation.output||'';
      if(operation.status==='running'){renderOperation(operation);screen('processing');await monitor(operation);}
      else if(operation.status==='completed')finishOperation(operation);
      else if(info.path&&info.path_kind==='file'){$('#source-path').value=info.path;$('#source-path').closest('details').open=true;}
    }else if(info.path&&info.path_kind==='file'){$('#source-path').value=info.path;$('#source-path').closest('details').open=true;}
  }catch(reason){$('#connection').textContent='The local application could not be reached.';showError(`${reason.message} Launch dietrich-gui, then open the complete local address printed in its terminal.`);}
}
connect();
