/** Keyboard-accessible local filesystem chooser, backed by the loopback API. */
export function createBrowser(api) {
  const dialog = document.querySelector('#file-dialog');
  const path = document.querySelector('#browse-path');
  const entries = document.querySelector('#browse-entries');
  const status = document.querySelector('#browse-status');
  const error = document.querySelector('#browse-error');
  const up = document.querySelector('#browse-up');
  const select = document.querySelector('#select-folder');
  let kind = 'file', current = '', parent = '', resolveSelection, version = 0;
  function finish(value) { dialog.close(); resolveSelection?.(value); resolveSelection=null; }
  async function load(folder) {
    const request = ++version;
    status.textContent='Reading folder…'; error.hidden=true; entries.replaceChildren(); up.disabled=true; select.disabled=true;
    try {
      const result = await api('browse',{path:folder,kind});
      if (request!==version || !dialog.open) return;
      current=result.path; parent=result.parent; path.value=current;
      up.disabled=!parent||parent===current; select.disabled=false;
      status.textContent = result.truncated?'Showing a limited directory listing. Enter a path to reach other files.':result.entries.length?'Choose a folder or document.':'This folder is empty.';
      for (const entry of result.entries) {
        const li=document.createElement('li'), button=document.createElement('button');
        button.type='button'; button.textContent=`${entry.directory?'▸  ':''}${entry.name}`;
        if(entry.directory)button.className='directory';
        button.addEventListener('click',()=>entry.directory?load(entry.path):finish(entry.path));
        li.append(button); entries.append(li);
      }
    } catch(reason) { if(request!==version)return; error.textContent=reason.message; error.hidden=false; status.textContent='Folder could not be opened.'; }
  }
  document.querySelector('#browse-form').addEventListener('submit',event=>{event.preventDefault();load(path.value);});
  up.addEventListener('click',()=>load(parent)); select.addEventListener('click',()=>finish(current));
  dialog.addEventListener('close',()=>{version++;resolveSelection?.(null);resolveSelection=null;});
  return (initial,requestedKind='file')=>new Promise(resolve=>{
    kind=requestedKind;resolveSelection=resolve;
    document.querySelector('#dialog-title').textContent=kind==='folder'?'Choose output folder':'Choose local file';
    select.hidden=kind!=='folder';dialog.showModal();load(initial);path.focus();
  });
}
