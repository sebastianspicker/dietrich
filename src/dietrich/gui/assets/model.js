/** Pure presentation mappings for the public Dietrich domain models. */
export const formats = {excel_ooxml:'Excel workbook',word_ooxml:'Word document',powerpoint_ooxml:'PowerPoint presentation',pdf:'PDF document',encrypted_ooxml:'Encrypted Office document',legacy_cfbf:'Legacy Office document',unknown:'Unknown format'};
export const categories = [
  ['remove_worksheet_protection','Remove worksheet protection',['sheetProtection']],
  ['remove_workbook_protection','Remove workbook protection',['workbookProtection']],
  ['remove_document_protection','Remove document protection',['documentProtection','writeProtection']],
  ['remove_modify_verifier','Remove modify-password verifier',['modifyVerifier']],
  ['remove_mark_as_final','Clear final/read-only package flags',['MarkAsFinal','DocSecurity']],
];
export const countLabels = {worksheet_protections:'Worksheet protection elements removed',workbook_protections:'Workbook protection elements removed',document_protections:'Document protection elements removed',modify_verifiers:'Modify-password verifiers removed',mark_as_final:'Final/read-only package flags cleared',pdf_permission_strips:'PDF permission restrictions removed',signatures_stripped:'Package signatures removed',vba_unlocked:'VBA verifier fields cleared',other:'Other protection elements removed'};
export function isWindowsPath(path) {
  // Absolute POSIX paths can contain literal backslashes, including in names.
  return !path.startsWith('/') && (/^[A-Za-z]:[\\/]/.test(path) || path.startsWith('\\\\'));
}
function pathSeparator(path) {
  return isWindowsPath(path) ? (/^[A-Za-z]:/.test(path) ? path[2] : '\\') : '/';
}
export function splitPath(path) {
  const separator = pathSeparator(path);
  const index = isWindowsPath(path) ? Math.max(path.lastIndexOf('/'),path.lastIndexOf('\\')) : path.lastIndexOf('/');
  const driveRoot = index===2 && /^[A-Za-z]:/.test(path);
  const folder = index<0 ? '.' : driveRoot ? path.slice(0,3) : path.slice(0,index)||separator;
  return {name:path.slice(index+1),folder,separator};
}
export function outputDefault(path) {
  const parts = splitPath(path);
  const dot = parts.name.lastIndexOf('.');
  return {...parts,name:dot>0?`${parts.name.slice(0,dot)}_unprotected${parts.name.slice(dot)}`:`${parts.name}_unprotected`};
}
export function joinPath(folder,name) {
  const separator = pathSeparator(folder);
  const suffix = isWindowsPath(folder) ? /[\\/]+$/ : /\/+$/;
  return `${folder.replace(suffix,'')}${separator}${name}`;
}
export function protectionChoices(inspection) {
  const parts = inspection.soft_protections || [];
  const choices = categories.map(([key,label,kinds]) => ({key,label,count:parts.filter(part=>kinds.includes(part.kind)).reduce((sum,part)=>sum+part.count,0)})).filter(choice=>choice.count>0);
  if (inspection.document_format === 'encrypted_ooxml') {
    // Inner package findings are unavailable until decryption. Explicit choices
    // retain category-wide control without claiming a detected protection count.
    for (const [key,label] of categories) if (!choices.some(choice=>choice.key===key)) choices.push({key,label,count:null});
  }
  if (inspection.document_format === 'pdf') choices.push({key:'strip_pdf_permissions',label:'Create an unencrypted PDF copy',count:null,fixed:true,detail:'PDF working copies are always saved without encryption and owner restrictions.'});
  return choices;
}
export function optionsFrom(form) {
  const data = new FormData(form);
  const options = {};
  for (const key of [...categories.map(category=>category[0]),'strip_pdf_permissions','strip_signatures','unlock_vba','soft_only','overwrite','use_hashcat']) options[key] = data.get(key)==='on';
  for (const key of ['password','wordlist','mask','charset','resign_cert','resign_key']) options[key] = data.get(key) || null;
  for (const key of ['max_length','max_candidates','workers','hashcat_timeout']) options[key] = data.get(key) ? Number(data.get(key)) : null;
  options.hashcat_args = String(data.get('hashcat_args')||'').split(/\r?\n/).map(value=>value.trim()).filter(Boolean);
  return options;
}
export function inspectionMetadata(inspection) {
  return [formats[inspection.document_format]||inspection.document_format,inspection.encrypted?'Encrypted':inspection.user_password_required?'Open password required':'No open password',inspection.signed?'Package signature present':inspection.document_format==='encrypted_ooxml'?'Package signature: unknown until decrypted':'No package signature'].join(' · ');
}
export function technicalEntries(inspection,dependencies) {
  return [
    ['Format',formats[inspection.document_format]||inspection.document_format],['Open password required',inspection.user_password_required?'Yes':'No'],['Encrypted',inspection.encrypted?'Yes':'No'],['Owner restrictions',inspection.owner_restrictions?'Present':'Not detected'],['Package signature',inspection.signed?'Present':inspection.document_format==='encrypted_ooxml'?'Unknown until decrypted':'Not detected'],['VBA project',inspection.vba_project_present?'Present':inspection.document_format==='encrypted_ooxml'?'Unknown until decrypted':'Not detected'],
    ...['encryption_scheme','encryption_version','encryption_spin_count','encryption_cost_class','hashcat_mode','irm_kind'].filter(key=>inspection[key]!=null).map(key=>[key.replaceAll('_',' '),String(inspection[key])]),
    ...Object.entries(dependencies||{}).map(([key,value])=>[`${key} dependency`,value?'Available':'Unavailable']),
  ];
}
export function phaseSteps(phase) {
  // Only infer completed checkpoints from concrete backend phase boundaries.
  const value = (phase||'').toLowerCase();
  if (value==='publishing'||value==='ready to publish') return 3;
  if (value.includes('validat')) return 2;
  if (value.includes('writing')||value.includes('applying')||value.includes('rewriting')||value.includes('removing')||value.includes('decrypt')||value.includes('signing')||value.includes('recovering')) return 1;
  return 0;
}
