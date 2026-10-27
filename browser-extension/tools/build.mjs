import {mkdir, copyFile, writeFile, readFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';
import {deflateRawSync} from 'node:zlib';
const root = fileURLToPath(new URL('../', import.meta.url));
const files = ['background.mjs','visibility.mjs','popup.html','popup.mjs','popup.css'];
export function nativeHostManifest(browser, executable, chromeId) {
  if (!['chrome','firefox'].includes(browser) || (!path.posix.isAbsolute(executable) && !path.win32.isAbsolute(executable))) throw Error('An absolute native executable is required');
  const base = {name:'com.openems.browser', description:'OpenEMS browser visibility broker', path:executable, type:'stdio'};
  if (browser === 'chrome') {
    if (!/^[a-p]{32}$/.test(chromeId ?? '')) throw Error('An exact Chrome extension ID is required');
    return {...base, allowed_origins:[`chrome-extension://${chromeId}/`]};
  }
  return {...base, allowed_extensions:['browser-visibility@openems.local']};
}
function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) { crc ^= byte; for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1)); }
  return (crc ^ 0xffffffff) >>> 0;
}
async function zip(directory, destination) {
  const local = []; const central = []; let offset = 0;
  for (const name of ['manifest.json', ...files]) {
    const bytes = await readFile(path.join(directory, name)); const compressed = deflateRawSync(bytes); const filename = Buffer.from(name);
    const header = Buffer.alloc(30); header.writeUInt32LE(0x04034b50); header.writeUInt16LE(20,4); header.writeUInt16LE(8,8); header.writeUInt32LE(crc32(bytes),14); header.writeUInt32LE(compressed.length,18); header.writeUInt32LE(bytes.length,22); header.writeUInt16LE(filename.length,26);
    local.push(header,filename,compressed);
    const entry = Buffer.alloc(46); entry.writeUInt32LE(0x02014b50); entry.writeUInt16LE(20,4); entry.writeUInt16LE(20,6); entry.writeUInt16LE(8,10); header.copy(entry,16,14,26); entry.writeUInt16LE(filename.length,28); entry.writeUInt32LE(offset,42); central.push(entry,filename); offset += header.length+filename.length+compressed.length;
  }
  const entries = Buffer.concat(central); const end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50); end.writeUInt16LE(files.length+1,8); end.writeUInt16LE(files.length+1,10); end.writeUInt32LE(entries.length,12); end.writeUInt32LE(offset,16);
  await writeFile(destination, Buffer.concat([...local,entries,end]));
}
export async function buildTargets(destination = path.join(root,'dist')) {
  for (const browser of ['chrome','firefox']) {
    const directory = path.join(destination,browser); await mkdir(directory,{recursive:true});
    const manifest = {manifest_version:3, name:'OpenEMS Browser Visibility', version:'0.1.0', description:'Observação opcional de navegação conforme a política OpenEMS.', permissions:['nativeMessaging','storage','webNavigation'], incognito:'not_allowed', action:{default_popup:'popup.html'}, background:browser === 'chrome' ? {service_worker:'background.mjs',type:'module'} : {scripts:['background.mjs'],type:'module'}};
    if (browser === 'firefox') manifest.browser_specific_settings = {gecko:{id:'browser-visibility@openems.local'}};
    await writeFile(path.join(directory,'manifest.json'),JSON.stringify(manifest,null,2)+'\n');
    for (const file of files) await copyFile(path.join(root,'src',file),path.join(directory,file));
    await zip(directory,path.join(destination,`openems-browser-${browser}.zip`));
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) { await buildTargets(); console.log('Chrome and Firefox packages built; native broker integration remains pending.'); }
