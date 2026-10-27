import assert from 'node:assert/strict';
import {test} from 'node:test';
import {mkdtemp, readFile, readdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {buildTargets, nativeHostManifest} from '../tools/build.mjs';

test('browser-specific MV3 packages do not request history, content injection or remote connections', async () => {
  const root = await mkdtemp(path.join(tmpdir(), 'openems-extension-build-'));
  await buildTargets(root);
  for (const browser of ['chrome','firefox']) {
    const directory = path.join(root, browser);
    const archive = await readFile(path.join(root, `openems-browser-${browser}.zip`));
    assert.equal(archive.readUInt32LE(0), 0x04034b50);
    assert.equal(archive.readUInt32LE(archive.length - 22), 0x06054b50);
    assert.equal(archive.readUInt16LE(archive.length - 14), 6);
    const manifest = JSON.parse(await readFile(path.join(directory, 'manifest.json'), 'utf8'));
    assert.equal(manifest.manifest_version, 3);
    assert.deepEqual(manifest.permissions.toSorted(), ['nativeMessaging','storage','webNavigation'].toSorted());
    assert.equal(manifest.incognito, 'not_allowed');
    assert.equal(manifest.content_scripts, undefined); assert.equal(manifest.host_permissions, undefined);
    assert.equal(manifest.externally_connectable, undefined); assert.equal(manifest.web_accessible_resources, undefined);
    assert.equal(manifest.action.default_popup, 'popup.html');
    for (const file of ['background.mjs','visibility.mjs','popup.html','popup.mjs','popup.css']) assert.ok((await readdir(directory)).includes(file), file);
    if (browser === 'chrome') { assert.deepEqual(manifest.background, {service_worker:'background.mjs', type:'module'}); assert.equal(manifest.browser_specific_settings, undefined); }
    else { assert.deepEqual(manifest.background, {scripts:['background.mjs'], type:'module'}); assert.equal(manifest.browser_specific_settings.gecko.id, 'browser-visibility@openems.local'); }
  }
});

test('native-host manifest generation rejects wildcard caller IDs and requires an absolute executable', () => {
  const id = 'abcdefghijklmnopabcdefghijklmnop';
  assert.throws(() => nativeHostManifest('chrome', 'C:/Program Files/openems/openems-browser.exe', '*'));
  assert.throws(() => nativeHostManifest('chrome', 'relative.exe', id));
  assert.throws(() => nativeHostManifest('chrome', 'C:/agent.exe', 'evil.example'));
  assert.deepEqual(nativeHostManifest('chrome', 'C:/Program Files/openems/openems-browser.exe', id).allowed_origins, [`chrome-extension://${id}/`]);
  assert.deepEqual(nativeHostManifest('firefox', '/usr/bin/openems-browser').allowed_extensions, ['browser-visibility@openems.local']);
});
