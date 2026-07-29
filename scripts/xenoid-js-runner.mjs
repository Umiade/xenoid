#!/usr/bin/env node
import { pathToFileURL } from 'node:url';

const args = process.argv.slice(2);
const script = args[0];
const mode = args.includes('--execute') ? 'execute' : 'plan';
const endpointArg = args.find(a => a.startsWith('--endpoint='));
const endpoint = endpointArg ? endpointArg.slice('--endpoint='.length) : 'http://127.0.0.1:18765';
if (!script) {
  console.error('usage: xenoid-js-runner.mjs <task.js> [--execute] [--endpoint=http://127.0.0.1:18765]');
  process.exit(64);
}
const calls = [];
async function post(path, body) {
  if (mode !== 'execute') return { ok: true, planned: true, path, body };
  const res = await fetch(endpoint + path, { method: 'POST', headers: {'content-type': 'application/json'}, body: JSON.stringify(body ?? {}) });
  return await res.json();
}
const xenoid = {
  async tap(x, y) { const call = {op:'tap', x, y}; calls.push(call); return await post('/input/tap', {x, y}); },
  async swipe(x1, y1, x2, y2, durationMs = 300) { const call = {op:'swipe', x1, y1, x2, y2, durationMs}; calls.push(call); return await post('/input/swipe', call); },
  async sleep(ms) { const call = {op:'sleep', ms}; calls.push(call); if (mode === 'execute') await new Promise(r => setTimeout(r, ms)); return {ok:true, sleepMs:ms}; },
  async shell(command) { const call = {op:'shell', command}; calls.push(call); return await post('/root/exec', {command}); },
  async launch(component) { const call = {op:'launch', component}; calls.push(call); return await post('/app/launch', {component}); },
  async install(path) { const call = {op:'install', path}; calls.push(call); return await post('/app/install', {path}); },
  async uninstall(packageName) { const call = {op:'uninstall', package: packageName}; calls.push(call); return await post('/app/uninstall', {package: packageName}); },
  async set(field, value) { const call = {op:'set', field, value}; calls.push(call); return await post('/fingerprint/set', {field, value}); },
};
try {
  const mod = await import(pathToFileURL(script).href + `?t=${Date.now()}`);
  if (typeof mod.default !== 'function') throw new Error('task module must export default async function task(xenoid)');
  const result = await mod.default(xenoid);
  console.log(JSON.stringify({ok:true, mode, calls, result}, null, 2));
} catch (e) {
  console.log(JSON.stringify({ok:false, error:String(e && e.stack || e), calls}, null, 2));
  process.exit(1);
}
