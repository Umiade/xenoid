#!/usr/bin/env node
import { pathToFileURL } from 'node:url';
import { readFileSync } from 'node:fs';
import { setTimeout as sleep } from 'node:timers/promises';

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
const controller = new AbortController();
let failure;
let token;
let timer;
function checkFailure() {
  if (failure) throw failure;
  controller.signal.throwIfAborted();
}
async function post(path, body) {
  checkFailure();
  if (mode !== 'execute') return { ok: true, planned: true, path, body };
  try {
    const res = await fetch(endpoint + path, {
      method: 'POST',
      headers: {'content-type': 'application/json', 'X-Xenoid-Token': token},
      body: JSON.stringify(body ?? {}),
      signal: controller.signal,
      redirect: 'error',
    });
    const result = await res.json();
    if (!res.ok || result?.ok !== true) throw new Error('automation_action_failed');
    return result;
  } catch (error) {
    failure = error;
    throw error;
  }
}
const xenoid = {
  async tap(x, y) { const call = {op:'tap', x, y}; calls.push(call); return await post('/input/tap', {x, y}); },
  async swipe(x1, y1, x2, y2, durationMs = 300) { const call = {op:'swipe', x1, y1, x2, y2, durationMs}; calls.push(call); return await post('/input/swipe', call); },
  async sleep(ms) { checkFailure(); const call = {op:'sleep', ms}; calls.push(call); if (mode === 'execute') await sleep(ms, undefined, {signal: controller.signal}); checkFailure(); return {ok:true, sleepMs:ms}; },
  async shell(command) { const call = {op:'shell', command}; calls.push(call); return await post('/root/exec', {command}); },
  async launch(component) { const call = {op:'launch', component}; calls.push(call); return await post('/app/launch', {component}); },
  async install(path) { const call = {op:'install', path}; calls.push(call); return await post('/app/install', {path}); },
  async uninstall(packageName) { const call = {op:'uninstall', package: packageName}; calls.push(call); return await post('/app/uninstall', {package: packageName}); },
  async set(field, value) { const call = {op:'set', field, value}; calls.push(call); return await post('/fingerprint/set', {field, value}); },
};
try {
  if (mode === 'execute') {
    const credential = readFileSync(0);
    token = credential.toString('ascii');
    credential.fill(0);
    if (!/^[0-9a-f]{32}$/.test(token)) throw new Error('automation_auth_unavailable');
  }
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new Error('automation_timeout'));
    }, 30000);
  });
  const task = async () => {
    const mod = await import(pathToFileURL(script).href);
    if (typeof mod.default !== 'function') throw new Error('automation_script_invalid');
    const result = await mod.default(xenoid);
    checkFailure();
    if (result?.ok === false) throw new Error('automation_task_failed');
    return result;
  };
  const result = await Promise.race([task(), timeout]);
  clearTimeout(timer);
  await new Promise(resolve => process.stdout.write(JSON.stringify({ok:true, mode, calls, result}, null, 2) + '\n', resolve));
  process.exit(0);
} catch (error) {
  clearTimeout(timer);
  controller.abort();
  const code = controller.signal.aborted && error?.name === 'AbortError'
    ? 'automation_timeout' : error?.message;
  await new Promise(resolve => process.stdout.write(JSON.stringify({ok:false, error:/^automation_[a-z_]+$/.test(code) ? code : 'automation_script_failed', calls}, null, 2) + '\n', resolve));
  process.exit(1);
}
