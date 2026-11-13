'use strict';
const element = id => document.getElementById(id);
let csrf; let ticket; let step = 'login'; let busy = false;
const show = value => { element('result').textContent = JSON.stringify(value, null, 2); };
function stage(next) {
  step = next; element('stage').textContent = step;
  element('value').type = step === 'password' ? 'password' : 'text';
  element('value').autocomplete = step === 'password' ? 'current-password' : step === 'totp' ? 'one-time-code' : 'off';
}
async function request(path, body, raw = false) {
  const response = await fetch(path, body === undefined ? {} : { method: 'POST',
    headers: { 'Content-Type': raw ? 'application/octet-stream' : 'application/json', 'X-CSRF-Token': csrf },
    body: raw ? body : JSON.stringify(body) });
  const value = await response.json();
  if (!response.ok) throw new Error(value.error);
  return value;
}
async function refresh() {
  const value = await request('/api/bootstrap'); csrf = value.csrf;
  element('hints').textContent = JSON.stringify({ synthetic: true, users: value.users, captchaAnswer: value.captchaAnswer }, null, 2);
}
async function action(fn) {
  if (busy) return; busy = true;
  try { await fn(); } catch { show({ error: 'request_denied' }); } finally { busy = false; }
}
element('refresh').onclick = () => action(refresh);
element('login').onsubmit = event => {
  event.preventDefault(); const value = element('value').value; element('value').value = '';
  action(async () => {
    if (step === 'authenticated') return;
    try {
      const response = await request('/api/' + step, step === 'login' ? { value } : { value, ticket });
      ticket = response.ticket; stage(response.authenticated ? 'authenticated' : response.next); show(response.authenticated ? { authenticated: true } : { next: response.next });
    } catch (error) { ticket = undefined; stage('login'); throw error; }
  });
};
element('reset').onclick = () => { if (!busy) { ticket = undefined; element('value').value = ''; stage('login'); } };
element('logout').onclick = () => action(async () => { show(await request('/api/logout', {})); ticket = undefined; stage('login'); });
element('contact').onsubmit = event => { event.preventDefault(); action(async () => show(await request('/api/contacts', Object.fromEntries(new FormData(event.target))))); };
element('list').onclick = () => action(async () => show(await request('/api/contacts')));
element('upload').onclick = () => action(async () => {
  const file = element('file').files[0]; if (!file || file.size > 1048576) throw new Error('Invalid file');
  const response = await request('/api/uploads', file, true); element('upload-id').value = response.id; show(response);
});
element('process').onclick = () => action(async () => show(await request('/api/uploads/' + encodeURIComponent(element('upload-id').value) + '/process', {})));
element('download').onclick = () => action(async () => {
  const response = await fetch('/api/uploads/' + encodeURIComponent(element('upload-id').value));
  if (!response.ok) throw new Error('Denied');
  const blob = await response.blob(); const url = URL.createObjectURL(blob); const anchor = document.createElement('a');
  anchor.href = url; anchor.download = 'lab-download.bin'; anchor.click(); URL.revokeObjectURL(url); show({ downloaded: true });
});
action(refresh);
