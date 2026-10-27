const api = globalThis.browser ?? globalThis.chrome;
const enabled = document.querySelector('#enabled');
const includePath = document.querySelector('#includePath');
const button = document.querySelector('button');
const status = document.querySelector('#status');
const error = document.querySelector('#error');
function render(result) {
  if (!result?.ok) throw Error('Invalid status');
  enabled.checked = result.status.enabled; includePath.checked = result.status.includePath;
  status.textContent = !result.status.enabled ? 'Observação desativada.' : result.status.paired ? 'Agente conectado. Observação conforme a política.' : 'Inativa: aguardando agente compatível e pareamento.';
}
async function request(message) {
  button.disabled = true; error.textContent = '';
  try { render(await api.runtime.sendMessage(message)); }
  catch { error.textContent = 'Não foi possível consultar ou salvar a configuração. Tente novamente.'; }
  finally { button.disabled = false; }
}
document.querySelector('form').addEventListener('submit', (event) => { event.preventDefault(); void request({type:'visibility_configure', settings:{enabled:enabled.checked, includePath:includePath.checked}}); });
void request({type:'visibility_status'});
