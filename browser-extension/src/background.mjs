import {createVisibilityController} from './visibility.mjs';
const api = globalThis.browser ?? globalThis.chrome;
const controller = createVisibilityController(api);
const initialized = controller.initialize();
api.webNavigation.onCommitted.addListener((details) => { void initialized.then(() => controller.observe(details)).catch(() => console.warn('Visibility observation failed')); });
api.runtime.onMessage.addListener((message, sender, respond) => {
  if (sender.id !== api.runtime.id || sender.tab || !['visibility_status','visibility_configure'].includes(message?.type)) return false;
  void initialized.then(async () => {
    if (message.type === 'visibility_configure') await controller.configure(message.settings);
    respond({ok:true, status:controller.status()});
  }).catch(() => respond({ok:false, error:'Não foi possível salvar ou consultar a configuração.'}));
  return true;
});
