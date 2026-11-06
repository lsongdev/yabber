// yabber gateway panel entry point (panel module contract, version 1). The
// host is a panel shell, or standalone.js on its own.
import { createMount } from './lib/mount.js';

const page = load => ({ load });

const routes = [
  { path: '/', ...page(() => import('./pages/overview.js')) },
  { path: '/sites', ...page(() => import('./pages/sites.js')) },
  { path: '/sites/new', ...page(() => import('./pages/site.js')) },
  { path: '/sites/:id', ...page(() => import('./pages/site.js')) },
  { path: '/certificates', ...page(() => import('./pages/certificates.js')) },
  { path: '/events', ...page(() => import('./pages/events.js')) },
  { path: '/config', ...page(() => import('./pages/config.js')) },
];

// The management API answers plain JSON, not {"data": …}.
export const mount = createMount({ routes, envelope: false });
