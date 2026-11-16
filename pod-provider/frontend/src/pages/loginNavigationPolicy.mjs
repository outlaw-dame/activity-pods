/** Configured origins, never string prefixes, authorize post-login navigation. */
export function resolveLoginReturn(value, { backendUrl, frontendOrigin }) {
  const fallback = { mode: 'internal', url: '/network' };
  if (typeof value !== 'string' || !value || value.length > 4096 || value !== value.trim() ||
      /[\s\\]/u.test(value) || value.startsWith('//')) return fallback;
  try {
    const frontend = new URL(frontendOrigin);
    const parsed = new URL(value, frontend.origin);
    const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname);
    if (parsed.username || parsed.password ||
        (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && loopback))) return fallback;
    if (parsed.origin === frontend.origin) {
      return { mode: 'internal', url: `${parsed.pathname}${parsed.search}${parsed.hash}` };
    }
    const backend = new URL(backendUrl);
    if (!backend.username && !backend.password && parsed.origin === backend.origin) {
      return { mode: 'external', url: parsed.href };
    }
  } catch { return fallback; }
  return fallback;
}
