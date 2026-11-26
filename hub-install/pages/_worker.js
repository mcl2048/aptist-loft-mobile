export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    if (pathname === '/.well-known/loft-app' || pathname.startsWith('/v1/')) {
      return env.HUB.fetch(request);
    }
    return env.ASSETS.fetch(request);
  },
};
