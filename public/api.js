/* ================================================================
   VirtualPrime — client API layer
   Wraps fetch() to the Express backend and stores JWTs.
   Load with <script src="api.js"></script> before page scripts.
   Everything is exposed on window.VE.
   ================================================================ */
(function () {
  // Same-origin in production (served by Express). Override for local cross-origin if needed.
  const BASE = (window.VE_API_BASE || '') + '/api';

  // token keys (member / partner / admin kept separate so all three can coexist)
  const TK = { member: 've_tok', partner: 've_ptok', admin: 've_atok' };

  const getTok = (role) => localStorage.getItem(TK[role] || '') || '';
  const setTok = (role, t) => t ? localStorage.setItem(TK[role], t) : localStorage.removeItem(TK[role]);

  async function req(method, path, body, role) {
    const headers = { 'Content-Type': 'application/json' };
    const tok = role ? getTok(role) : (getTok('member') || getTok('partner') || getTok('admin'));
    if (tok) headers.Authorization = 'Bearer ' + tok;
    const res = await fetch(BASE + path, {
      method,
      headers,
      body: body != null ? JSON.stringify(body) : undefined,
    });
    let data = null;
    try { data = await res.json(); } catch { /* no body */ }
    if (!res.ok) {
      const err = new Error((data && data.error) || ('Request failed (' + res.status + ')'));
      err.status = res.status;
      throw err;
    }
    return data;
  }

  const VE = {
    /* ---- token / session helpers ---- */
    token: getTok,
    setToken: setTok,
    isMember:  () => !!getTok('member'),
    isPartner: () => !!getTok('partner'),
    isAdmin:   () => !!getTok('admin'),

    /* ---- member auth ---- */
    async register(name, email, password, ref) {
      const r = await req('POST', '/auth/register', { name, email, password, ref });
      setTok('member', r.token);
      localStorage.setItem('ve_me', JSON.stringify(r.user));
      return r.user;
    },
    forgotPassword: (email) => req('POST', '/auth/forgot', { email }),
    resetPassword: (token, password) => req('POST', '/auth/reset', { token, password }),
    async login(email, password) {
      const r = await req('POST', '/auth/login', { email, password });
      setTok('member', r.token);
      localStorage.setItem('ve_me', JSON.stringify(r.user));
      return r.user;
    },
    me: () => req('GET', '/me', null, 'member'),
    async connectSporty(account) {
      const r = await req('POST', '/me/sporty', { account }, 'member');
      if (r && r.user) localStorage.setItem('ve_me', JSON.stringify(r.user));
      return r;
    },
    myPicks: (pendingOnly) => req('GET', '/me/picks' + (pendingOnly ? '?pending=1' : ''), null, 'member'),
    consumePick: (id) => req('POST', '/me/picks/' + id + '/consume', {}, 'member'),
    recordPurchase: (p) => req('POST', '/me/purchases', p, 'member'),
    manualClaim: (p) => req('POST', '/me/manual-claims', p, 'member'),
    manualClaimStatus: (id) => req('GET', '/me/manual-claims/' + id, null, 'member'),
    spendCredit: (amount, game) => req('POST', '/me/credits/spend', { amount: amount || 1, game }, 'member'),
    cachedMe: () => { try { return JSON.parse(localStorage.getItem('ve_me') || 'null'); } catch { return null; } },
    signOutMember() { setTok('member', null); localStorage.removeItem('ve_me'); },

    /* ---- partner auth ---- */
    partnerRegister: (name, email, password) => req('POST', '/partner/register', { name, email, password }),
    async partnerLogin(email, password) {
      const r = await req('POST', '/partner/login', { email, password });
      setTok('partner', r.token);
      localStorage.setItem('ve_pme', JSON.stringify(r.partner));
      return r.partner;
    },
    partnerMe: () => req('GET', '/partner/me', null, 'partner'),
    partnerReferrals: () => req('GET', '/partner/referrals', null, 'partner'),
    partnerRevenueDaily: () => req('GET', '/partner/revenue-daily', null, 'partner'),
    partnerClearRevenue: () => req('POST', '/partner/revenue-clear', {}, 'partner'),
    partnerPicks: () => req('GET', '/partner/picks', null, 'partner'),
    partnerSendPicks: (email, picks) => req('POST', '/partner/picks', { email, picks }, 'partner'),
    partnerCancelPick: (id) => req('DELETE', '/partner/picks/' + id, null, 'partner'),
    cachedPartner: () => { try { return JSON.parse(localStorage.getItem('ve_pme') || 'null'); } catch { return null; } },
    signOutPartner() { setTok('partner', null); localStorage.removeItem('ve_pme'); },

    /* ---- shared ---- */
    accounts: () => req('GET', '/accounts'),
    scan: (image, game) => req('POST', '/scan', { image, game }),

    /* ---- admin ---- */
    async adminLogin(email, password) {
      const r = await req('POST', '/admin/login', { email, password });
      setTok('admin', r.token);
      return true;
    },
    adminUsers: () => req('GET', '/admin/users', null, 'admin'),
    adminPartners: () => req('GET', '/admin/partners', null, 'admin'),
    adminAddPartner: (p) => req('POST', '/admin/partners', p, 'admin'),
    adminPartnerAction: (id, action, extra) => req('PATCH', '/admin/partners/' + id, Object.assign({ action }, extra || {}), 'admin'),
    adminDeletePartner: (id) => req('DELETE', '/admin/partners/' + id, null, 'admin'),
    adminGrantCredits: (email, amount, game) => req('POST', '/admin/credits', { email, amount, game }, 'admin'),
    adminScanUsage: () => req('GET', '/admin/scan-usage', null, 'admin'),
    adminScanTopup: (amount) => req('POST', '/admin/scan-topup', { amount }, 'admin'),
    adminDeleteUser: (email) => req('DELETE', '/admin/users/' + encodeURIComponent(email), null, 'admin'),
    adminPurchases: () => req('GET', '/admin/purchases', null, 'admin'),
    adminClearPurchases: () => req('DELETE', '/admin/purchases', null, 'admin'),
    adminClearRevenue: () => req('POST', '/admin/revenue-clear', {}, 'admin'),
    adminRevenueDaily: () => req('GET', '/admin/revenue-daily', null, 'admin'),
    adminDeletePurchase: (key, revoke) => req('DELETE', '/admin/purchases/' + encodeURIComponent(key) + (revoke ? '?revoke=1' : ''), null, 'admin'),
    adminAlerts: () => req('GET', '/admin/alerts', null, 'admin'),
    adminClearAlerts: () => req('DELETE', '/admin/alerts', null, 'admin'),
    adminPicks: () => req('GET', '/admin/picks', null, 'admin'),
    adminSendPicks: (email, picks) => req('POST', '/admin/picks', { email, picks }, 'admin'),
    adminCancelPick: (id) => req('DELETE', '/admin/picks/' + id, null, 'admin'),
    adminStats: () => req('GET', '/admin/stats', null, 'admin'),
    adminPaymentConfig: () => req('POST', '/admin/payment-config/get', {}, 'admin'),
    adminSavePaymentConfig: (c) => req('PUT', '/admin/payment-config', c, 'admin'),
    adminManualClaims: () => req('GET', '/admin/manual-claims', null, 'admin'),
    adminManualClaimDecide: (id, action) => req('POST', '/admin/manual-claims/' + id + '/' + action, {}, 'admin'),
    adminManualClaimProof: (id) => req('GET', '/admin/manual-claims/' + id + '/proof', null, 'admin'),
    signOutAdmin() { setTok('admin', null); },

    /* ---- public ---- */
    paymentConfigPublic: () => req('GET', '/payment-config/public'),
    fxRates: () => req('GET', '/fx-rates'),
    adminSaveFxRates: (rates) => req('PUT', '/admin/fx-rates', rates, 'admin'),

    /* ---- Cowrie gateway (proxied server-side; no CORS, secret stays on server) ---- */
    cowrieInit: (body) => req('POST', '/pay/cowrie/init', body),
    cowrieStatus: (reference) => req('GET', '/pay/cowrie/status?reference=' + encodeURIComponent(reference)),
  };

  window.VE = VE;
})();
