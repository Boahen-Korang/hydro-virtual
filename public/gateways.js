/* ================================================================
   VirtualPrime — pluggable payment gateways
   ----------------------------------------------------------------
   One small adapter per provider. The active provider is chosen in
   Admin → Payment Gateway and returned by /api/payment-config/public.
   Checkout pages call:  VEPay.checkout(provider, cfg, opts, handlers)

   cfg      = { key, business }            (from the public config)
   opts     = { email, name, amount, currency, reference, metadata }
              amount is in MAJOR units (e.g. 300 = GHS 300)
   handlers = { onSuccess(reference), onCancel(), onError(message) }

   To add a new inline gateway, add one entry to GATEWAYS below with a
   `label`, an optional `sdk` URL, and a `pay()` that opens its popup.
   ================================================================ */
(function () {
  /* load a 3rd-party SDK once, on demand */
  const _scripts = {};
  function loadScript(src) {
    if (!src) return Promise.resolve();
    if (_scripts[src]) return _scripts[src];
    _scripts[src] = new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = src; s.async = true;
      s.onload = () => resolve();
      s.onerror = () => { delete _scripts[src]; reject(new Error('Could not load ' + src)); };
      document.head.appendChild(s);
    });
    return _scripts[src];
  }

  const GATEWAYS = {
    /* ---- Paystack (inline v2) ---- */
    paystack: {
      label: 'Paystack',
      sdk: 'https://js.paystack.co/v2/inline.js',
      async pay(cfg, o, h) {
        await loadScript(this.sdk);
        const popup = new window.PaystackPop();
        popup.newTransaction({
          key: cfg.key,
          email: o.email,
          amount: Math.round(o.amount * 100), // kobo/pesewas
          currency: o.currency,
          reference: o.reference,
          metadata: o.metadata || {},
          onSuccess: (tx) => h.onSuccess((tx && tx.reference) || o.reference),
          onCancel: () => h.onCancel(),
          onError: (err) => h.onError(err && err.message),
        });
      },
    },

    /* ---- Flutterwave (inline v3) ---- */
    flutterwave: {
      label: 'Flutterwave',
      sdk: 'https://checkout.flutterwave.com/v3.js',
      async pay(cfg, o, h) {
        await loadScript(this.sdk);
        const modal = window.FlutterwaveCheckout({
          public_key: cfg.key,
          tx_ref: o.reference,
          amount: o.amount, // major units
          currency: o.currency,
          payment_options: 'card,mobilemoneyghana,mobilemoney,ussd,banktransfer',
          customer: { email: o.email, name: o.name || '' },
          meta: o.metadata || {},
          customizations: {
            title: cfg.business || 'VirtualPrime',
            description: (o.metadata && o.metadata.package) || 'Predictions package',
          },
          callback: (resp) => {
            try { modal && modal.close && modal.close(); } catch (e) {}
            const ok = resp && (resp.status === 'successful' || resp.status === 'completed' || resp.charge_response_code === '00');
            if (ok) h.onSuccess(resp && resp.tx_ref ? resp.tx_ref : o.reference);
            else h.onCancel();
          },
          onclose: () => h.onCancel(),
        });
      },
    },

    /* ---- Cowrie (REST API, hosted checkout via server proxy) ----
       The browser can't call Cowrie directly (no CORS) and must not see the
       secret key, so this goes through /api/pay/cowrie/* on our own server. */
    cowrie: {
      label: 'Cowrie',
      sdk: null,
      async pay(cfg, o, h) {
        // Full-page redirect in the SAME tab (no popup → no stray second tab).
        // Cowrie sends the buyer back to pricing.html (callbackUrl), which then
        // confirms the charge with the server and forwards to the dashboard.
        let init;
        try {
          init = await window.VE.cowrieInit({
            amount: o.amount, currency: o.currency, email: o.email, metadata: o.metadata,
            callbackUrl: window.location.origin + '/pricing.html',
          });
        } catch (e) {
          return h.onError((e && e.message) || 'Could not start payment.');
        }
        // remember the charge so the return page can confirm it and go to the dashboard
        try { localStorage.setItem('ve_pending_ref', init.reference); } catch (_) {}
        window.location.href = init.checkoutUrl;   // leave this tab for Cowrie's checkout
      },
    },

    /* ---- Manual / Mobile Money (no SDK) ----
       Uses the "business" field as the payment instructions to show. */
    manual: {
      label: 'Manual / Mobile Money',
      sdk: null,
      async pay(cfg, o, h) {
        const instructions = (cfg.business && cfg.business.trim())
          || 'Send mobile-money payment to the number provided by VirtualPrime.';
        const ref = window.prompt(
          'PAYMENT INSTRUCTIONS\n\n' + instructions +
          '\n\nAmount: ' + o.currency + ' ' + o.amount +
          '\n\nAfter paying, paste the transaction ID / reference you received to confirm:'
        );
        if (ref && ref.trim()) h.onSuccess('MANUAL_' + ref.trim());
        else h.onCancel();
      },
    },
  };

  window.VEPay = {
    /* list of { id, label } for the admin dropdown */
    list: () => Object.keys(GATEWAYS).map((id) => ({ id, label: GATEWAYS[id].label })),
    has: (id) => !!GATEWAYS[id],

    /* pick the gateway from the API key's prefix (keys are self-identifying) */
    providerForKey(key) {
      key = String(key || '');
      if (/^cowrie_/i.test(key)) return 'cowrie';
      if (/^FLWPUBK/i.test(key)) return 'flutterwave';
      return 'paystack';
    },

    async checkout(provider, cfg, opts, handlers) {
      const g = GATEWAYS[provider] || GATEWAYS.paystack;
      handlers = handlers || {};
      // ensure only the first terminal callback wins (some SDKs fire close after success)
      let settled = false;
      const once = (fn) => (...a) => { if (settled) return; settled = true; (fn || function () {})(...a); };
      const h = {
        onSuccess: once(handlers.onSuccess),
        onCancel: once(handlers.onCancel),
        onError: once(handlers.onError),
      };
      try {
        await g.pay(cfg, opts, h);
      } catch (e) {
        h.onError(e && e.message ? e.message : 'Payment could not start.');
      }
    },
  };
})();
