# Virtual Oracle

SportyBet Instant Virtual Football predictions. Static front-end (`public/`) served by a
Node/Express API, backed by PostgreSQL. Built to deploy on **Render**.

## What changed (localStorage → real backend)

Data that used to live in each browser's `localStorage` now lives in Postgres, so members,
partners and the admin all see the same data across devices:

| Old localStorage key | Now |
|---|---|
| `ve_users`          | `users` table + `/api/auth/*`, `/api/me` |
| `ve_partners`       | `partners` table + `/api/partner/*`, `/api/admin/partners` |
| `ve_pushed`         | `pushed_picks` table + `/api/*/picks` |
| `ve_purchases`      | `purchases` table |
| `ve_credits`        | `credits` table |
| `ve_payment_config` | `payment_config` table |
| `ve_session` / `ve_partner_session` / `ve_admin_ok` | JWT tokens (see `public/api.js`) |

Passwords are now hashed with bcrypt (not `btoa`). Auth is JWT-based.

## Local development

```bash
npm install
cp .env.example .env      # then edit DATABASE_URL etc.
npm run initdb            # create tables (optional; server also does this on boot)
npm start                 # http://localhost:3000
```

You need a Postgres database. Easiest is to create the free Render database first and put its
**External** connection string in `.env` (set `DATABASE_SSL=on` for the Render DB).

## Deploy to Render (Blueprint — easiest)

1. Push this folder to a new **GitHub** repo.
2. In Render: **New → Blueprint**, select the repo. `render.yaml` provisions:
   - a **Web Service** (`virtualedge`)
   - a **PostgreSQL** database (`virtualedge-db`), auto-wired via `DATABASE_URL`
   - `JWT_SECRET` (auto-generated)
3. Set **`ADMIN_PASSCODE`** in the web service's *Environment* tab (it's `sync:false`).
4. Deploy. Tables are created automatically on first boot.

### Or wire it up manually

1. **New → PostgreSQL** (free). Copy the *Internal* connection string.
2. **New → Web Service** from the repo. Build: `npm install`, Start: `npm start`.
3. Add env vars: `DATABASE_URL` (the internal string), `JWT_SECRET` (long random),
   `ADMIN_PASSCODE`, `DATABASE_SSL=on`.

## Security notes (read before going public)

- **Gemini API key** is still hardcoded client-side in the dashboard/partner/admin pages.
  Restrict it by HTTP referrer in Google AI Studio before launch, or proxy it through the server.
- **Paystack secret key** must never reach the browser — only the public key is sent via
  `/api/payment-config/public`. The secret stays in the `payment_config` table / server.
- `ADMIN_PASSCODE`, `JWT_SECRET`, `DATABASE_URL` live in environment variables — never commit `.env`.
- Server source files are **not** in `public/`, so they are never served to the browser.

## API surface

Auth: `POST /api/auth/register|login`, `POST /api/partner/register|login`, `POST /api/admin/login`.
Member: `GET /api/me`, `GET /api/me/picks`, `POST /api/me/picks/:id/consume`, `POST /api/me/purchases`, `POST /api/me/credits/spend`.
Partner: `GET /api/partner/me|referrals|picks`, `POST /api/partner/picks`, `DELETE /api/partner/picks/:id`, `GET /api/accounts`.
Admin: `GET /api/admin/users|partners|purchases|picks|stats|payment-config`, `POST /api/admin/partners|picks`, `PATCH /api/admin/partners/:id`, `DELETE /api/admin/partners/:id|picks/:id`, `PUT /api/admin/payment-config`.
Public: `GET /api/payment-config/public`.
