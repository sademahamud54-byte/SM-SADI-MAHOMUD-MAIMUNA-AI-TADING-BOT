# Cloudflare deployment — fixes the “TypeScript / build process” uploader error

The Cloudflare **Upload your static files** screen shown in the video is a static-file uploader.
It cannot compile this Vite + React + TypeScript source tree. Do **not** upload the project root
(`src/`, `*.tsx`, `*.ts`, `package.json`) to that screen.

## Option A — Cloudflare Pages connected to Git (recommended)

- Framework preset: **Vite**
- Build command: `npm run build`
- Build output directory: `dist`
- Node version: 22 (or the version used by your CI environment)
- Environment variable: `VITE_API_BASE_URL=https://YOUR-BACKEND-DOMAIN`

The existing Node/Express API in `server.ts` must be hosted on a Node-compatible service such as
Render/Koyeb/a VPS. Set its `APP_ORIGIN` to the exact Cloudflare Pages URL.

## Option B — Cloudflare dashboard “Upload your static files”

Build the project first on a machine with Node.js/npm:

```bash
npm install
npm run build
```

Then open Cloudflare Pages -> **Upload your static files** and upload the **contents of `dist/`**,
not the source project. The warning about TypeScript/build processing will then be gone because
Cloudflare receives already-built HTML/CSS/JavaScript assets.

## Option C — Wrangler

From the project root:

```bash
npm install
npm run deploy:cloudflare
```

Or explicitly:

```bash
npm run build
npx wrangler pages deploy dist
```

`wrangler.toml` is included in this project.

## Important API note

Cloudflare Pages static hosting does **not** execute the Express `server.ts`. The frontend has been
updated to support `VITE_API_BASE_URL`, so it can call the separate Node API without changing every
`fetch()` call. If the frontend and API are on the same origin, leave `VITE_API_BASE_URL` empty.

Do not put Gemini, Telegram bot, JWT, AES, or other server secrets in `VITE_*` variables; Vite embeds
`VITE_*` values into browser JavaScript.
