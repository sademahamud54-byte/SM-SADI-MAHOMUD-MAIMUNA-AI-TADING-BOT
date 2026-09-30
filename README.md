<div align="center">
<img width="1200" height="475" alt="GHBanner" src="https://ai.google.dev/static/site-assets/images/share-ais-513315318.png" />
</div>

# Run and deploy your AI Studio app

This contains everything you need to run your app locally.

View your app in AI Studio: https://ai.studio/apps/4ebedd8f-44ec-4295-905c-72ec4c0bb346

## Run Locally

**Prerequisites:**  Node.js


1. Install dependencies:
   `npm install`
2. Set the `GEMINI_API_KEY` in [.env.local](.env.local) to your Gemini API key
3. Run the app:
   `npm run dev`

## Cloudflare Pages deployment

The project is a Vite + React + TypeScript application, so Cloudflare’s **Upload your static files**
screen cannot accept the source tree directly. Build it first and upload `dist/`, or connect the repo
to Pages with build command `npm run build` and output directory `dist`. See `CLOUDFLARE_DEPLOY.md`.

The frontend supports `VITE_API_BASE_URL` for the Node/Express API. The Express API itself must run
on a Node-compatible backend host unless you separately port it to Cloudflare Workers.
