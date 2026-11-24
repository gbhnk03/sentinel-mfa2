import { json } from "./_shared.mjs";
export const handler = async () => json(200, { siteKey: process.env.TURNSTILE_SITE_KEY || "" });
