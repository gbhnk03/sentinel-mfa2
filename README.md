# Sentinel MFA Lab — Email verification (Resend)

This is the email-based version of the Sentinel educational MFA demo. A visitor creates a temporary demo username and password in the browser, then receives a six-digit code at their email address. The server generates the code, stores only an HMAC digest in Upstash Redis, sends the code using Resend, and checks it server-side.

## Included protections
- Six-digit random code, five-minute server-side expiry, single use.
- Server-side HMAC digest only; the plaintext code is never stored in Redis or logged.
- Atomic Redis verification and deletion; five incorrect code attempts invalidate the code.
- Cloudflare Turnstile validation with hostname allowlisting.
- Upstash Redis rate limits by hashed email address and IP, plus configurable global daily/monthly email caps (defaults: 100/day and 3,000/month).
- E-mail syntax validation, no-store responses, and fail-closed configuration.

**Important educational limitation:** the first-factor username/password is a local-only demonstration and is not sent to the server or validated against a real account. The dashboard is front-end demo content, not a protected authenticated session. Do not use this project to protect real accounts or sensitive data without replacing the first factor and session architecture with a proper backend identity system.

## What you need
1. A free Resend account and API key.
2. A domain you own, added and verified in Resend, for a public website sending to arbitrary visitor addresses. Set `EMAIL_FROM` to an address at that verified domain. Without a domain, you can still build and preview the site, but public email delivery is not ready. Resend's onboarding sender is for limited testing, not public arbitrary recipients.
3. A free Cloudflare Turnstile site + secret key.
4. An Upstash Redis database with REST URL and token.
5. A Netlify account connected to a Git repository (or deploy with Netlify CLI). This uses Netlify Functions; a static drag-and-drop upload alone will not run the backend functions.

## Deploy
1. Upload this complete folder to a GitHub repository.
2. In Netlify, choose **Add new site → Import an existing project** and connect the repository. Use publish directory `.` and no build command.
3. Add the variables from `.env.example` in **Site configuration → Environment variables**.
4. In `ALLOWED_HOSTNAMES`, list the exact deployed hostnames, comma-separated, without `https://` or paths.
5. Set `EMAIL_FROM` to a sender at the domain verified in Resend. Keep `RESEND_API_KEY`, `OTP_HMAC_SECRET`, Turnstile secret, and Upstash token private. Never put them in `index.html`.
6. Redeploy after adding variables. Test first with your own email address.

Generate `OTP_HMAC_SECRET` using a password manager or a cryptographically secure random generator; it must be at least 32 characters. Do not reuse an API key as this secret.

## Cost notes
Resend has a free tier with a monthly and daily send allowance, subject to its current plan limits. A domain name may cost money, and domain registration/renewal is separate from email sending. Cloudflare Turnstile and Upstash also have free tiers with limits. Check each provider's current terms and pricing before public launch.

## Endpoints
- `GET /.netlify/functions/mfa-config` — returns the public Turnstile site key.
- `POST /.netlify/functions/mfa-start` — `{ "email": "visitor@example.com", "turnstileToken": "..." }`.
- `POST /.netlify/functions/mfa-check` — `{ "email": "visitor@example.com", "code": "123456", "turnstileToken": "..." }`.

## Privacy checklist
Publish a privacy notice naming the site operator and providers (Resend, Netlify, Cloudflare, Upstash), explaining the purpose of email verification, what data is processed, retention, and a contact method. Obtain any consent required for your audience and jurisdiction.


## Security-question layer (educational only)
The demo randomly selects three preset security questions whenever the visitor reaches the question step; visitors cannot choose which questions appear. Any non-empty answer is accepted, so visitors can explore the full flow without knowing predetermined answers. The question step is intentionally illustrative and does not validate identity. The username/password demo profile is stored in that browser's localStorage. Clearing browser site data, using another browser/device, or private browsing removes/isolates the demo profile. This is deliberately a client-side educational simulation, not a secure identity provider. Do not use the question step or local browser account data for real authentication. For real accounts, move enrollment, password verification, lockouts, and session issuance to a trusted backend; security questions are not recommended as a production MFA factor.
