# Hunt report — prism_vdp (f_8bbd7a)

## Executive summary

Initial VPS `/secrets` job (j_4ccb5948) returned **0 hits** because wildcard scope entries were fed literally as hostnames (`http://*.oyorooms.com` → DNS failure). Follow-on live recon against resolved in-scope assets found **actionable leads on Weddingz and CheckIn**, with Belvilla staging as a strong secondary target.

Top signals: (1) **`weddingz.in/private_apis/`** responds publicly with a debug JSON message and issues Django session cookies; sibling paths `/health` and `/env` throw **500 errors**. (2) **`www.checkin.life`** ships a full **Firebase Identity Toolkit** config in JS; unauthenticated signup succeeds (account-creation abuse vector). (3) The same bundle exposes **30+ `/api/pwa/*` booking/auth endpoints** (`updateUserProfile`, `shortlisted-hotels-list`, etc.) against `api.oyorooms.com` — prime IDOR/BOLA targets once reachable (Akamai blocked direct VPS POSTs). No confirmed critical vuln yet; Weddingz private API fuzzing and CheckIn API authz testing are the highest-ROI next steps.

## Findings

### [LIKELY] Weddingz `/private_apis/` debug endpoint exposed on production

- Asset: `https://weddingz.in/private_apis/` (*.weddingz.in)
- Type: Information disclosure / misconfiguration (debug or internal route on public host)
- Evidence:
  - `GET https://weddingz.in/private_apis/` → `200 application/json`:
    ```json
    {"message": "This thing should be working some how", "data": "Hope this works out like a charm"}
    ```
  - Response sets cookies: `sessionid=…`, `is_superuser=False`, `django_language=en-us` (Django backend fingerprint).
  - CSP on `www.weddingz.in` references `/private_apis/content-security-violation/` as report-uri — confirms intentional but non-public API surface.
  - `/private_apis/health` and `/private_apis/env` return **500 Internal Server Error** (Akamai/origin misconfig).
- Impact: Confirms hidden Django API plane on the public site; debug messaging + session issuance may aid session-fixation or further private-route discovery. `/env` path name suggests possible configuration leak if error verbosity increases.
- Reproduction steps:
  1. `curl -sL 'https://weddingz.in/private_apis/'`
  2. Observe JSON debug body and `Set-Cookie: sessionid=…`
  3. `curl -sI 'https://weddingz.in/private_apis/health'` → 500
  4. `curl -sI 'https://weddingz.in/private_apis/env'` → 500
- Remediation: Remove or auth-gate all `/private_apis/*` routes on production; disable debug handlers; ensure `/env` and `/health` are internal-only.

### [LIKELY] CheckIn client bundle exposes Firebase project + open Identity Toolkit signup

- Asset: `https://www.checkin.life/assets/desktop/main.207009ff17c2044cc73f.js` (*.checkin.life)
- Type: Sensitive config disclosure / authentication misconfiguration
- Evidence:
  - Firebase config in JS:
    - `apiKey: AIzaSyBJDXVdaokDyBkVvkoGcABtrKYaCZ6zvo8`
    - `authDomain: oyo-consumer-web.firebaseapp.com`
    - `projectId: oyo-consumer-web`
    - `storageBucket: oyo-consumer-web.appspot.com`
    - `messagingSenderId: 926223673013`
    - `appId: 1:926223673013:web:57ab5c8973969e61ba00fc`
  - `POST https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=AIzaSyBJDXVdaokDyBkVvkoGcABtrKYaCZ6zvo8` with test credentials returned `identitytoolkit#SignupNewUserResponse` + `idToken` (unauthenticated account creation).
  - Realtime DB probe `https://oyo-consumer-web.firebaseio.com/.json` → `Permission denied` (rules present).
  - Additional Google keys in same bundle (Maps/payment): `AIzaSyCkH-mi0xne1VRcIfksoxjE-HlC9JIbtm0`, `AIzaSyAvWRcjrPIhvbj9KZSFVNQnojiPK3WdKYo` — geocode API returns referer-restriction error (lower risk).
- Impact: Mass account creation / quota burn / auth-flow abuse; if Firestore/Storage rules or Cloud Functions trust client-side auth alone, could chain to data access. Maps keys may allow billing abuse if other Google APIs lack matching restrictions.
- Reproduction steps:
  1. Download `https://www.checkin.life/assets/desktop/main.207009ff17c2044cc73f.js` and search for `oyo-consumer-web`.
  2. POST to Identity Toolkit signup endpoint with the embedded `apiKey`.
  3. Confirm `idToken` issued without email verification gate.
  4. Optionally probe Firestore/Storage with returned token per Firebase rules testing methodology.
- Remediation: Enable email verification / CAPTCHA / rate limits on signup; restrict API key to referrers; audit Firestore/Storage/Functions rules; rotate keys if abuse detected.

### [HYPOTHESIS] CheckIn/OYO PWA API surface — IDOR & authz on booking/user endpoints

- Asset: `https://api.oyorooms.com/api/pwa/*` (called from *.checkin.life / *.oyorooms.com frontends)
- Type: Broken object-level authorization (BOLA/IDOR), auth bypass
- Evidence:
  - Paths extracted from CheckIn `main.*.js`:
    - `/api/pwa/authenticate`, `/authenticateV2`, `/authenticateV3`
    - `/api/pwa/updateUserProfile`, `/forgotPassword`, `/resetPassword`, `/signup`
    - `/api/pwa/shortlisted-hotels-list`, `/shortlisthotel`
    - `/api/pwa/bookingPropertMeta`, `/checkHotelAvailability`, `/bookingCancellationReasons/`
    - `/api/pwa/yoImageUpload`, `/referral/deeplink`, `/validate-wizard-coupon`
  - Custom headers in bundle: `Authorization`, `X-OYO-ORIGIN`, `X-TENANT-ID` (tenant header spoofing candidate).
  - Direct VPS POSTs to `api.oyorooms.com` returned Akamai **“DNS failure / Service Unavailable”** — likely geo/WAF; browser/residential egress may succeed.
- Impact: Cross-user profile read/write, booking enumeration, password-reset abuse, image upload → stored XSS or SSRF if insufficient validation.
- Reproduction steps:
  1. Intercept CheckIn login/booking flow in browser Burp (scope: checkin.life).
  2. Capture authenticated calls to `/api/pwa/updateUserProfile` and `/api/pwa/shortlisted-hotels-list`.
  3. Replay with another user's `userId` / booking ID; test without `Authorization`.
  4. Fuzz `X-TENANT-ID` / `X-OYO-ORIGIN` for cross-tenant access (CheckIn vs OYO vs Belvilla tenants in same bundle).
- Remediation: Server-side object ownership checks on all `/api/pwa/*`; bind tenant to token, not client header; rate-limit auth endpoints.

### [HYPOTHESIS] Weddingz unauthenticated DRF API — enquiry/venue data endpoints

- Asset: `https://weddingz.in/api/v1/venues/event-details/` (*.weddingz.in)
- Type: API misconfiguration / potential IDOR (needs authenticated enquiry context)
- Evidence:
  - `GET` → `{"detail":"Method \"GET\" not allowed."}` (Django REST Framework)
  - `POST {}` → `{"message":"Enquiry id must be passed.","success":false}`
  - `POST {"enquiry_id":1,...}` → validation errors requiring `city`, `locality`, `event_type`, `event_date`, `no_of_guests` (endpoint live without auth).
  - Separate host `api.weddingz.in` banner: `Weddingz Content Service - Server is up!` (Spring Boot).
  - JS also references `/api/v2/video/` (404/Not found on prod).
- Impact: If enquiry IDs are predictable or returned elsewhere, POST may leak venue/event PII for other users' enquiries; spam/abuse on open POST.
- Reproduction steps:
  1. `curl -X POST 'https://weddingz.in/api/v1/venues/event-details/' -H 'Content-Type: application/json' -d '{}'`
  2. Create a legitimate enquiry via UI; capture real `enquiry_id`.
  3. Replay POST from unauthenticated session with victim `enquiry_id`.
  4. Parallel: fuzz `api.weddingz.in` with wordlist (`/api/v1/`, `/content-service/`) — actuator `/env` returns 403, `/health` returns 500.
- Remediation: Require auth on enquiry-scoped endpoints; use non-enumerable enquiry tokens; disable Spring actuator paths on public LB.

### [HYPOTHESIS] Belvilla acceptance environment & permissive CORS on consumer site

- Asset: `https://acc-rental.belvilla.com/`, `https://www.belvilla.com/` (*.belvilla.com — use designated test properties per program policy)
- Type: Staging exposure / CORS misconfiguration
- Evidence:
  - `acc-rental.belvilla.com` resolves and redirects to `/login` (acceptance/staging rental portal).
  - CSP `connect-src` on rental portal includes hardcoded **`http://35.190.115.57`** and internal hostnames (`acc-howa.belvilla.com`, `sentry.oyorooms.io`).
  - `www.belvilla.com` responds with **`Access-Control-Allow-Origin: *`** and `Access-Control-Allow-Headers: *` (confirmed with `Origin: https://evil.example`).
  - Program scope note: must use **designated test property** for Belvilla booking tests.
- Impact: Staging may run weaker auth or expose pre-production APIs; wildcard CORS on main site dangerous if any authenticated JSON endpoints share origin policy.
- Reproduction steps:
  1. `curl -sI 'https://acc-rental.belvilla.com/'` — note redirect to login.
  2. `curl -sI -H 'Origin: https://evil.example' 'https://www.belvilla.com/'` — observe `access-control-allow-origin: *`.
  3. Log into acc-rental with test credentials (if available); diff API calls vs prod `rental.belvilla.com`.
  4. Map leisure CDN JS (`cdn2.leisure-nb.net`) for `/api/` paths.
- Remediation: Restrict CORS to required origins; remove raw IP from CSP; VPN/IP-restrict acceptance hosts.

### [HYPOTHESIS] Internal OYO infrastructure subdomains discoverable

- Asset: `staging.oyorooms.io`, `cms.oyorooms.io`, `partner.oyorooms.io`, `sso.oyorooms.io`, `sentry.oyorooms.io`, `securesentry.oyorooms.io` (*.oyorooms.io)
- Type: Attack surface expansion / staging exposure
- Evidence:
  - `staging.oyorooms.io` → `staging-oyorooms-lb-paloalto-662957564.ap-southeast-1.elb.amazonaws.com` (AWS ELB, no HTTP response from VPS).
  - `cms.oyorooms.io` → `cms-service-api.cee.oyorooms.io`.
  - `sentry.oyorooms.io` → `zp-common-internal.oyorooms.io` (naming leaks internal zone).
  - `partner.oyorooms.com` → 302 to `patron.oyorooms.com` (partner portal).
  - `patron.oyorooms.com` → **403** from VPS (Akamai admin rules); `sso.oyorooms.com` → custom 500 “Sign-In Issue” page (Microsoft OAuth).
  - `analytics.oyorooms.com` → 403 `length: 11`.
- Impact: Staging/internal hosts often carry default creds, debug modes, or unpatched services → RCE/auth bypass if exposed.
- Reproduction steps:
  1. Resolve subdomains via passive DNS / `subfinder` against in-scope wildcards.
  2. `nmap -sV -p 443,80,8080,8443 staging.oyorooms.io cms.oyorooms.io`.
  3. Browser-test `patron.oyorooms.com` with residential IP + partner test account.
  4. Probe `sso.checkin.life` / `sso.oyorooms.com` OAuth redirect_uri manipulation (stay in scope).
- Remediation: Remove public DNS for internal names; IP-allowlist staging; uniform WAF on partner portals.

## Dead ends / ruled out

| Item | Result |
|------|--------|
| Initial `/secrets` j_4ccb5948 (23 seeds) | **0 hits** — wildcards (`http://*.oyorooms.com`) and Play Store labels used as URLs → DNS failures; only ~80 pages from resolvable seeds (likely prismlife, app store pages, checkin). |
| `prismlife.com` | Static S3/CloudFront marketing site; no API/JS attack surface beyond third-party links. |
| `api.oyorooms.com/swagger*` | HTTP 200 but **empty HTML** (Akamai placeholder, not real Swagger UI). |
| Google Maps keys (`AIzaSyCk…`, `AIzaSyAv…`) | Geocode API returns **referer restriction** error — not keyless abusable from VPS. |
| Firebase Realtime DB | `/.json` → **Permission denied** — rules block unauth read. |
| `api.oyorooms.com` POST from VPS | **Akamai DNS failure** — blocked for automated testing; use browser egress. |
| `partner.oyorooms.io` / `staging.oyorooms.io` | Timeout / no HTTP response from VPS (may need different network path). |
| `motel6.com` / `g6hospitality.com` | Minimal/no JS API leakage from homepage fetch; defer to dedicated crawl. |
| Mobile apps (`com.oyo.*`, Weddingz, Co-OYO) | Not yet decompiled — APK/IPA static analysis pending. |

## Recommended next VPS commands

```bash
# Re-run secrets with RESOLVED hosts (not wildcards)
/secrets f_8bbd7a
# Manual seed override example for operator:
# https://www.checkin.life/, https://business.checkin.life/, https://weddingz.in/,
# https://api.weddingz.in/, https://www.belvilla.com/, https://acc-rental.belvilla.com/,
# https://www.oyorooms.com/, https://patron.oyorooms.com/, https://www.innov8.work/

# Port/service discovery on discovered infra hosts
/nmap f_8bbd7a
# Targets: staging.oyorooms.io, cms.oyorooms.io, api.weddingz.in, securesentry.oyorooms.io,
#          acc-rental.belvilla.com, sso.oyorooms.com, partner.oyorooms.io

# Webserver misconfig / exposed paths on highest-signal hosts
/nikto f_8bbd7a
# Targets: weddingz.in (esp. /private_apis/, /admin/, /accounts/), acc-rental.belvilla.com

# Deep fuzz + authz testing (browser-assisted)
/ai_resume f_8bbd7a Fuzz weddingz.in/private_apis/* and /api/v1/*; Burp-checkin /api/pwa IDOR on updateUserProfile + shortlisted-hotels-list with test booking only

# Subdomain enumeration (wildcard scope expansion)
/ai_resume f_8bbd7a Run subfinder/amass on oyorooms.com, checkin.life, oyorooms.io, weddingz.in, belvilla.com; feed new hosts to /secrets

# Mobile (out of band)
# apkeep/apkmirror: com.oyo.consumer, com.oyo.partnerapp, com.weddingz.consumer → jadx for hardcoded keys/APIs
```

## Telegram brief

```
PRISM (f_8bbd7a) — hunt update

Initial /secrets: 0 hits (wildcards fed as literal URLs → DNS fail). Recon on live hosts found leads:

🔶 LIKELY — weddingz.in/private_apis/ returns 200 JSON debug msg ("This thing should be working...") + Django sessionid cookie. /private_apis/health & /env → 500. Hidden API plane on prod.

🔶 LIKELY — checkin.life JS leaks full Firebase config (oyo-consumer-web). Identity Toolkit signup works unauthenticated (idToken returned). RTDB rules deny anon read. Test Firestore/Storage + signup abuse.

🔷 HYPOTHESIS — checkin.life exposes 30+ api.oyorooms.com/api/pwa/* endpoints (updateUserProfile, shortlisted-hotels-list, yoImageUpload). Custom X-TENANT-ID header. VPS blocked by Akamai — test IDOR in browser/Burp.

🔷 HYPOTHESIS — weddingz.in POST /api/v1/venues/event-details/ live without auth (needs enquiry_id). api.weddingz.in Spring Boot banner exposed.

🔷 HYPOTHESIS — acc-rental.belvilla.com (staging) live; www.belvilla.com CORS *. CSP leaks IP 35.190.115.57. Use designated test property only.

🔷 HYPOTHESIS — staging.oyorooms.io, cms.oyorooms.io, sentry→zp-common-internal.oyorooms.io. patron.oyorooms.com 403 from VPS.

Next: /nmap f_8bbd7a, /secrets with resolved subdomains, /nikto weddingz+acc-rental, /ai_resume fuzz private_apis + CheckIn API authz. APK jadx for com.oyo.*.
```
