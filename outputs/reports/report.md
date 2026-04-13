# Attack Surface Discovery Report

**Target:** 

**Generated:** 2026-04-13T08:47:09.005Z
**Completeness score:** 90.5%

## Target Summary

- **URL:** https://ginandjuice.shop
- **App type:** Hybrid (confidence 0.65) — React SPA shell with server-rendered shop/blog/account routes.
- **Tech stack:** React (`react.development.js`, `react-dom.development.js`) plus Angular 1.7.7 co-loaded (`angular_1-7-7.js`), served behind a vendor edge (status codes 200/400/403/404 observed with short 15-byte 403 bodies).
- **Auth mechanism:** Cookie/session-based login form at `/login`, triggered from `/my-account` which redirects (302) unauthenticated visitors. No credentials were supplied, so the authenticated attack surface was not exercised.
- **Roles tested:** `unauthenticated` only.
- **Total endpoints discovered:** 83 unique canonicals from 4 sources (active-crawl, passive traffic, fuzzing, JS analysis).
- **Discovery sources used:** active-crawl, traffic, fuzzing, js-analysis.
- **Notable application signals:** the product-detail page loads `stockCheck.js` + `xmlStockCheckPayload.js` (implying an XML-bodied stock-check POST endpoint not exercised this run), `deparam.js` is loaded site-wide (classic query-string parser), and `searchLogger.js` suggests a search feature never reached by the crawler. `subscribeNow.js` implies a newsletter subscribe POST. All flagged — none probed.

### Observations (from phase 8 classification)

- `/my-account` returns **302** unauthenticated — consistent with a redirect to `/login`.
- `/catalog/product` and `/blog/post` return **400** when probed without their `productId` / `postId` query parameters, confirming they are server-validated endpoints rather than pure SPA routes.
- Fuzzing surfaced a cluster of **9 auth-gated** administrative paths (`/admin`, `/admin/login`, `/admin/dashboard`, `/admin/users`, `/admin/settings`, `/admin/logs`) — all returning 403 with a uniform 15-byte body, suggesting a single upstream gate.
- `/analytics` returns **200** with a zero-byte body — likely a beacon/pixel endpoint; worth re-probing with POST and query params during an authenticated follow-up.
- `/favicon.ico` present (15 KB).
- One "spec-ish" response at `/?wsdl` was captured by phase 12 but classified as the SPA shell (ui-page) — not a real WSDL/OpenAPI document.

## Endpoint Inventory

| # | Path | Methods | Sources | Confidence |
|---|------|---------|---------|------------|
| 1 | `/` | GET | active-crawl,traffic | high |
| 2 | `/about` | GET | active-crawl,traffic | high |
| 3 | `/admin` | GET | fuzzing | medium |
| 4 | `/admin/dashboard` | GET | fuzzing | medium |
| 5 | `/admin/login` | GET | fuzzing | medium |
| 6 | `/admin/logs` | GET | fuzzing | medium |
| 7 | `/admin/settings` | GET | fuzzing | medium |
| 8 | `/admin/users` | GET | fuzzing | medium |
| 9 | `/analytics` | GET | fuzzing | medium |
| 10 | `/blog` | GET | active-crawl,traffic | high |
| 11 | `/blog/post` | GET | active-crawl,traffic | high |
| 12 | `/catalog` | GET | active-crawl,traffic | high |
| 13 | `/catalog/cart` | GET | active-crawl,traffic | high |
| 14 | `/catalog/product` | GET | active-crawl,traffic | high |
| 15 | `/favicon.ico` | GET | fuzzing | medium |
| 16 | `/image/scanme/blog/posts/1.jpg` | GET | active-crawl,traffic | high |
| 17 | `/image/scanme/blog/posts/2.jpg` | GET | active-crawl,traffic | high |
| 18 | `/image/scanme/blog/posts/3.jpg` | GET | active-crawl,traffic | high |
| 19 | `/image/scanme/blog/posts/4.jpg` | GET | active-crawl,traffic | high |
| 20 | `/image/scanme/blog/posts/5.jpg` | GET | active-crawl,traffic | high |
| 21 | `/image/scanme/blog/posts/6.jpg` | GET | active-crawl,traffic | high |
| 22 | `/image/scanme/productcatalog/products/1.png` | GET | active-crawl,traffic | high |
| 23 | `/image/scanme/productcatalog/products/10.png` | GET | active-crawl,traffic | high |
| 24 | `/image/scanme/productcatalog/products/11.png` | GET | active-crawl,traffic | high |
| 25 | `/image/scanme/productcatalog/products/12.png` | GET | active-crawl,traffic | high |
| 26 | `/image/scanme/productcatalog/products/2.png` | GET | active-crawl,traffic | high |
| 27 | `/image/scanme/productcatalog/products/3.png` | GET | active-crawl,traffic | high |
| 28 | `/image/scanme/productcatalog/products/4.png` | GET | active-crawl,traffic | high |
| 29 | `/image/scanme/productcatalog/products/5.png` | GET | active-crawl,traffic | high |
| 30 | `/image/scanme/productcatalog/products/6.png` | GET | active-crawl,traffic | high |
| 31 | `/image/scanme/productcatalog/products/7.png` | GET | active-crawl,traffic | high |
| 32 | `/image/scanme/productcatalog/products/8.png` | GET | active-crawl,traffic | high |
| 33 | `/image/scanme/productcatalog/products/9.png` | GET | active-crawl,traffic | high |
| 34 | `/image/scanme/productcatalog/products/batch_1337.png` | GET | active-crawl,traffic | high |
| 35 | `/image/scanme/productcatalog/products/kettle_still.png` | GET | active-crawl,traffic | high |
| 36 | `/image/scanme/productcatalog/products/lost_in_a_heyes.png` | GET | active-crawl,traffic | high |
| 37 | `/image/scanme/productcatalog/products/original_dry_sqli.png` | GET | active-crawl,traffic | high |
| 38 | `/image/scanme/productcatalog/products/pineapple_edition.png` | GET | active-crawl,traffic | high |
| 39 | `/image/scanme/productcatalog/products/purple_hat.png` | GET | active-crawl,traffic | high |
| 40 | `/logger` | GET | js-analysis | medium |
| 41 | `/login` | GET | active-crawl,traffic | high |
| 42 | `/my-account` | GET | active-crawl,traffic | high |
| 43 | `/resources/css/labsBlog.css` | GET | active-crawl,traffic | high |
| 44 | `/resources/css/labsEcommerce.css` | GET | active-crawl,traffic | high |
| 45 | `/resources/css/labsScanme.css` | GET | active-crawl,traffic | high |
| 46 | `/resources/fonts/JosefinSans/JosefinSans-Bold.woff` | GET | active-crawl,traffic | high |
| 47 | `/resources/fonts/Poppins/poppins-bold.woff` | GET | active-crawl,traffic | high |
| 48 | `/resources/fonts/Poppins/poppins.woff` | GET | active-crawl,traffic | high |
| 49 | `/resources/footer/js/scanme.js` | GET | active-crawl,traffic | high |
| 50 | `/resources/images/Portswigger.png` | GET | active-crawl,traffic | high |
| 51 | `/resources/images/avatar.svg` | GET | active-crawl,traffic | high |
| 52 | `/resources/images/batch1337_can.png` | GET | active-crawl,traffic | high |
| 53 | `/resources/images/dark-blue-squiggle-pattern-tile.jpg` | GET | active-crawl,traffic | high |
| 54 | `/resources/images/dry_SQLI_can.png` | GET | active-crawl,traffic | high |
| 55 | `/resources/images/footer_graphic.jpg` | GET | active-crawl,traffic | high |
| 56 | `/resources/images/g_j_bottle.png` | GET | active-crawl,traffic | high |
| 57 | `/resources/images/gin-and-juice-distillery.jpg` | GET | active-crawl,traffic | high |
| 58 | `/resources/images/gin-and-juice-shop-logo.svg` | GET | active-crawl,traffic | high |
| 59 | `/resources/images/gin-and-juice-team.jpg` | GET | active-crawl,traffic | high |
| 60 | `/resources/images/gin-and-juice-team.mp4` | GET | active-crawl,traffic | high |
| 61 | `/resources/images/hero_banner_background1.jpg` | GET | active-crawl,traffic | high |
| 62 | `/resources/images/hero_banner_background2.png` | GET | active-crawl,traffic | high |
| 63 | `/resources/images/heyes_bottle.png` | GET | active-crawl,traffic | high |
| 64 | `/resources/images/icon-account.svg` | GET | active-crawl,traffic | high |
| 65 | `/resources/images/icon-cart.svg` | GET | active-crawl,traffic | high |
| 66 | `/resources/images/icon-search.svg` | GET | active-crawl,traffic | high |
| 67 | `/resources/images/kettle_bottle.png` | GET | active-crawl,traffic | high |
| 68 | `/resources/images/pineapple-can.png` | GET | active-crawl,traffic | high |
| 69 | `/resources/images/rating1.png` | GET | active-crawl,traffic | high |
| 70 | `/resources/images/rating2.png` | GET | active-crawl,traffic | high |
| 71 | `/resources/images/rating3.png` | GET | active-crawl,traffic | high |
| 72 | `/resources/images/rating4.png` | GET | active-crawl,traffic | high |
| 73 | `/resources/images/rating5.png` | GET | active-crawl,traffic | high |
| 74 | `/resources/images/shopping-cart.svg` | GET | active-crawl,traffic | high |
| 75 | `/resources/js/angular_1-7-7.js` | GET | active-crawl,traffic | high |
| 76 | `/resources/js/deparam.js` | GET | active-crawl,traffic | high |
| 77 | `/resources/js/react-dom.development.js` | GET | active-crawl,traffic | high |
| 78 | `/resources/js/react.development.js` | GET | active-crawl,traffic | high |
| 79 | `/resources/js/searchLogger.js` | GET | active-crawl,traffic | high |
| 80 | `/resources/js/stockCheck.js` | GET | active-crawl,traffic | high |
| 81 | `/resources/js/subscribeNow.js` | GET | active-crawl,traffic | high |
| 82 | `/resources/js/xmlStockCheckPayload.js` | GET | active-crawl,traffic | high |
| 83 | `/resources/labheader/css/scanMeHeader.css` | GET | active-crawl,traffic | high |


## Role-Based Access Map

| Path | unauthenticated |
|---|---|
| `/` | 200 |
| `/about` | 200 |
| `/blog` | 200 |
| `/blog/post` | 400 |
| `/catalog` | 200 |
| `/catalog/cart` | 200 |
| `/catalog/product` | 400 |
| `/image/scanme/blog/posts/1.jpg` | 200 |
| `/image/scanme/blog/posts/2.jpg` | 200 |
| `/image/scanme/blog/posts/3.jpg` | 200 |
| `/image/scanme/blog/posts/4.jpg` | 200 |
| `/image/scanme/blog/posts/5.jpg` | 200 |
| `/image/scanme/blog/posts/6.jpg` | 200 |
| `/image/scanme/productcatalog/products/1.png` | 200 |
| `/image/scanme/productcatalog/products/10.png` | 200 |
| `/image/scanme/productcatalog/products/11.png` | 200 |
| `/image/scanme/productcatalog/products/12.png` | 200 |
| `/image/scanme/productcatalog/products/2.png` | 200 |
| `/image/scanme/productcatalog/products/3.png` | 200 |
| `/image/scanme/productcatalog/products/4.png` | 200 |
| `/image/scanme/productcatalog/products/5.png` | 200 |
| `/image/scanme/productcatalog/products/6.png` | 200 |
| `/image/scanme/productcatalog/products/7.png` | 200 |
| `/image/scanme/productcatalog/products/8.png` | 200 |
| `/image/scanme/productcatalog/products/9.png` | 200 |
| `/image/scanme/productcatalog/products/batch_1337.png` | 200 |
| `/image/scanme/productcatalog/products/kettle_still.png` | 200 |
| `/image/scanme/productcatalog/products/lost_in_a_heyes.png` | 200 |
| `/image/scanme/productcatalog/products/original_dry_sqli.png` | 200 |
| `/image/scanme/productcatalog/products/pineapple_edition.png` | 200 |
| `/image/scanme/productcatalog/products/purple_hat.png` | 200 |
| `/login` | 200 |
| `/my-account` | 302 |
| `/resources/css/labsBlog.css` | 200 |
| `/resources/css/labsEcommerce.css` | 200 |
| `/resources/css/labsScanme.css` | 200 |
| `/resources/fonts/JosefinSans/JosefinSans-Bold.woff` | 200 |
| `/resources/fonts/Poppins/poppins-bold.woff` | 200 |
| `/resources/fonts/Poppins/poppins.woff` | 200 |
| `/resources/footer/js/scanme.js` | 200 |
| `/resources/images/Portswigger.png` | 200 |
| `/resources/images/avatar.svg` | 200 |
| `/resources/images/batch1337_can.png` | 200 |
| `/resources/images/dark-blue-squiggle-pattern-tile.jpg` | 200 |
| `/resources/images/dry_SQLI_can.png` | 200 |
| `/resources/images/footer_graphic.jpg` | 200 |
| `/resources/images/g_j_bottle.png` | 200 |
| `/resources/images/gin-and-juice-distillery.jpg` | 200 |
| `/resources/images/gin-and-juice-shop-logo.svg` | 200 |
| `/resources/images/gin-and-juice-team.jpg` | 200 |
| `/resources/images/gin-and-juice-team.mp4` | 200 |
| `/resources/images/hero_banner_background1.jpg` | 200 |
| `/resources/images/hero_banner_background2.png` | 200 |
| `/resources/images/heyes_bottle.png` | 200 |
| `/resources/images/icon-account.svg` | 200 |
| `/resources/images/icon-cart.svg` | 200 |
| `/resources/images/icon-search.svg` | 200 |
| `/resources/images/kettle_bottle.png` | 200 |
| `/resources/images/pineapple-can.png` | 200 |
| `/resources/images/rating1.png` | 200 |
| `/resources/images/rating2.png` | 200 |
| `/resources/images/rating3.png` | 200 |
| `/resources/images/rating4.png` | 200 |
| `/resources/images/rating5.png` | 200 |
| `/resources/images/shopping-cart.svg` | 200 |
| `/resources/js/angular_1-7-7.js` | 200 |
| `/resources/js/deparam.js` | 200 |
| `/resources/js/react-dom.development.js` | 200 |
| `/resources/js/react.development.js` | 200 |
| `/resources/js/searchLogger.js` | 200 |
| `/resources/js/stockCheck.js` | 200 |
| `/resources/js/subscribeNow.js` | 200 |
| `/resources/js/xmlStockCheckPayload.js` | 200 |
| `/resources/labheader/css/scanMeHeader.css` | 200 |


## Application Flows

### Landing → Catalog browse → Product detail

_Public e-commerce discovery path: homepage listing takes visitor to full catalog and then to a single product page (productId query parameter)._

1. `GET /` (as unauthenticated)
2. `GET /catalog` (as unauthenticated)
3. `GET /catalog/product` (as unauthenticated)

### Blog browse → Post view

_Content-marketing path: index page lists posts, detail page loads a single post by postId._

1. `GET /blog` (as unauthenticated)
2. `GET /blog/post` (as unauthenticated)

### Cart view (unauthenticated)

_Visitor navigates to cart without having added items or logged in; page rendered without server-side order creation being observed._

1. `GET /catalog` (as unauthenticated)
2. `GET /catalog/cart` (as unauthenticated)

### Account entry / login form render

_Clicking the account icon exposes /my-account which in turn presents /login. No credentials were supplied so the form submission step was not exercised._

1. `GET /my-account` (as unauthenticated)
2. `GET /login` (as unauthenticated)

### About / static content

_Marketing-team about page with inline video and images — no dynamic behaviour observed._

1. `GET /` (as unauthenticated)
2. `GET /about` (as unauthenticated)

## JavaScript Analysis

- Files analyzed: 9
- Endpoints extracted from JS: 1
- Secrets/leaks flagged: **0**

_No secrets detected._

## Historical & Fuzzing

- **Wayback:** 0 historical paths retrieved; 0 still respond on the live target.
- **Predictive fuzzing:** 164 paths tested, 2 new hits, 9 auth-gated.

## Response Fingerprints

- **200:** 1 samples, typical length 7492 bytes
- **403:** 1 samples, typical length 15 bytes
- **404:** 8 samples, typical length 7349 bytes

## Limitations & Gaps

- **No credentials supplied.** The run was fully unauthenticated. Authenticated-only surface (account pages, cart mutation, order history, admin paths) was not probed beyond status-code gating. `credentials.json` was cleared at runtime because the pre-shipped values pointed at a local juice-shop dev instance (http://localhost:3000) that was irrelevant to this target. To expand coverage, provide login creds for at least one shopper role and rerun phase 6 onward.
- **Wayback Machine query aborted.** `phase9-wayback.js` timed out against web.archive.org's CDX API (see `output/gates/gate9.json` — warning: "This operation was aborted"). Zero historical paths were retrieved; do not interpret this as evidence the target has no archival footprint.
- **No POST/write flows exercised.** The crawler is GET-only for discovery; observed JS (`xmlStockCheckPayload.js`, `subscribeNow.js`, `searchLogger.js`) strongly implies POST handlers for stock check, newsletter subscribe, and search logging exist but were not hit. Listed in `phase16_flows.json.inferredButNotExercised`.
- **API spec discovery inconclusive.** Phase 12 flagged `/?wsdl` as 200 but it's the SPA HTML shell, not a spec. No OpenAPI / Swagger / GraphQL introspection endpoint was confirmed.
- **Parameter classification is thin.** Only 2 query parameters observed (`productId`, `postId`) because dynamic interactions (search, add-to-cart, subscribe) were never fired; `phase14_params.json` reflects this.
- **Search feature unmapped.** `searchLogger.js` is loaded but no `/search` or `/catalog/search` endpoint was observed or responded to fuzzing hits; likely gated behind a UI event the crawler didn't fire.
- **Heroku/vendor edge 503 on canonical juice-shop.** The originally-requested `juice-shop.herokuapp.com` target returned 503 from Heroku's router (see note under Phase 1 history in artifacts); switched to the user-confirmed live target `ginandjuice.shop` before any substantive discovery ran.

## Final Judge Verdict

- **Verdict:** `CONDITIONAL_PASS` (mechanical judge — see `output/reports/final-judge.json`).
- **Gates:** 16 recorded; 15 PASS, 1 WARN (phase 9 Wayback timeout), 0 FAIL.
- **Recommended actions (MEDIUM):**
  - *Missing discovery sources: `api-spec`, `wayback`.* Both contributed zero endpoints. The api-spec miss is a genuine null result (no Swagger/OpenAPI/GraphQL endpoint responded on probe paths). The Wayback miss is a soft failure (CDX API aborted). These are documented above in Limitations; no rerun was executed because the conditions are explained and the MEDIUM priority does not trigger an automatic rerun per the skill's rules.

---

_Report generated by attack-surface-discovery skill. Every finding traceable to its phase artifact under `output/artifacts/`._
