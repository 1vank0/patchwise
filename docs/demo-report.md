# Patchwise report

Repo: `/workspace/moneymaker/hackathon/patchwise/demo/statuspage` · mode: **online** · 6 pinned deps · 32 advisories · 86.5s

**6 fix now · 1 need review · 25 not exploitable here**

Nemotron on Nebius Token Factory: 68 calls, 64,156 in / 30,485 out tokens, **$0.0492**. Tavily calls: 35.

## Fix now (6)

### pyyaml 5.3.1 — GHSA-8q59-q68h-6hv4 (CRITICAL)
Improper Input Validation in PyYAML  
Fix: upgrade to **5.4** · Verdict: **reachable** (95%)  
Why: The code imports yaml and calls yaml.load with Loader=yaml.FullLoader on raw input from customer-uploaded YAML (statuspage/config.py:7). This matches the trigger condition for GHSA-8q59-q68h-6hv4: processing untrusted YAML with FullLoader before PyYAML 5.4 allows RCE via python/object/new constructor.  
Vulnerable code: `yaml.load, yaml.FullLoader, yaml.safe_load, yaml.SafeLoader`

`statuspage/config.py:7`
```
   5| def load_tenant_config(raw: str) -> dict:
   6|     # Customers upload this file; we need custom tags for !env lookups.
   7|     return yaml.load(raw, Loader=yaml.FullLoader)
   8| 
   9| 
```

Sources: https://github.com/advisories/GHSA-8q59-q68h-6hv4

### pyjwt 1.7.1 — GHSA-752w-5fwx-jx9f (HIGH)
PyJWT accepts unknown `crit` header extensions  
Fix: upgrade to **2.14.0** · Verdict: **reachable** (90%)  
Why: The code calls jwt.decode at statuspage/auth.py:15 with a static secret known to attackers. An attacker can forge a JWS token containing a 'crit' header with an unsupported extension, sign it with HS256 using the known secret, and pass it to verify_admin_token, causing jwt.decode to accept the token without raising InvalidTokenError per GHSA-752w-5fwx-jx9f.  
Vulnerable code: `jwt.decode, jwt.encode`

`statuspage/auth.py:15`
```
  13| 
  14| def verify_admin_token(token: str) -> str:
  15|     claims = jwt.decode(token, SECRET, algorithms=["HS256"])
  16|     return claims["sub"]
```

Sources: https://github.com/jpadilla/pyjwt

### pyjwt 1.7.1 — PYSEC-2025-183 (HIGH)
pyjwt v2.10.1 was discovered to contain weak encryption.  
Fix: upgrade to **2.14.0** · Verdict: **reachable** (95%)  
Why: The code directly imports jwt and uses jwt.encode and jwt.decode with algorithm HS256 and a hard-coded short secret 'change-me', satisfying the vulnerability condition of weak key material.  
Vulnerable code: `jwt.encode, jwt.decode`

`statuspage/auth.py:10`
```
   8| 
   9| def issue_admin_token(user: str, ttl: int = 3600) -> str:
  10|     token = jwt.encode({"sub": user, "exp": int(time.time()) + ttl}, SECRET, algorithm="HS256")
  11|     return token.decode("utf-8")
  12| 
```

`statuspage/auth.py:15`
```
  13| 
  14| def verify_admin_token(token: str) -> str:
  15|     claims = jwt.decode(token, SECRET, algorithms=["HS256"])
  16|     return claims["sub"]
```

Sources: https://github.com/pyjwt/pyjwt/security/advisories/GHSA-98j8-5j5v-5j5v

### urllib3 1.26.4 — GHSA-2xpw-w6gg-jr37 (HIGH)
urllib3 streaming API improperly handles highly compressed data  
Fix: upgrade to **2.8.0** · Verdict: **reachable** (90%)  
Why: The code calls requests.get() without stream=True, which downloads the full response body. This causes urllib3 to process the compressed stream; if the server returns highly compressible content, the vulnerability's condition (full decompression despite small chunk request) is met.  
Vulnerable code: `urllib3.HTTPResponse.stream, urllib3.HTTPResponse.read, urllib3.HTTPResponse.read1, urllib3.HTTPResponse.read_chunked, urllib3.HTTPResponse.readinto`

`statuspage/checks.py:7`
```
   5| def check(url: str, timeout: float = 3.0) -> str:
   6|     try:
   7|         r = requests.get(url, timeout=timeout)
   8|     except requests.RequestException:
   9|         return "down"
```

Sources: https://urllib3.readthedocs.io/en/2.5.0/advanced-usage.html#streaming-and-i-o, https://github.com/advisories/GHSA-2xpw-w6gg-jr37

### urllib3 1.26.4 — GHSA-q2q7-5pp4-w6pg (HIGH)
Catastrophic backtracking in URL authority parser when passed URL containing many @ characters  
Fix: upgrade to **2.8.0** · Verdict: **reachable** (85%)  
Why: The code imports requests and calls requests.get with a url parameter. Requests uses urllib3 internally, which parses URLs via urllib3.util.url.parse_url. Supplying a URL with many '@' characters in the authority component triggers the vulnerability.  
Vulnerable code: `urllib3.util.url.parse_url`

`statuspage/checks.py:2`
```
   2| import requests
```

`statuspage/checks.py:7`
```
   5| def check(url: str, timeout: float = 3.0) -> str:
   6|     try:
   7|         r = requests.get(url, timeout=timeout)
   8|     except requests.RequestException:
   9|         return "down"
```

Sources: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-33503, https://github.com/urllib3/urllib3/releases/tag/1.26.5

### urllib3 1.26.4 — GHSA-vxq7-64xx-v4gw (HIGH)
urllib3: HTTPResponse.stream()/read_chunked() buffers an unbounded chunk-size line into memory  
Fix: upgrade to **2.8.0** · Verdict: **reachable** (90%)  
Why: The code calls requests.get (statuspage/checks.py:7), which uses urllib3 internally to process HTTP responses, including chunked transfer encoding. An attacker controlling the target server could send a malformed chunked response triggering the vulnerability.  
Vulnerable code: `urllib3.response.BaseHTTPResponse.read_chunked, urllib3.response.BaseHTTPResponse.stream, urllib3.request.RequestMethods.get, urllib3.request.RequestMethods.send`

`statuspage/checks.py:7`
```
   5| def check(url: str, timeout: float = 3.0) -> str:
   6|     try:
   7|         r = requests.get(url, timeout=timeout)
   8|     except requests.RequestException:
   9|         return "down"
```

Sources: https://urllib3.readthedocs.io/en/stable/reference/urllib3.response.html#urllib3.response.BaseHTTPResponse.read_chunked, https://urllib3.readthedocs.io/en/stable/reference/urllib3.response.html#urllib3.response.BaseHTTPResponse.stream, https://urllib3.readthedocs.io/en/2.7.0/advanced-usage.html#streaming-and-i-o

## Needs review (1)

### requests 2.25.1 — GHSA-9hjg-9r4m-mvj7 (MODERATE)
Requests vulnerable to .netrc credentials leak via malicious URLs  
Fix: upgrade to **2.33.0** · Verdict: **uncertain** (50%)  
Why: The code calls requests.get with a url parameter (statuspage/checks.py:7), which matches a vulnerable symbol. However, the source of the url argument is not shown in the evidence; we cannot determine whether it can contain embedded credentials. Without seeing how the function is invoked, we cannot confirm reachability or safety.  
Vulnerable code: `requests.Session.trust_env, requests.Session.get, requests.Session.post`

`statuspage/checks.py:2`
```
   2| import requests
```

`statuspage/checks.py:7`
```
   5| def check(url: str, timeout: float = 3.0) -> str:
   6|     try:
   7|         r = requests.get(url, timeout=timeout)
   8|     except requests.RequestException:
   9|         return "down"
```

Sources: https://github.com/psf/requests/pull/6965, https://seclists.org/fulldisclosure/2025/Jun/2

## Not exploitable here (25)

### pyjwt 1.7.1 — GHSA-ffc3-869f-jxw9 (CRITICAL)
PyJWT: Asymmetric-PEM detection bypass: whitespace/line-ending-mutated public keys skip the HS/asymmetric confusion guard  
Fix: upgrade to **2.14.0** · Verdict: **not_reachable** (95%)  
Why: The only jwt.decode call uses algorithms=["HS256"], which does not mix HMAC and asymmetric algorithms as required for the vulnerability. No other jwt.decode usage is shown.  
Vulnerable code: `jwt.decode, jwt.algorithms.HMACAlgorithm.prepare_key, jwt.utils.is_pem_format, jwt.utils._PEM_RE, jwt.api_jws.perform_verification`

`statuspage/auth.py:15`
```
  13| 
  14| def verify_admin_token(token: str) -> str:
  15|     claims = jwt.decode(token, SECRET, algorithms=["HS256"])
  16|     return claims["sub"]
```

Sources: GHSA-ffc3-869f-jxw9, CVE-2026-102268, PYSEC-2026-4145

### pyjwt 1.7.1 — GHSA-9v7f-9g4p-ffgj (HIGH)
PyJWT: PyJWKClient follows redirects when fetching JWKS  
Fix: upgrade to **2.14.0** · Verdict: **not_reachable** (99%)  
Why: The code only uses jwt.encode and jwt.decode; there is no instantiation or use of PyJWKClient, which is required for the vulnerability to be triggered.  
Vulnerable code: `PyJWKClient`

`statuspage/auth.py:4`
```
   4| import jwt
```

`statuspage/auth.py:10`
```
   8| 
   9| def issue_admin_token(user: str, ttl: int = 3600) -> str:
  10|     token = jwt.encode({"sub": user, "exp": int(time.time()) + ttl}, SECRET, algorithm="HS256")
  11|     return token.decode("utf-8")
  12| 
```

Sources: https://github.com/jpadilla/pyjwt/commit/0a795b8e1f6ef08f634aa7086fc41cc6d5ce3e56, https://github.com/jpadilla/pyjwt/security/advisories/GHSA-9v7f-9g4p-ffgj

### pyjwt 1.7.1 — GHSA-ffqj-6fqr-9h24 (HIGH)
Key confusion through non-blocklisted public key formats  
Fix: upgrade to **2.14.0** · Verdict: **not_reachable** (95%)  
Why: The code encodes with a hard-coded secret, not a public key, and decodes with an explicit algorithms list ["HS256"] rather than the default algorithms. Both conditions required for GHSA-ffqj-6fqr-9h24 (public key used as HMAC secret during encoding and decode with default algorithms) are absent.  
Vulnerable code: `jwt.encode with algorithm="HS256", jwt.decode with algorithms=jwt.algorithms.get_default_algorithms(), jwt.algorithms.get_default_algorithms()`

`statuspage/auth.py:10`
```
   8| 
   9| def issue_admin_token(user: str, ttl: int = 3600) -> str:
  10|     token = jwt.encode({"sub": user, "exp": int(time.time()) + ttl}, SECRET, algorithm="HS256")
  11|     return token.decode("utf-8")
  12| 
```

`statuspage/auth.py:15`
```
  13| 
  14| def verify_admin_token(token: str) -> str:
  15|     claims = jwt.decode(token, SECRET, algorithms=["HS256"])
  16|     return claims["sub"]
```

Sources: https://nvd.nist.gov/vuln/detail/CVE-2022-29217, https://github.com/jpadilla/pyjwt/security/advisories/GHSA-ffqj-6fqr-9h24

### pyjwt 1.7.1 — GHSA-xgmm-8j9v-c9wx (HIGH)
PyJWT: Public-key JWK accepted as HMAC secret enables forged HS256 tokens when mixed families are allowed  
Fix: upgrade to **2.14.0** · Verdict: **not_reachable** (95%)  
Why: The code uses jwt.encode/decode with only HS256 algorithm and a plain string secret; it never passes a list containing both symmetric and asymmetric algorithms nor supplies a raw-JSON JWK as the key, which are required conditions for the vulnerability.  
Vulnerable code: `jwt.api_jws.PyJWS.decode, jwt.api_jws.PyJWS.encode, jwt.algorithms.HMACAlgorithm.prepare_key`

`statuspage/auth.py:10`
```
   8| 
   9| def issue_admin_token(user: str, ttl: int = 3600) -> str:
  10|     token = jwt.encode({"sub": user, "exp": int(time.time()) + ttl}, SECRET, algorithm="HS256")
  11|     return token.decode("utf-8")
  12| 
```

`statuspage/auth.py:15`
```
  13| 
  14| def verify_admin_token(token: str) -> str:
  15|     claims = jwt.decode(token, SECRET, algorithms=["HS256"])
  16|     return claims["sub"]
```

Sources: https://github.com/jpadilla/pyjwt/security/advisories/GHSA-xgmm-8j9v-c9wx, https://github.com/jpadilla/pyjwt/blob/main/jwt/auth.py, https://github.com/jpadilla/pyjwt/blob/main/jwt/hmac.py

### urllib3 1.26.4 — GHSA-38jv-5279-wg99 (HIGH)
Decompression-bomb safeguards bypassed when following HTTP redirects (streaming API)  
Fix: upgrade to **2.8.0** · Verdict: **not_reachable** (90%)  
Why: The code uses requests.get() without stream=True, which defaults to preload_content=True in urllib3, avoiding the vulnerable setting (preload_content=False) required for the decompression bomb via redirect chain.  
Vulnerable code: `urllib3.PoolManager.request, urllib3.HTTPConnectionPool.urlopen, urllib3.response.decode`

`statuspage/checks.py:2`
```
   2| import requests
```

`statuspage/checks.py:7`
```
   5| def check(url: str, timeout: float = 3.0) -> str:
   6|     try:
   7|         r = requests.get(url, timeout=timeout)
   8|     except requests.RequestException:
   9|         return "down"
```

Sources: https://urllib3.readthedocs.io/en/2.6.2/advanced-usage.html#streaming-and-i-o, https://urllib3.readthedocs.io/en/2.6.2/user-guide.html#retrying-requests

### urllib3 1.26.4 — GHSA-8988-9cw3-xx77 (HIGH)
urllib3: HTTPS proxy TLS configuration may be ignored or overridden  
Fix: upgrade to **2.8.0** · Verdict: **not_reachable** (90%)  
Why: The code only makes plain requests.get calls without any proxy configuration; there is no evidence of HTTPS proxy use with use_forwarding_for_https=True or proxy_ssl_context, which are required for the vulnerability to be triggered.  
Vulnerable code: `urllib3.ProxyManager, urllib3.HTTPConnectionPool.urlopen, urllib3.util.ssl_.create_urllib3_context, urllib3.util.ssl_.DEFAULT_CIPHERS, urllib3.util.ssl_.get_urllib3_context, urllib3.util.ssl_.ssl_wrap_socket`

`statuspage/checks.py:7`
```
   5| def check(url: str, timeout: float = 3.0) -> str:
   6|     try:
   7|         r = requests.get(url, timeout=timeout)
   8|     except requests.RequestException:
   9|         return "down"
```

Sources: https://github.com/advisories/GHSA-8988-9cw3-xx77

### urllib3 1.26.4 — GHSA-gm62-xv2j-4w53 (HIGH)
urllib3 allows an unbounded number of links in the decompression chain  
Fix: upgrade to **2.8.0** · Verdict: **not_reachable** (80%)  
Why: The code uses requests.get which internally invokes urllib3.PoolManager.request, but there is no evidence that the URL argument can be attacker‑controlled to point to a malicious server; the docstring indicates polling of owned service endpoints.  
Vulnerable code: `urllib3.PoolManager.request, urllib3.HTTPConnectionPool.urlopen`

`statuspage/checks.py:2`
```
   2| import requests
```

`statuspage/checks.py:7`
```
   5| def check(url: str, timeout: float = 3.0) -> str:
   6|     try:
   7|         r = requests.get(url, timeout=timeout)
   8|     except requests.RequestException:
   9|         return "down"
```

Sources: https://github.com/advisories/GHSA-gm62-xv2j-4w53

### urllib3 1.26.4 — GHSA-qccp-gfcp-xxvc (HIGH)
urllib3: Sensitive headers forwarded across origins in proxied low-level redirects  
Fix: upgrade to **2.8.0** · Verdict: **not_reachable** (90%)  
Why: The code uses requests.get, which internally uses urllib3 but does not set assert_same_host=False. The vulnerability requires that specific parameter; without it, the unsafe header preservation does not occur.  
Vulnerable code: `ProxyManager.connection_from_url().urlopen(..., assert_same_host=False), HTTPConnection.urlopen() instances created via ProxyManager.connection_from_url()`

`statuspage/checks.py:7`
```
   5| def check(url: str, timeout: float = 3.0) -> str:
   6|     try:
   7|         r = requests.get(url, timeout=timeout)
   8|     except requests.RequestException:
   9|         return "down"
```

Sources: https://github.com/advisories/GHSA-qccp-gfcp-xxvc, https://urllib3.readthedocs.io/

### urllib3 1.26.4 — GHSA-v845-jxx5-vc9f (HIGH)
`Cookie` HTTP header isn't stripped on cross-origin redirects  
Fix: upgrade to **2.8.0** · Verdict: **not_reachable** (95%)  
Why: The code uses requests.get without specifying a Cookie header, and there is no evidence of automatic cookie inclusion (no session or cookie jar). Since the vulnerability requires a Cookie header to be sent, the condition is not satisfied.  
Vulnerable code: `urllib3.request.RequestMethods.request, urllib3.request.RequestMethods.get, urllib3.request.RequestMethods.post, urllib3.request.RequestMethods.put, urllib3.request.RequestMethods.delete, urllib3.request.RequestMethods.head, urllib3.request.RequestMethods.options, urllib3.request.RequestMethods.patch, urllib3.request.RequestMethods.request_url, urllib3.connectionpool.HTTPConnectionPool.urlopen, urllib3.util.url.parse_url`

`statuspage/checks.py:7`
```
   5| def check(url: str, timeout: float = 3.0) -> str:
   6|     try:
   7|         r = requests.get(url, timeout=timeout)
   8|     except requests.RequestException:
   9|         return "down"
```

Sources: https://github.com/advisories/GHSA-v845-jxx5-vc9f

### jinja2 2.11.2 — GHSA-cpwx-vrp4-4pq7 (MODERATE)
Jinja2 vulnerable to sandbox breakout through attr filter selecting format method  
Fix: upgrade to **3.1.6** · Verdict: **not_reachable** (95%)  
Why: The code imports and uses jinja2.Environment, not jinja2.sandbox.SandboxedEnvironment, and the template contains no |attr filter. Therefore the vulnerable sandboxed attr filter is never invoked.  
Vulnerable code: `jinja2.sandbox.SandboxedEnvironment, jinja2.sandbox.SandboxedEnvironment.attr, jinja2.sandbox.SandboxedEnvironment.filter`

`statuspage/render.py:2`
```
   2| from jinja2 import Environment, Markup, contextfilter
```

`statuspage/render.py:2`
```
   2| from jinja2 import Environment, Markup, contextfilter
```

### jinja2 2.11.2 — GHSA-g3rq-g295-4j3m (MODERATE)
Regular Expression Denial of Service (ReDoS) in Jinja2  
Fix: upgrade to **3.1.6** · Verdict: **not_reachable** (95%)  
Why: The code creates a Jinja2 Environment and registers only a 'badge' filter. The template string used does not invoke the urlize filter, and no other Jinja templates are present in the codebase. Therefore the vulnerable urlize feature is never exercised.  
Vulnerable code: `jinja2.urlize`

`statuspage/render.py:14`
```
  12| 
  13| 
  14| env = Environment(autoescape=True)
  15| env.filters["badge"] = status_badge
  16| 
```

Sources: https://github.com/advisories/GHSA-g3rq-g295-4j3m

### jinja2 2.11.2 — GHSA-h5c8-rqwp-cp95 (MODERATE)
Jinja vulnerable to HTML attribute injection when passing user input as keys to xmlattr filter  
Fix: upgrade to **3.1.6** · Verdict: **not_reachable** (95%)  
Why: The code defines a custom 'badge' filter and renders a simple template, but never uses Jinja2's xmlattr filter. Since the vulnerability requires the xmlattr filter to be invoked with user‑controlled keys containing spaces, there is no call site that could trigger it.  
Vulnerable code: `xmlattr filter with keys containing spaces`

`statuspage/render.py:14`
```
  12| 
  13| 
  14| env = Environment(autoescape=True)
  15| env.filters["badge"] = status_badge
  16| 
```

`statuspage/render.py:11`
```
   9|     color = STATUS_COLORS.get(status, "#57606a")
  10|     label = ctx.get("labels", {}).get(status, status)
  11|     return Markup(f'<span class="badge" style="background:{color}">{Markup.escape(label)}</span>')
  12| 
  13| 
```

Sources: https://github.com/advisories/GHSA-h5c8-rqwp-cp95

### jinja2 2.11.2 — GHSA-h75v-3vvj-5mfj (MODERATE)
Jinja vulnerable to HTML attribute injection when passing user input as keys to xmlattr filter  
Fix: upgrade to **3.1.6** · Verdict: **not_reachable** (95%)  
Why: The code defines a Jinja2 environment and a custom badge filter, but the only template (PAGE) does not use the xmlattr filter. Since the vulnerable xmlattr filter is never invoked with user‑controlled keys, the vulnerability cannot be triggered.  
Vulnerable code: `xmlattr filter with user-controlled keys`

`statuspage/render.py:14`
```
  12| 
  13| 
  14| env = Environment(autoescape=True)
  15| env.filters["badge"] = status_badge
  16| 
```

Sources: https://github.com/advisories/GHSA-h75v-3vvj-5mfj

### jinja2 2.11.2 — GHSA-q2x7-8rv6-6q7h (MODERATE)
Jinja has a sandbox breakout through indirect reference to format method  
Fix: upgrade to **3.1.6** · Verdict: **not_reachable** (95%)  
Why: The code uses jinja2.Environment, not jinja2.sandbox.SandboxedEnvironment, so the vulnerable SandboxedEnvironment methods are not instantiated. The template string is hardcoded in the source; there is no evidence that attacker‑controlled template content is supplied. Therefore the vulnerability cannot be triggered.  
Vulnerable code: `jinja2.sandbox.SandboxedEnvironment.getattr, jinja2.sandbox.SandboxedEnvironment.__getattr__, jinja2.sandbox.SandboxedEnvironment._SandboxedEnvironmentFilter, jinja2.sandbox.SandboxedEnvironment._SandboxedEnvironmentFilter.call`

`statuspage/render.py:2`
```
   2| from jinja2 import Environment, Markup, contextfilter
```

`statuspage/render.py:2`
```
   2| from jinja2 import Environment, Markup, contextfilter
```

Sources: https://github.com/advisories/GHSA-q2x7-8rv6-6q7h

### pyjwt 1.7.1 — GHSA-2gx3-rcp4-g85q (MODERATE)
PyJWT: PyJWKClient still amplifies unauthenticated JWKS fetches on unknown kid values (incomplete fix of CVE-2026-48524)  
Fix: upgrade to **2.14.0** · Verdict: **not_reachable** (95%)  
Why: The codebase only uses jwt.encode and jwt.decode with HS256 symmetric keys; it never imports or calls PyJWKClient, get_signing_key, get_signing_keys, fetch_data, or jwk_set_cache. Therefore the vulnerable code path requiring unknown kid values cannot be triggered.  
Vulnerable code: `jwt.jwks_client.PyJWKClient.get_signing_key, jwt.jwks_client.PyJWKClient.get_signing_keys, jwt.jwks_client.PyJWKClient.fetch_data, jwt.jwks_client.PyJWKClient.jwk_set_cache`

`statuspage/auth.py:4`
```
   4| import jwt
```

`statuspage/auth.py:10`
```
   8| 
   9| def issue_admin_token(user: str, ttl: int = 3600) -> str:
  10|     token = jwt.encode({"sub": user, "exp": int(time.time()) + ttl}, SECRET, algorithm="HS256")
  11|     return token.decode("utf-8")
  12| 
```

Sources: https://github.com PyJWKClient source code (jwt/jwks_client.py), GHSA-2gx3-rcp4-g85q advisory, CVE-2026-101917

### pyjwt 1.7.1 — GHSA-hxm8-2xgr-2p9m (MODERATE)
PyJWT: Non-canonical signature segments enable raw-token revocation bypass  
Fix: upgrade to **2.14.0** · Verdict: **not_reachable** (90%)  
Why: The code uses jwt.encode and jwt.decode but does not compute or store any hash of the raw token string for logout/revocation; the vulnerability requires such usage, which is absent in the provided evidence.  
Vulnerable code: `pyjwt.jwt.encode, pyjwt.jwt.decode, pyjwt.jwt.decode_options, pyjwt.jwt.PyJWT.encode, pyjwt.jwt.PyJWT.decode`

`statuspage/auth.py:10`
```
   8| 
   9| def issue_admin_token(user: str, ttl: int = 3600) -> str:
  10|     token = jwt.encode({"sub": user, "exp": int(time.time()) + ttl}, SECRET, algorithm="HS256")
  11|     return token.decode("utf-8")
  12| 
```

`statuspage/auth.py:15`
```
  13| 
  14| def verify_admin_token(token: str) -> str:
  15|     claims = jwt.decode(token, SECRET, algorithms=["HS256"])
  16|     return claims["sub"]
```

Sources: https://github.com/jpadilla/pyjwt/security/advisories/GHSA-hxm8-2xgr-2p9m, https://nvd.nist.gov/vuln/detail/CVE-2026-102269

### pyjwt 1.7.1 — GHSA-jwrc-g2q2-pq5p (MODERATE)
PyJWT: ReDoS vulnerability when calling the `is_pem_format` function.  
Fix: upgrade to **2.14.0** · Verdict: **not_reachable** (95%)  
Why: The code uses jwt.encode/decode only with algorithm='HS256' and a string secret. These HMAC operations do not invoke PyJWT's PEM‑parsing functions (is_pem_format, _PEM_RE) that contain the vulnerable regex. Hence the vulnerable symbol is never reached.  
Vulnerable code: `re.compile(b"----[- ]BEGIN (" + b"|".join(_PEMS) + b"[- ]----\r? .+?\r? ----[- ]END \\1[- ]----\r?\n?", re.DOTALL), is_pem_format(key: bytes), _PEM_RE.search(key)`

`statuspage/auth.py:10`
```
   8| 
   9| def issue_admin_token(user: str, ttl: int = 3600) -> str:
  10|     token = jwt.encode({"sub": user, "exp": int(time.time()) + ttl}, SECRET, algorithm="HS256")
  11|     return token.decode("utf-8")
  12| 
```

`statuspage/auth.py:15`
```
  13| 
  14| def verify_admin_token(token: str) -> str:
  15|     claims = jwt.decode(token, SECRET, algorithms=["HS256"])
  16|     return claims["sub"]
```

Sources: https://github.com/pyjwt/pyjwt/security/advisories/GHSA-jwrc-g2q2-pq5p

### pyjwt 1.7.1 — PYSEC-2026-175 (MEDIUM)
PyJWT is a JSON Web Token implementation in Python.  
Fix: upgrade to **2.14.0** · Verdict: **not_reachable** (99%)  
Why: The code only uses jwt.encode and jwt.decode; it never instantiates PyJWKClient, calls fetch_jwks, or invokes urllib.request.urlopen, which are required for the SSRF via JKU URL ingestion.  
Vulnerable code: `PyJWKClient, PyJWKClient.__init__, PyJWKClient.fetch_jwks, urllib.request.urlopen, urllib.request.urlopen()`

`statuspage/auth.py:10`
```
   8| 
   9| def issue_admin_token(user: str, ttl: int = 3600) -> str:
  10|     token = jwt.encode({"sub": user, "exp": int(time.time()) + ttl}, SECRET, algorithm="HS256")
  11|     return token.decode("utf-8")
  12| 
```

`statuspage/auth.py:15`
```
  13| 
  14| def verify_admin_token(token: str) -> str:
  15|     claims = jwt.decode(token, SECRET, algorithms=["HS256"])
  16|     return claims["sub"]
```

Sources: https://github.com/pyjwt/pyjwt/security/advisories/GHSA-993g-76c3-p5m4

### requests 2.25.1 — GHSA-9wx4-h78v-vm56 (MODERATE)
Requests `Session` object does not verify requests after making first request with verify=False  
Fix: upgrade to **2.33.0** · Verdict: **not_reachable** (90%)  
Why: The code only calls requests.get with default verify=True; there is no invocation with verify=False that would poison the connection pool. Without an initial verify=False request to an origin, the described TLS verification bypass cannot occur.  
Vulnerable code: `requests.Session, requests.Session.request, requests.adapters.HTTPAdapter`

`statuspage/checks.py:7`
```
   5| def check(url: str, timeout: float = 3.0) -> str:
   6|     try:
   7|         r = requests.get(url, timeout=timeout)
   8|     except requests.RequestException:
   9|         return "down"
```

Sources: https://github.com/advisories/GHSA-9wx4-h78v-vm56

### requests 2.25.1 — GHSA-gc5v-m9x4-r6x2 (MODERATE)
Requests has Insecure Temp File Reuse in its extract_zipped_paths() utility function  
Fix: upgrade to **2.33.0** · Verdict: **not_reachable** (95%)  
Why: The code imports requests but only calls requests.get; there is no invocation of requests.utils.extract_zipped_paths anywhere in the provided source.  
Vulnerable code: `requests.utils.extract_zipped_paths`

`statuspage/checks.py:7`
```
   5| def check(url: str, timeout: float = 3.0) -> str:
   6|     try:
   7|         r = requests.get(url, timeout=timeout)
   8|     except requests.RequestException:
   9|         return "down"
```

Sources: https://github.com/advisories/GHSA-gc5v-m9x4-r6x2, https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/429

### requests 2.25.1 — GHSA-j8r2-6x86-q33q (MODERATE)
Unintended leak of Proxy-Authorization header in requests  
Fix: upgrade to **2.33.0** · Verdict: **not_reachable** (85%)  
Why: The code uses requests.get without explicit proxy configuration and there is no evidence that proxy credentials are supplied via URL user-info or environment variables. The vulnerability requires a proxy with credentials in the URL and a redirect; without such proxy usage the flaw cannot be triggered.  
Vulnerable code: `requests.sessions.Session.rebuild_proxies, requests.adapters.proxy_manager_for, requests.sessions.Session.send, requests.Request.headers`

`statuspage/checks.py:2`
```
   2| import requests
```

`statuspage/checks.py:7`
```
   5| def check(url: str, timeout: float = 3.0) -> str:
   6|     try:
   7|         r = requests.get(url, timeout=timeout)
   8|     except requests.RequestException:
   9|         return "down"
```

Sources: https://github.com/psf/requests/blob/f2629e9e3c7ce3c3c8c025bcd8db551101cbc773/requests/sessions.py#L319-L328, https://github.com/psf/requests/blob/f2629e9e3c7ce3c3c8c025bcd8db551101cbc773/requests/adapters.py#L199-L235

### urllib3 1.26.4 — GHSA-34jh-p97f-mpxf (MODERATE)
urllib3's Proxy-Authorization request header isn't stripped during cross-origin redirects  
Fix: upgrade to **2.8.0** · Verdict: **not_reachable** (95%)  
Why: The code uses requests.get without setting a Proxy-Authorization header; the vulnerability requires that header to be set (without using urllib3's proxy support). No evidence shows Proxy-Authorization being added, so the attack vector cannot be triggered.  
Vulnerable code: `urllib3 Proxy-Authorization header, urllib3 ProxyManager`

`statuspage/checks.py:7`
```
   5| def check(url: str, timeout: float = 3.0) -> str:
   6|     try:
   7|         r = requests.get(url, timeout=timeout)
   8|     except requests.RequestException:
   9|         return "down"
```

Sources: https://github.com/advisories/GHSA-34jh-p97f-mpxf, https://urllib3.readthedocs.io/

### urllib3 1.26.4 — GHSA-g4mx-q9vg-27p4 (MODERATE)
urllib3's request body not stripped after redirect from 303 status changes request method to GET  
Fix: upgrade to **2.8.0** · Verdict: **not_reachable** (95%)  
Why: The code only performs GET requests via requests.get, which have no request body. The vulnerability requires a request with a body (e.g., POST) that is later redirected with a 303, causing the body to be forwarded. Since no body is sent, the vulnerable condition cannot be met.  
Vulnerable code: `urllib3.util.url.parse_url, urllib3.connectionpool.HTTPConnectionPool.urlopen, urllib3.util.retry.Retry, urllib3.util.url.parse_url, urllib3.connectionpool.HTTPConnectionPool._new_conn, urllib3.connectionpool.HTTPConnectionPool._make_request, urllib3.connectionpool.HTTPConnectionPool._validate_conn, urllib3.connectionpool.HTTPConnectionPool.urlopen, urllib3.util.url.parse_url, urllib3.connectionpool.HTTPConnectionPool.urlopen, urllib3.util.retry.Retry, urllib3.connectionpool.HTTPConnectionPool._new_conn`

`statuspage/checks.py:7`
```
   5| def check(url: str, timeout: float = 3.0) -> str:
   6|     try:
   7|         r = requests.get(url, timeout=timeout)
   8|     except requests.RequestException:
   9|         return "down"
```

Sources: https://github.com/advisories/GHSA-g4mx-q9vg-27p4, https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-45803

### urllib3 1.26.4 — GHSA-pq67-6m6q-mj2v (MODERATE)
urllib3 redirects are not disabled when retries are disabled on PoolManager instantiation  
Fix: upgrade to **2.8.0** · Verdict: **not_reachable** (95%)  
Why: The code uses requests.get without passing a retries argument to disable redirects; the vulnerability only affects cases where retries is explicitly set (e.g., 0, False, or a Retry object) to block redirects. Since no such parameter is supplied, the bug cannot be triggered.  
Vulnerable code: `urllib3.PoolManager, urllib3.Retry, urllib3.request`

`statuspage/checks.py:7`
```
   5| def check(url: str, timeout: float = 3.0) -> str:
   6|     try:
   7|         r = requests.get(url, timeout=timeout)
   8|     except requests.RequestException:
   9|         return "down"
```

Sources: https://github.com/advisories/GHSA-pq67-6m6q-mj2v

### pyjwt 1.7.1 — PYSEC-2026-177 (LOW)
PyJWT is a JSON Web Token implementation in Python.  
Fix: upgrade to **2.14.0** · Verdict: **not_reachable** (95%)  
Why: The code only uses jwt.encode and jwt.decode with HS256 algorithm; there is no import or call to pyjwt.PyJWKClient.get_signing_key, and no wrapper library that would invoke it. Therefore the vulnerable symbol is never used.  
Vulnerable code: `pyjwt.PyJWKClient.get_signing_key`

`statuspage/auth.py:4`
```
   4| import jwt
```

`statuspage/auth.py:10`
```
   8| 
   9| def issue_admin_token(user: str, ttl: int = 3600) -> str:
  10|     token = jwt.encode({"sub": user, "exp": int(time.time()) + ttl}, SECRET, algorithm="HS256")
  11|     return token.decode("utf-8")
  12| 
```

Sources: https://github.com/jpadilla/pyjwt/security/advisories/GHSA-fhv5-28vv-h8m8

## Verified fix

Status: **verified_with_code_changes**  
Upgrades: jinja2 2.11.2→3.1.6, pyyaml 5.3.1→6.0, pyjwt 1.7.1→2.14.0, requests 2.25.1→2.33.0, urllib3 1.26.4→2.8.0  
Compatibility bumps: markupsafe 1.1.1→2.0.0  
Baseline tests: 3 passed in 0.10s · After fix: 3 passed, 2 warnings in 0.12s  
fix.patch re-applied to a pristine copy: yes · tests there: 3 passed, 2 warnings in 0.13s

- Repair 1: statuspage/render.py — The upgrade to jinja2 3.1.6 removed `Markup` and `contextfilter` from the top-level package. `Markup` is now exported by the `markupsafe` package. `contextfilter` decorator is gone; filters needing context must now accept context via explicit arguments. The template and filter are updated to pass `labels` explicitly. Other files (config.py, auth.py, checks.py) show no breakage with their upgraded dependencies. (tests fail)
- Repair 2: statuspage/auth.py — The pyjwt 2.14.0 upgrade changed jwt.encode to return a string instead of bytes, so calling .decode('utf-8') on the result fails. The fix is to return the token directly. No other shown files have breaking changes; the jinja2/markupsafe usage is already correct, pyyaml and requests calls remain compatible. (tests pass)
- Note: pyyaml 5.4 fails to build on this Python; used 5.4.1 instead.
- Note: pyyaml 5.4.1 fails to build on this Python; used 6.0 instead.
- Note: fix.patch re-applied to a pristine copy with git apply; tests there: 3 passed, 2 warnings in 0.13s

```diff
diff --git a/requirements.txt b/requirements.txt
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,7 +1,7 @@
 # Status page service — pinned in early 2021 and never touched since.
-jinja2==2.11.2
-markupsafe==1.1.1
-pyyaml==5.3.1
-pyjwt==1.7.1
-requests==2.25.1
-urllib3==1.26.4
+jinja2==3.1.6
+markupsafe==2.0.0
+pyyaml==6.0
+pyjwt==2.14.0
+requests==2.33.0
+urllib3==2.8.0
diff --git a/statuspage/auth.py b/statuspage/auth.py
--- a/statuspage/auth.py
+++ b/statuspage/auth.py
@@ -8,7 +8,7 @@
 
 def issue_admin_token(user: str, ttl: int = 3600) -> str:
     token = jwt.encode({"sub": user, "exp": int(time.time()) + ttl}, SECRET, algorithm="HS256")
-    return token.decode("utf-8")
+    return token
 
 
 def verify_admin_token(token: str) -> str:
diff --git a/statuspage/render.py b/statuspage/render.py
--- a/statuspage/render.py
+++ b/statuspage/render.py
@@ -1,22 +1,21 @@
 """Server-side rendering of the public status page."""
-from jinja2 import Environment, Markup, contextfilter
+from jinja2 import Environment
+from markupsafe import Markup
 
 STATUS_COLORS = {"up": "#1a7f37", "degraded": "#9a6700", "down": "#cf222e"}
 
 
-@contextfilter
-def status_badge(ctx, status):
+def status_badge(status, labels=None):
     color = STATUS_COLORS.get(status, "#57606a")
-    label = ctx.get("labels", {}).get(status, status)
+    label = (labels or {}).get(status, status)
     return Markup(f'<span class="badge" style="background:{color}">{Markup.escape(label)}</span>')
-
 
 env = Environment(autoescape=True)
 env.filters["badge"] = status_badge
 
 PAGE = env.from_string(
     "<h1>{{ title }}</h1><ul>{% for s in services %}"
-    "<li>{{ s.name }} {{ s.status|badge }}</li>{% endfor %}</ul>"
+    "<li>{{ s.name }} {{ s.status|badge(labels) }}</li>{% endfor %}</ul>"
 )
 
 

```
