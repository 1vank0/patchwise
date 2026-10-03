# Patchwise report

Repo: `demo/statuspage` · mode: **online** · 6 pinned deps · 32 advisories · 77.4s

**6 fix now · 0 need review · 26 not exploitable here**

Nemotron on Nebius Token Factory: 68 calls, 67,572 in / 33,034 out tokens, **$0.0433**. Tavily calls: 35.

## Fix now (6)

### pyyaml 5.3.1 — GHSA-8q59-q68h-6hv4 (CRITICAL)
Improper Input Validation in PyYAML  
Fix: upgrade to **5.4** · Verdict: **reachable** (95%)  
Why: The function load_tenant_config calls yaml.load with Loader=yaml.FullLoader on raw input supplied by customers (untrusted YAML), which matches the vulnerable usage pattern.  
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
Fix: upgrade to **2.14.0** · Verdict: **reachable** (95%)  
Why: The verify_admin_token function calls jwt.decode on a token supplied via the Authorization header without restricting headers. An attacker can craft a JWS token containing a 'crit' header with unsupported extensions, triggering the vulnerability in jwt.decode.  
Vulnerable code: `jwt.decode, jwt.encode, jwt.JWT.encode, jwt.JWT.decode`

`statuspage/auth.py:16`
```
  14| 
  15| def verify_admin_token(token: str) -> str:
  16|     claims = jwt.decode(token, SECRET, algorithms=["HS256"])
  17|     return claims["sub"]
```

Sources: https://github.com/jpadilla/pyjwt/issues/1011, https://github.com/jpadilla/pyjwt/blob/main/jwt/api_jwt.py, https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.11

### pyjwt 1.7.1 — PYSEC-2025-183 (HIGH)
pyjwt v2.10.1 was discovered to contain weak encryption.  
Fix: upgrade to **2.14.0** · Verdict: **reachable** (95%)  
Why: The code directly imports jwt and uses HS256 with a hard‑coded weak secret 'change-me' in both jwt.encode (line 11) and jwt.decode (line 16). This satisfies the vulnerability condition of using HS256 with a weak secret key, making the flaw reachable.  
Vulnerable code: `jwt.encode, jwt.decode`

`statuspage/auth.py:7`
```
   5| import jwt
   6| 
   7| SECRET = "change-me"
   8| 
   9| 
```

`statuspage/auth.py:11`
```
   9| 
  10| def issue_admin_token(user: str, ttl: int = 3600) -> str:
  11|     token = jwt.encode({"sub": user, "exp": int(time.time()) + ttl}, SECRET, algorithm="HS256")
  12|     return token.decode("utf-8")
  13| 
```

Sources: https://nvd.nist.gov/vuln/detail/CVE-2025-45768

### urllib3 1.26.4 — GHSA-gm62-xv2j-4w53 (HIGH)
urllib3 allows an unbounded number of links in the decompression chain  
Fix: upgrade to **2.8.0** · Verdict: **reachable** (100%)  
Why: The code uses requests.get which internally invokes urllib3's request handling with default content decoding; a malicious server could send a response with >5 compression algorithms triggering the vulnerability.  
Vulnerable code: `urllib3.PoolManager.request, urllib3.HTTPConnectionPool.urlopen, urllib3.response.decode`

`statuspage/checks.py:7`
```
   5| def check(url: str, timeout: float = 3.0) -> str:
   6|     try:
   7|         r = requests.get(url, timeout=timeout)
   8|     except requests.RequestException:
   9|         return "down"
```

Sources: https://github.com/advisories/GHSA-gm62-xv2j-4w53, https://urllib3.readthedocs.io/en/2.5.0/advanced-usage.html#streaming-and-i-o

### urllib3 1.26.4 — GHSA-q2q7-5pp4-w6pg (HIGH)
Catastrophic backtracking in URL authority parser when passed URL containing many @ characters  
Fix: upgrade to **2.8.0** · Verdict: **reachable** (85%)  
Why: The code calls requests.get with a user‑supplied url parameter (statuspage/checks.py:7). requests internally uses urllib3's parse_url/parse_url2 to process the URL; a URL containing many '@' characters in the authority component can trigger the vulnerability. No validation or sanitization of the url argument is shown.  
Vulnerable code: `urllib3.util.url.parse_url, urllib3.util.url.parse_url2`

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

### requests 2.25.1 — GHSA-9hjg-9r4m-mvj7 (MODERATE)
Requests vulnerable to .netrc credentials leak via malicious URLs  
Fix: upgrade to **2.33.0** · Verdict: **reachable** (95%)  
Why: The code imports requests and calls requests.get without setting trust_env=False, using the default Session which trusts environment variables and could leak .netrc credentials via a malicious URL.  
Vulnerable code: `requests.Session.trust_env`

`statuspage/checks.py:7`
```
   5| def check(url: str, timeout: float = 3.0) -> str:
   6|     try:
   7|         r = requests.get(url, timeout=timeout)
   8|     except requests.RequestException:
   9|         return "down"
```

Sources: https://github.com/psf/requests/pull/6965, https://seclists.org/fulldisclosure/2025/Jun/2

## Not exploitable here (26)

### pyjwt 1.7.1 — GHSA-ffc3-869f-jxw9 (CRITICAL)
PyJWT: Asymmetric-PEM detection bypass: whitespace/line-ending-mutated public keys skip the HS/asymmetric confusion guard  
Fix: upgrade to **2.14.0** · Verdict: **not_reachable** (99%)  
Why: The only jwt.decode call uses algorithms=["HS256"], which does not mix HMAC and asymmetric algorithms as required for the vulnerability. Therefore the vulnerable condition cannot be triggered.  
Vulnerable code: `jwt.decode, jwt.algorithms.HMACAlgorithm.prepare_key, jwt.utils.is_pem_format, jwt.utils._PEM_RE`

`statuspage/auth.py:16`
```
  14| 
  15| def verify_admin_token(token: str) -> str:
  16|     claims = jwt.decode(token, SECRET, algorithms=["HS256"])
  17|     return claims["sub"]
```

Sources: https://github.com/jpadilla/pyjwt/security/advisories/GHSA-ffc3-869f-jxw9

### pyjwt 1.7.1 — GHSA-9v7f-9g4p-ffgj (HIGH)
PyJWT: PyJWKClient follows redirects when fetching JWKS  
Fix: upgrade to **2.14.0** · Verdict: **not_reachable** (99%)  
Why: The code only uses jwt.encode and jwt.decode; PyJWKClient is never instantiated or called, so the vulnerable code path is not exercised.  
Vulnerable code: `PyJWKClient`

`statuspage/auth.py:11`
```
   9| 
  10| def issue_admin_token(user: str, ttl: int = 3600) -> str:
  11|     token = jwt.encode({"sub": user, "exp": int(time.time()) + ttl}, SECRET, algorithm="HS256")
  12|     return token.decode("utf-8")
  13| 
```

`statuspage/auth.py:16`
```
  14| 
  15| def verify_admin_token(token: str) -> str:
  16|     claims = jwt.decode(token, SECRET, algorithms=["HS256"])
  17|     return claims["sub"]
```

Sources: https://github.com/jpadilla/pyjwt/commit/0a795b8e1f6ef08f634aa7086fc41cc6d5ce3e56, https://github.com/jpadilla/pyjwt/security/advisories/GHSA-9v7f-9g4p-ffgj

### pyjwt 1.7.1 — GHSA-ffqj-6fqr-9h24 (HIGH)
Key confusion through non-blocklisted public key formats  
Fix: upgrade to **2.14.0** · Verdict: **not_reachable** (95%)  
Why: The code calls jwt.decode with an explicit algorithms list ["HS256"] and uses the SECRET string as the verification key, not a public key. The vulnerability requires jwt.decode to be called with the default algorithms list and a public key supplied as the key, which does not occur here.  
Vulnerable code: `jwt.encode with algorithm="HS256", jwt.decode with algorithms=jwt.algorithms.get_default_algorithms(), jwt.algorithms.get_default_algorithms()`

`statuspage/auth.py:16`
```
  14| 
  15| def verify_admin_token(token: str) -> str:
  16|     claims = jwt.decode(token, SECRET, algorithms=["HS256"])
  17|     return claims["sub"]
```

Sources: https://nvd.nist.gov/vuln/detail/CVE-2022-29217, https://github.com/jpadilla/pyjwt/security/advisory/GHSA-ffqj-6fqr-9h24

### pyjwt 1.7.1 — GHSA-xgmm-8j9v-c9wx (HIGH)
PyJWT: Public-key JWK accepted as HMAC secret enables forged HS256 tokens when mixed families are allowed  
Fix: upgrade to **2.14.0** · Verdict: **not_reachable** (95%)  
Why: The verifier uses jwt.decode with algorithms=["HS256"] only (no asymmetric algorithms) and a string SECRET, not a raw-JSON JWK. The vulnerability requires both symmetric and asymmetric algorithms in the algorithms list and a JWK key, which are absent.  
Vulnerable code: `jwt.api_jws.PyJWS.decode, jwt.api_jws.PyJWS.encode, jwt.algorithms.HMACAlgorithm.prepare_key`

`statuspage/auth.py:16`
```
  14| 
  15| def verify_admin_token(token: str) -> str:
  16|     claims = jwt.decode(token, SECRET, algorithms=["HS256"])
  17|     return claims["sub"]
```

Sources: https://github.com/jpadilla/pyjwt/security/advisories/GHSA-xgmm-8j9v-c9wx

### urllib3 1.26.4 — GHSA-2xpw-w6gg-jr37 (HIGH)
urllib3 streaming API improperly handles highly compressed data  
Fix: upgrade to **2.8.0** · Verdict: **not_reachable** (90%)  
Why: The code only checks HTTP status code and never accesses the response body, so urllib3's streaming read methods are not invoked; without body consumption, the decompression attack cannot be triggered.  
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

### urllib3 1.26.4 — GHSA-38jv-5279-wg99 (HIGH)
Decompression-bomb safeguards bypassed when following HTTP redirects (streaming API)  
Fix: upgrade to **2.8.0** · Verdict: **not_reachable** (90%)  
Why: The code calls requests.get without stream=True, so urllib3 is used with default preload_content=True, not the streaming API with preload_content=False required for the vulnerability.  
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
Why: The code makes HTTPS requests via requests.get without any proxy configuration. The vulnerability requires an HTTPS proxy with use_forwarding_for_https=True and a configured proxy_ssl_context, which is not present in the code.  
Vulnerable code: `urllib3.ProxyManager, urllib3.HTTPConnectionPool.urlopen, urllib3.util.ssl_.create_urllib3_context, urllib3.util.ssl_.ssl_wrap_socket, urllib3.util.ssl_.DEFAULT_CIPHERS`

`statuspage/checks.py:7`
```
   5| def check(url: str, timeout: float = 3.0) -> str:
   6|     try:
   7|         r = requests.get(url, timeout=timeout)
   8|     except requests.RequestException:
   9|         return "down"
```

Sources: https://github.com/advisories/GHSA-8988-9cw3-xx77

### urllib3 1.26.4 — GHSA-qccp-gfcp-xxvc (HIGH)
urllib3: Sensitive headers forwarded across origins in proxied low-level redirects  
Fix: upgrade to **2.8.0** · Verdict: **not_reachable** (90%)  
Why: The code uses requests.get without configuring proxies or passing assert_same_host=False; the vulnerability requires ProxyManager usage with assert_same_host=False during cross-origin redirects, which is not present.  
Vulnerable code: `ProxyManager.connection_from_url, HTTPConnection.urlopen, assert_same_host=False`

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
Fix: upgrade to **2.8.0** · Verdict: **not_reachable** (90%)  
Why: The code uses requests.get without setting a Cookie header or using the cookies parameter, so the condition requiring a user-specified Cookie header is not satisfied. Without a Cookie header, the vulnerability cannot be triggered even though requests follows redirects by default.  
Vulnerable code: `urllib3.util.url.parse_url, urllib3.util.url.url_to_request, urllib3.PoolManager.request, urllib3.HTTPConnectionPool.urlopen`

`statuspage/checks.py:7`
```
   5| def check(url: str, timeout: float = 3.0) -> str:
   6|     try:
   7|         r = requests.get(url, timeout=timeout)
   8|     except requests.RequestException:
   9|         return "down"
```

Sources: https://github.com/advisories/GHSA-v845-jxx5-vc9f

### urllib3 1.26.4 — GHSA-vxq7-64xx-v4gw (HIGH)
urllib3: HTTPResponse.stream()/read_chunked() buffers an unbounded chunk-size line into memory  
Fix: upgrade to **2.8.0** · Verdict: **not_reachable** (90%)  
Why: The code uses requests.get but never accesses the response body (e.g., .content, .text, or iteration). The urllib3 chunked parsing vulnerability only triggers when reading/chunking the body; without body consumption, the vulnerable code path is not exercised.  
Vulnerable code: `urllib3.response.BaseHTTPResponse.read_chunked, urllib3.response.BaseHTTPResponse.stream, urllib3.request.RequestMethods.request, urllib3.request.RequestMethods.get, urllib3.request.RequestMethods.head, urllib3.request.RequestMethods.post, urllib3.request.RequestMethods.put, urllib3.request.RequestMethods.delete, urllib3.request.RequestMethods.patch, urllib3.request.RequestMethods.options, urllib3.request.RequestMethods.head`

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

Sources: https://urllib3.readthedocs.io/en/stable/reference/urllib3.response.html#urllib3.response.BaseHTTPResponse.read_chunked, https://urllib3.readthedocs.io/en/stable/reference/urllib3.response.html#urllib3.response.BaseHTTPResponse.stream, https://urllib3.readthedocs.io/en/2.7.0/advanced-usage.html#streaming-and-i-o

### jinja2 2.11.2 — GHSA-cpwx-vrp4-4pq7 (MODERATE)
Jinja2 vulnerable to sandbox breakout through attr filter selecting format method  
Fix: upgrade to **3.1.6** · Verdict: **not_reachable** (95%)  
Why: The code imports and uses jinja2.Environment (not SandboxedEnvironment) and defines a template that does not contain the |attr filter. Since the vulnerable feature requires both SandboxedEnvironment and the |attr filter with attacker‑controlled template content, neither condition is met.  
Vulnerable code: `jinja2.sandbox.SandboxedEnvironment.attr, |attr filter`

`statuspage/render.py:2`
```
   2| from jinja2 import Environment, Markup, contextfilter
```

`statuspage/render.py:2`
```
   2| from jinja2 import Environment, Markup, contextfilter
```

Sources: https://github.com/advisories/GHSA-cpwx-vrp4-4pq7

### jinja2 2.11.2 — GHSA-g3rq-g295-4j3m (MODERATE)
Regular Expression Denial of Service (ReDoS) in Jinja2  
Fix: upgrade to **3.1.6** · Verdict: **not_reachable** (95%)  
Why: The code imports jinja2 but never uses the urlize filter or any feature that would invoke it. The only custom filter added is 'badge', and the template strings reference only that filter. Therefore the vulnerable symbol is not exercised.  
Vulnerable code: `jinja2.urlize, jinja2.utils.Markup`

`statuspage/render.py:2`
```
   2| from jinja2 import Environment, Markup, contextfilter
```

`statuspage/render.py:2`
```
   2| from jinja2 import Environment, Markup, contextfilter
```

Sources: https://github.com/advisories/GHSA-g3rq-g295-4j3m

### jinja2 2.11.2 — GHSA-h5c8-rqwp-cp95 (MODERATE)
Jinja vulnerable to HTML attribute injection when passing user input as keys to xmlattr filter  
Fix: upgrade to **3.1.6** · Verdict: **not_reachable** (95%)  
Why: The codebase imports jinja2 but never invokes the xmlattr filter; the sole template string (lines 17‑20) contains no xmlattr usage, and no other Jinja templates are present.  
Vulnerable code: `xmlattr filter`

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
Why: The codebase imports jinja2 but never invokes the xmlattr filter; the sole template string (lines 17‑20) contains no xmlattr usage, and no other Jinja templates are present.  
Vulnerable code: `xmlattr filter with user-controlled keys`

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

Sources: https://github.com/advisories/GHSA-h75v-3vvj-5mfj

### jinja2 2.11.2 — GHSA-q2x7-8rv6-6q7h (MODERATE)
Jinja has a sandbox breakout through indirect reference to format method  
Fix: upgrade to **3.1.6** · Verdict: **not_reachable** (95%)  
Why: The code uses jinja2.Environment, not SandboxedEnvironment, and the only custom filter (status_badge) does not invoke .format() on strings. The template is hardcoded; attacker‑controlled template content is not present. Therefore the vulnerable path cannot be triggered.  
Vulnerable code: `jinja2.sandbox.SandboxedEnvironment, jinja2.sandbox.SandboxedEnvironment.call_filter, jinja2.sandbox.SandboxedEnvironment._filter_call`

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
Why: The codebase only uses jwt.encode and jwt.decode with HS256; it never imports or calls PyJWKClient or its methods get_signing_key, get_signing_keys, fetch_data, or jwk_set_cache, so the vulnerable amplification path cannot be triggered.  
Vulnerable code: `jwt.jwks_client.PyJWKClient.get_signing_key, jwt.jwks_client.PyJWKClient.get_signing_keys, jwt.jwks_client.PyJWKClient.fetch_data, jwt.jwks_client.PyJWKClient.jwk_set_cache`

`statuspage/auth.py:11`
```
   9| 
  10| def issue_admin_token(user: str, ttl: int = 3600) -> str:
  11|     token = jwt.encode({"sub": user, "exp": int(time.time()) + ttl}, SECRET, algorithm="HS256")
  12|     return token.decode("utf-8")
  13| 
```

`statuspage/auth.py:16`
```
  14| 
  15| def verify_admin_token(token: str) -> str:
  16|     claims = jwt.decode(token, SECRET, algorithms=["HS256"])
  17|     return claims["sub"]
```

Sources: https://github.com PyJWKClient source code (jwt/jwks_client.py:185-211), GHSA-2gx3-rcp4-g85q advisory

### pyjwt 1.7.1 — GHSA-hxm8-2xgr-2p9m (MODERATE)
PyJWT: Non-canonical signature segments enable raw-token revocation bypass  
Fix: upgrade to **2.14.0** · Verdict: **not_reachable** (94%)  
Why: The code uses jwt.encode and jwt.decode only to issue and verify tokens; it never hashes the raw JWT string for revocation or logout state. The vulnerability requires indexing by a hash of the raw token (e.g., SHA-256) to be exploitable, which is absent.  
Vulnerable code: `jwt.encode, jwt.decode, pyjwt.decode, pyjwt.encode`

`statuspage/auth.py:11`
```
   9| 
  10| def issue_admin_token(user: str, ttl: int = 3600) -> str:
  11|     token = jwt.encode({"sub": user, "exp": int(time.time()) + ttl}, SECRET, algorithm="HS256")
  12|     return token.decode("utf-8")
  13| 
```

`statuspage/auth.py:16`
```
  14| 
  15| def verify_admin_token(token: str) -> str:
  16|     claims = jwt.decode(token, SECRET, algorithms=["HS256"])
  17|     return claims["sub"]
```

Sources: https://github.com/jpadilla/pyjwt/security/advisories/GHSA-hxm8-2xgr-2p9m

### pyjwt 1.7.1 — GHSA-jwrc-g2q2-pq5p (MODERATE)
PyJWT: ReDoS vulnerability when calling the `is_pem_format` function.  
Fix: upgrade to **2.14.0** · Verdict: **not_reachable** (95%)  
Why: The code uses PyJWT only for HS256 signing/verification with a hardcoded secret string; no attacker‑controlled key or certificate is ever passed to PyJWT, so the vulnerable is_pem_format/PATH regex is not invoked.  
Vulnerable code: `re.compile(b"----[- ]BEGIN (" + b"|".join(_PEMS) + b"[- ]----\r? .+?\r? ----[- ]END \\1[- ]----\r?\n?", re.DOTALL), is_pem_format(key: bytes) -> bool, _PEM_RE.search(key)`

`statuspage/auth.py:5`
```
   5| import jwt
```

`statuspage/auth.py:11`
```
   9| 
  10| def issue_admin_token(user: str, ttl: int = 3600) -> str:
  11|     token = jwt.encode({"sub": user, "exp": int(time.time()) + ttl}, SECRET, algorithm="HS256")
  12|     return token.decode("utf-8")
  13| 
```

Sources: https://github.com/pyjwt/pyjwt/security/advisories/GHSA-jwrc-g2q2-pq5p

### pyjwt 1.7.1 — PYSEC-2026-175 (MEDIUM)
PyJWT is a JSON Web Token implementation in Python.  
Fix: upgrade to **2.14.0** · Verdict: **not_reachable** (95%)  
Why: The code imports jwt but only uses jwt.encode and jwt.decode with HS256; there is no usage of PyJWKClient or any JKU URL ingestion, so the vulnerable feature is not exercised.  
Vulnerable code: `PyJWKClient`

`statuspage/auth.py:5`
```
   5| import jwt
```

`statuspage/auth.py:11`
```
   9| 
  10| def issue_admin_token(user: str, ttl: int = 3600) -> str:
  11|     token = jwt.encode({"sub": user, "exp": int(time.time()) + ttl}, SECRET, algorithm="HS256")
  12|     return token.decode("utf-8")
  13| 
```

Sources: https://github.com/pyjwt/pyjwt/security/advisories/GHSA-993g-76c3-p5m4

### requests 2.25.1 — GHSA-9wx4-h78v-vm56 (MODERATE)
Requests `Session` object does not verify requests after making first request with verify=False  
Fix: upgrade to **2.33.0** · Verdict: **not_reachable** (95%)  
Why: The code only calls requests.get with default verify=True; there is no call with verify=False, and each call uses a temporary Session, so connection‑pool reuse across verify settings cannot occur.  
Vulnerable code: `requests.Session, requests.Session.request, requests.adapters.HTTPAdapter`

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

Sources: https://github.com/advisories/GHSA-9wx4-h78v-vm56, https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-35195

### requests 2.25.1 — GHSA-gc5v-m9x4-r6x2 (MODERATE)
Requests has Insecure Temp File Reuse in its extract_zipped_paths() utility function  
Fix: upgrade to **2.33.0** · Verdict: **not_reachable** (95%)  
Why: The code only uses requests.get for HTTP checks; there is no call to requests.utils.extract_zipped_paths anywhere in the provided source, and no indirect usage via wrappers that would invoke that function.  
Vulnerable code: `requests.utils.extract_zipped_paths()`

`statuspage/checks.py:2`
```
   2| import requests
```

Sources: https://github.com/advisories/GHSA-gc5v-m9x4-r6x2

### requests 2.25.1 — GHSA-j8r2-6x86-q33q (MODERATE)
Unintended leak of Proxy-Authorization header in requests  
Fix: upgrade to **2.33.0** · Verdict: **not_reachable** (90%)  
Why: The code uses requests.get but never configures a proxy with credentials (via proxies dict or environment variables). The vulnerability requires such a proxy configuration; absent evidence of its use, the vulnerable path is not exercised.  
Vulnerable code: `rebuild_proxies, Proxy-Authorization`

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
Why: The code uses requests.get without setting the Proxy-Authorization header or configuring proxies, so the vulnerable condition of manually setting Proxy-Authorization header while bypassing urllib3's proxy support is not present.  
Vulnerable code: `Proxy-Authorization header, ProxyManager`

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

Sources: https://github.com/advisories/GHSA-34jh-p97f-mpxf

### urllib3 1.26.4 — GHSA-g4mx-q9vg-27p4 (MODERATE)
urllib3's request body not stripped after redirect from 303 status changes request method to GET  
Fix: upgrade to **2.8.0** · Verdict: **not_reachable** (95%)  
Why: The code only performs GET requests via requests.get (statuspage/checks.py:7). The vulnerability requires a POST/PUT request with a body that could be leaked on a 303 redirect. No POST/PUT calls are present, so the precondition for the flaw is not satisfied.  
Vulnerable code: `urllib3.util.url.parse_url, urllib3.util.url.url_to_request, urllib3.connectionpool.HTTPConnectionPool.urlopen, urllib3.request.RequestMethods`

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

Sources: https://github.com/advisories/GHSA-g4mx-q9vg-27p4, https://urllib3.readthedocs.io/en/latest/security.html

### urllib3 1.26.4 — GHSA-pq67-6m6q-mj2v (MODERATE)
urllib3 redirects are not disabled when retries are disabled on PoolManager instantiation  
Fix: upgrade to **2.8.0** · Verdict: **not_reachable** (95%)  
Why: The code uses requests.get without configuring retries or attempting to disable redirects via urllib3's PoolManager(retries=...). The vulnerability only affects applications that explicitly set the retries parameter to block redirects; since no such usage exists, the flaw cannot be triggered.  
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
Why: The codebase only uses jwt.encode and jwt.decode with HS256; it never imports or calls PyJWKClient or its methods get_signing_key, get_signing_keys, fetch_data, or jwk_set_cache, so the vulnerable amplification path cannot be triggered.  
Vulnerable code: `pyjwt.PyJWKClient.get_signing_key()`

`statuspage/auth.py:11`
```
   9| 
  10| def issue_admin_token(user: str, ttl: int = 3600) -> str:
  11|     token = jwt.encode({"sub": user, "exp": int(time.time()) + ttl}, SECRET, algorithm="HS256")
  12|     return token.decode("utf-8")
  13| 
```

`statuspage/auth.py:16`
```
  14| 
  15| def verify_admin_token(token: str) -> str:
  16|     claims = jwt.decode(token, SECRET, algorithms=["HS256"])
  17|     return claims["sub"]
```

Sources: https://github.com/jpadilla/pyjwt/security/advisories/GHSA-fhv5-28vv-h8m8

## Verified fix

Status: **verified_with_code_changes**  
Upgrades: pyyaml 5.3.1→6.0, pyjwt 1.7.1→2.12.0, urllib3 1.26.4→2.6.0, requests 2.25.1→2.32.4  

Baseline tests: 3 passed in 0.10s · After fix: 3 passed, 2 warnings in 0.11s  
fix.patch re-applied to a pristine copy: yes · tests there: 3 passed, 2 warnings in 0.12s

- Repair 1: statuspage/auth.py — The pyjwt 2.12.0 upgrade changed jwt.encode() to return a string instead of bytes, so the .decode('utf-8') call fails. The fix is to return the token directly. No other files show test failures, so only auth.py needs modification. (tests pass)
- Note: pyyaml 5.4 fails to build on this Python; used 5.4.1 instead.
- Note: pyyaml 5.4.1 fails to build on this Python; used 6.0 instead.
- Note: fix.patch re-applied to a pristine copy with git apply; tests there: 3 passed, 2 warnings in 0.12s
- Note: pyjwt PYSEC-2025-183 has no patched release; mitigate in code (pyjwt v2.10.1 was discovered to contain weak encryption.).

```diff
diff --git a/requirements.txt b/requirements.txt
--- a/requirements.txt
+++ b/requirements.txt
@@ -1,7 +1,7 @@
 # Status page service — pinned in early 2021 and never touched since.
 jinja2==2.11.2
 markupsafe==1.1.1
-pyyaml==5.3.1
-pyjwt==1.7.1
-requests==2.25.1
-urllib3==1.26.4
+pyyaml==6.0
+pyjwt==2.12.0
+requests==2.32.4
+urllib3==2.6.0
diff --git a/statuspage/auth.py b/statuspage/auth.py
--- a/statuspage/auth.py
+++ b/statuspage/auth.py
@@ -9,7 +9,7 @@
 
 def issue_admin_token(user: str, ttl: int = 3600) -> str:
     token = jwt.encode({"sub": user, "exp": int(time.time()) + ttl}, SECRET, algorithm="HS256")
-    return token.decode("utf-8")
+    return token
 
 
 def verify_admin_token(token: str) -> str:

```
