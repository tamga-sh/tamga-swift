/// `Transport.swift`
///
/// STUB -- scaffolding only. No HTTP implementation yet.
///
/// Intended contents once implemented:
///
/// - A `URLSession`-based async request executor, built behind a protocol
///   (per `ecc:swift-protocol-di-testing`) so tests can inject a mock session /
///   `URLProtocol` instead of hitting the network.
/// - Base URL builder: `https://<host>/v1/accounts/{account_id}/...` --
///   `account_id` is required in both singleplayer and multiplayer server modes
///   and must never be omitted.
/// - Auth header construction, in the order this SDK defaults to:
///     1. `Authorization: Bearer <token>`
///     2. `Authorization: Basic <base64>` (3 sub-forms: `email:password`,
///        `token:` with empty password, `license:<key>`)
///     3. `Authorization: License <key>` -- primary transport for this
///        embedded/client SDK
///     4. `?token=` / `?auth=` query parameter fallback
///   `Cookie: Tamga-Session=<uuid>` is browser/portal-only and explicitly OUT OF
///   SCOPE for this SDK.
/// - Token values are always opaque strings. Do NOT build prefix-based type
///   detection (`tok-`/`prod-`/`env-`/`activ-`/`lic-`) -- every issued token
///   currently gets the `tok-` prefix regardless of declared type.
/// - Request headers: `Tamga-OTP` (settable per request, TOTP 2FA), and
///   `Tamga-Version` (sanitized alphanumeric + `.`/`-`, max 32 chars, pinned to
///   this SDK's own major version -- not the server's `"1.8"` default).
/// - Response header parsing: `Tamga-Version`, `Tamga-Edition` (`"EE"`/`"CE"`),
///   `Tamga-Mode` (`"singleplayer"`/`"multiplayer"`), `X-Request-Id`.
/// - Content-type dispatch: `application/vnd.api+json` for all JSON:API
///   responses, EXCEPT `GET .../actions/validate` (quick-validate), which
///   returns plain `application/json` with a flat `{ ts, valid, detail, code }`
///   body and no `data` envelope -- this one endpoint needs special-cased
///   response parsing.
/// - Rate-limit handling, which is required rather than optional: HTTP 429 is
///   live server-side. Parse `Retry-After` and cap it, back off with jittered
///   exponential delays, and scope auto-retry to `GET` plus the five safe
///   `POST` actions (`validate`, `validate-key`, `check-in`, `check-out`,
///   `ping`). Creates are deliberately excluded -- retrying one risks a
///   duplicate resource.
/// - Explicitly NOT implemented (doc-only, matching the server's own known
///   gaps): the `Tamga-Environment` request header -- a planned EE feature no
///   server code path reads yet.
/// - Per Swift 6.2 Approachable Concurrency (`ecc:swift-concurrency-6-2`): this
///   type is main-actor by default; the actual request execution should be
///   explicitly `@concurrent`-annotated background work, not implicit
///   background hopping.
public enum Transport {
    // Intentionally empty. Implementation deferred to a future release.
}
