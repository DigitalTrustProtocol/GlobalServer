# Global Server — identity bindings

Status: **draft** · 2026-09-30 · implements
[TrustGraph identity-binding.md](../../TrustGraph/specs/identity-binding.md)

## Why binds decide usefulness

Attention publishes person trust about X accounts (`i=user:id:<digits>`,
`c=identity`), not about pubkeys. A trust statement becomes a **hop** only
when, for the observer, that `user:id` is bound to the account owner's pubkey.
Without binds, the walk would stop at the first X account.

A bind also carries power. Binding `user:id:X → P` gives P the trust
addressed to X's account, and makes P's own trust statements hops for people
who trust X. A wrong bind is an account hijack inside that person's web of
trust.

## Inputs: public Nostr events only

The Global Server holds no X data and no client-supplied identity evidence.
It binds from two kinds of signed events and nothing else:

| Model input | On the Global Server |
| --- | --- |
| Own evidence (Bio / linking post seen by the observer's client) | **None, ever.** The server never receives X observations. |
| Witness statements (`32009` with an npub hint, `s=x.com`) | Ingested like any statement; the hint is stored on the edge (`hintPubkey`) |
| Claims (`10011` naming the X account) | Ingested; every valid winner feeds the claims index |

Binds are decided **per root, inside the walk**, with the same rules as every
other runtime, in the mode the query asks for (`bindingMode`). There is no
server-wide bind table.

### Consequence for Attention users

With own evidence empty, the bind decision starts at step 2 (your own
witness). Your own X observation counts on the Global Server once you
**publish** it: when you trust an X account, Attention attaches the npub it
saw in that account's Bio or linking post as the hint
([identity-binding.md §9](../../TrustGraph/specs/identity-binding.md#9-publishing-rule)),
and that statement is your own witness. Until then, the Global Server can
bind that account only from your web of trust's witnesses.

The Personal Server behaves the same way: neither server holds X data, so
only the extension's local heap can use Bio evidence directly.

## Lenient and strict on the server

| | Lenient | Strict |
| --- | --- | --- |
| Candidates | Own witness, WoT witnesses | The same, but only npubs whose `10011` names the X account |
| Nearest witness | Decides, even without a `10011` | Decides among confirmed npubs; unconfirmed and false hints are skipped |
| Own witness without `10011` | Binds | Cuts the account (unbound) |
| Routes | Can differ per root for the same account | Converge on the key that claims the account |
| Server work | Witness lookup per touched account | Plus a claims lookup; may fetch a missing `10011` |

The full decision table and the side-by-side situations are in
[identity-binding.md §4–§5](../../TrustGraph/specs/identity-binding.md#4-bind-decision);
on the Global Server the own-evidence rows never apply.

### Missing claims in strict mode

Sync Servers push every `10011` they see, and the event store keeps all of
them, so a candidate's claim is usually already there. When it is not, the
resolver sends a `want` push for `kinds: [10011], authors: [P]` to writers
that subscribed to it ([sync-server.md § Optional demand hints](sync-server.md#optional-demand-hints)),
batched and rate-limited per client. Meanwhile affected results carry
`coverage: partial` with `claims-pending`. If nothing arrives, the candidate
stays cut.

## Verifier services are issuers

A service that proves X account control out of band (for example X OAuth plus
a signed Nostr challenge, the pattern of the local `nip05-Server` project)
publishes an ordinary witness statement. It runs outside the Global Server;
the server only sees the signed event:

```json
{
  "kind": 32009,
  "pubkey": "<verifier>",
  "tags": [
    ["d", "<sha256(user:id:11348282:x.com:identity:attest)>"],
    ["k", "user:id"],
    ["i", "user:id:11348282", "npub1…"],
    ["s", "x.com"],
    ["c", "identity:attest"],
    ["v", "1"]
  ],
  "content": ""
}
```

- `c=identity:attest` is outside the `identity` hop chain, so the statement
  witnesses a bind but is neither a hop nor trust evidence.
- It counts only for roots that trust the verifier, directly or through their
  web of trust. The operator may recommend verifiers; the server never
  applies them to roots that do not trust them.
- Revocation: the verifier publishes a Delete (`v=""`) for the same slot.

## Inspection

| Where | Returns |
| --- | --- |
| `identity.claims { twitterId }` | Every pubkey whose valid `10011` names that X account, with claim event ids (public Nostr data) |
| Result field `binding` | Mode, bound pubkey, source (`own-statement`, `witness`, `none`), witness and claim ids, and in strict mode the cut candidate and reason ([identity-binding.md §8](../../TrustGraph/specs/identity-binding.md#8-result-provenance)) |

## Security notes

- Lenient: a wrong witness misleads the roots for which it is the nearest
  witness. Results show which witness decided, so the UI can explain it.
- Strict: accounts without a `10011` stay terminal.
- Both: a `10011` alone, or a hint from outside the root's web of trust, never
  binds.
- A verifier key compromise affects only roots that trust that verifier; they
  can distrust it and the binds disappear in the next epoch.
- Bind inputs (hints, claims) invalidate root fields only where they matter
  ([resolver-engine.md § Cache and invalidation](resolver-engine.md#cache-and-invalidation)).
