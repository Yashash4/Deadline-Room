# Deadline Room: replay viewer

A static, dependency-free web app that replays a captured Deadline Room run on the
Band platform. It is the public demo for the lablab submission: a judge opens the
URL, picks a scenario, and watches the four statutory clocks race while the Band
room comes alive, the Warden gates each handoff, and the Examiner Packet seals.
The page then re-verifies the byte-identical replay hash in the browser, with no
server, against the bundled run log.

This is forensic playback, not a simulator. Every scenario is a captured run with
its own run-log JSONL and the hash the Warden recorded; the viewer recomputes that
hash client-side so the "byte-identical replay" claim is checkable on the page.

## What is bundled

Four selectable scenarios, each a packet plus its matching run log under `data/`:

- Normal run: three regimes draft, the contradiction diff is green, clocks stop on release.
- Contradiction block: one filing disagrees on the incident start time; the Warden's diff turns red and refuses signoff, then clears once the fact is corrected.
- Exactly-once under kill: a drafter is killed after posting but before acking; on restart the dedup ledger drops the duplicate so the filing lands once.
- Amendment reconciliation (live capture): the real live run (real Band ids, real Featherless models, real filing prose). After release a load-bearing fact is revised; two drafters reconcile through Band over hash-linked envelopes; the amended diff stays blocked until they concur.

The amendment scenario is copied verbatim from a real live capture
(`floor/out/examiner-packet.json` + `floor/out/run-inc-8842-amendment.jsonl`).
The other three are regenerated through the same floor orchestration over the
in-process Band so the capture is reproducible offline; their real regulator-facing
filing prose is grafted in from the live capture (same incident, same drafters,
same models). For every scenario the packet's recorded hash equals the SHA-256 of
its own bundled run log, so the in-browser verify is exact.

## Preview locally

The replay-hash verify uses the SubtleCrypto API, which needs a secure context, so
serve the directory rather than opening the file directly:

```
cd web
py -m http.server 8000
```

Then open http://localhost:8000 . Opening `index.html` over `file://` renders the
viewer but the in-browser hash verify will not run (browser security rule).

## Regenerate the captured scenarios

From the repo root (`code/`):

```
py web/capture_scenarios.py
```

This rewrites the four packets, their run logs, and `data/manifest.json` under
`web/data/`. No API keys are needed; the normal, contradiction, and chaos runs use
the in-process fake Band, and the amendment run is copied from the live capture.

## Deploy as static files

The app is plain HTML, CSS, and vanilla JS with no build step and no external
network calls (no CDNs, no fonts fetched, fully offline-capable). Deploy the `web/`
directory as-is.

GitHub Pages:

```
# from a repo that contains web/ at its root or under /docs
# Settings -> Pages -> Build from a branch -> /web (or copy web/* to /docs)
```

Or push `web/` as the site root of a `gh-pages` branch.

Vercel:

```
cd web
vercel deploy --prod
```

Set the project root to `web/` and the framework preset to "Other" (no build
command, output directory is `web/` itself). Netlify and Cloudflare Pages work the
same way: publish directory `web`, no build command.

## Files

- `index.html` — the page shell and panels.
- `styles.css` — the enterprise dark theme.
- `app.js` — scenario loading, timeline build, animation, and the client-side hash verify.
- `data/manifest.json` — the scenario index the app reads first.
- `data/packet-*.json` — one Examiner Packet per scenario.
- `data/run-inc-8842-*.jsonl` — the matching run logs the hash verify re-hashes.
- `capture_scenarios.py` — regenerates everything under `data/`.
