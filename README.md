# burn

Zero-knowledge "burn after reading" notes. Text only. A link opens once, then the note is gone.

- Encryption happens in the browser (AES-GCM 256, Web Crypto).
- Random-key mode: the key sits in the URL `#fragment`, which browsers never send to the server.
- Password mode: key derived with PBKDF2-SHA256 (600,000 iterations; format byte 80 = legacy 200,000, still readable).
- The server stores ciphertext, a view counter and an expiry. Nothing else about the note.
- Free tier: 32 KB, one view, up to 24 hours, 3 notes per day per IP.
- Optional paid tier (off unless `STRIPE_SECRET` is set): 96 KB, up to 5 views, up to 7 days, sold as credit packs through Stripe Checkout.
- Optional Cloudflare Turnstile (off unless both Turnstile keys are set).

Single Flask file, no database: notes are JSON files in a data directory.

## Run

    pip install -r requirements.txt
    python3 burn.py                 # http://127.0.0.1:8350
    python3 -m unittest discover -s tests

## Configuration (environment variables)

| Variable | Default | Purpose |
|---|---|---|
| `BURN_DATA_DIR` | `./data` | Where notes, credits and the blocklist live |
| `BURN_HOST` / `BURN_PORT` | `127.0.0.1` / `8350` | Listen address |
| `BURN_BASE_URL` | request host | Return URL for Stripe Checkout |
| `BURN_TRUST_PROXY` | off | Set to `1` only behind a proxy that sets `X-Real-IP` |
| `BURN_CONFIG_FILE` | none | Optional `KEY=VALUE` file holding the keys below |
| `STRIPE_SECRET`, `PACK_PRICE_CENTS`, `PACK_CREDITS` | off | Enable paid credit packs |
| `TURNSTILE_SITE_KEY`, `TURNSTILE_SECRET_KEY` | off | Enable Turnstile on note creation |

Put it behind a reverse proxy with TLS. See `deploy/burn.service`. Run a single worker process:
rate limits are in memory and the one-view guarantee relies on an in-process lock.

## Abuse model

Anyone can create notes, so it can be misused. Mitigations: per-IP rate limits, a daily free cap,
text-only payloads, a Report button, and automatic creator blocking after 3 reports. The server
cannot read notes, so it cannot scan them. `privacy.html` and `terms.html` are templates: replace them
if you run a public instance.

## Limits and honesty

- This code was written with AI assistance and has had limited review. Read it before you trust it.
- The server can serve modified JavaScript. Like any web-delivered crypto, you trust whoever hosts the page.
- If a link is intercepted before the recipient opens it, the interceptor can read the note instead.
- Rate limiting is in memory and resets on restart.

See also: [Awesome DNS Privacy](https://github.com/tbrzr/awesome-dns-privacy), a curated list of private DNS tools.

## License

MIT. See `LICENSE`.
