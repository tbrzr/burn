import importlib, os, sys, tempfile, threading, unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def fresh_app():
    os.environ["BURN_DATA_DIR"] = tempfile.mkdtemp()
    for k in ("STRIPE_SECRET", "TURNSTILE_SECRET_KEY", "TURNSTILE_SITE_KEY", "BURN_CONFIG_FILE"):
        os.environ.pop(k, None)
    import burn
    importlib.reload(burn)
    return burn


def make(c, **kw):
    body = {"ct": "ciphertext", "hours": 1, "views": 1, "tos": True}
    body.update(kw)
    return c.post("/api/create", json=body)


class BurnTests(unittest.TestCase):
    def setUp(self):
        self.b = fresh_app()
        self.c = self.b.app.test_client()

    def test_health_and_index(self):
        self.assertEqual(self.c.get("/api/health").status_code, 200)
        self.assertEqual(self.c.get("/").status_code, 200)
        self.assertEqual(self.c.get("/privacy.html").status_code, 200)

    def test_config_has_no_turnstile_by_default(self):
        j = self.c.get("/api/config").get_json()
        self.assertFalse(j["payments"])
        self.assertEqual(j["turnstile_sitekey"], "")

    def test_requires_tos(self):
        self.assertEqual(make(self.c, tos=False).status_code, 400)

    def test_roundtrip_and_burn_once(self):
        nid = make(self.c).get_json()["id"]
        self.assertEqual(self.c.get("/api/note/" + nid).status_code, 200)  # peek does not consume
        r = self.c.post("/api/note/%s/burn" % nid)
        self.assertEqual(r.get_json()["ct"], "ciphertext")
        self.assertEqual(self.c.post("/api/note/%s/burn" % nid).status_code, 404)
        self.assertTrue(self.c.get("/api/note/" + nid).get_json().get("gone"))

    def test_concurrent_burn_reads_once(self):
        nid = make(self.c).get_json()["id"]
        codes = []
        def go():
            codes.append(self.b.app.test_client().post("/api/note/%s/burn" % nid).status_code)
        ts = [threading.Thread(target=go) for _ in range(16)]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(codes.count(200), 1)

    def test_free_daily_cap(self):
        for _ in range(self.b.FREE_DAILY_CAP):
            self.assertEqual(make(self.c).status_code, 200)
        self.assertEqual(make(self.c).status_code, 402)

    def test_free_size_limit(self):
        r = make(self.c, ct="x" * (self.b.FREE_MAX_CT + 1))
        self.assertEqual(r.status_code, 413)

    def test_pro_requires_credits(self):
        self.assertEqual(make(self.c, pro=True, token="nope").status_code, 402)

    def test_pro_credit_no_double_spend(self):
        b = self.b
        b.save(b.CREDITS_FILE, {"tok": {"credits": 1, "redeemed": []}})
        codes = []
        def go():
            codes.append(make(b.app.test_client(), pro=True, token="tok").status_code)
        ts = [threading.Thread(target=go) for _ in range(8)]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(codes.count(200), 1)
        self.assertEqual(b.credits_for("tok"), 0)

    def test_free_note_forced_single_view(self):
        nid = make(self.c, views=5).get_json()["views"]
        self.assertEqual(nid, 1)

    def test_security_headers(self):
        r = self.c.get("/api/health")
        self.assertEqual(r.headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertEqual(r.headers["Cache-Control"], "no-store")
        self.assertIn("frame-ancestors 'none'", r.headers["Content-Security-Policy"])

    def test_oversize_body_rejected(self):
        r = self.c.post("/api/create", data="x" * (300 * 1024), content_type="application/json")
        self.assertEqual(r.status_code, 413)

    def test_salt_file_is_private(self):
        self.b.ip_hash("1.2.3.4")
        self.assertEqual(oct(os.stat(self.b.SALT_FILE).st_mode & 0o777), "0o600")

    def test_bad_id_is_404(self):
        self.assertEqual(self.c.get("/api/note/..%2f..%2fetc").status_code, 404)


if __name__ == "__main__":
    unittest.main()
