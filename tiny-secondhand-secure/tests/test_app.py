import io
import os
import re
import tempfile
import unittest
from urllib.parse import urlencode

TMP = tempfile.NamedTemporaryFile(delete=False)
TMP.close()
os.environ["TINYMARKET_DB"] = TMP.name

import app


class WSGIClient:
    def __init__(self):
        self.cookie = ""

    def request(self, path, method="GET", data=None):
        body = urlencode(data or {}).encode()
        environ = {
            "REQUEST_METHOD": method,
            "PATH_INFO": path.split("?", 1)[0],
            "QUERY_STRING": path.split("?", 1)[1] if "?" in path else "",
            "CONTENT_LENGTH": str(len(body)),
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
            "wsgi.input": io.BytesIO(body),
            "REMOTE_ADDR": "127.0.0.1",
            "HTTP_COOKIE": self.cookie,
            "SERVER_NAME": "test",
            "SERVER_PORT": "80",
            "wsgi.url_scheme": "http",
            "wsgi.version": (1, 0),
            "wsgi.errors": io.StringIO(),
            "wsgi.multithread": False,
            "wsgi.multiprocess": False,
            "wsgi.run_once": False,
        }
        result = {}
        def start_response(status, headers):
            result["status"] = int(status.split()[0])
            result["headers"] = headers
        chunks = app.application(environ, start_response)
        result["body"] = b"".join(chunks).decode("utf-8")
        for k, v in result["headers"]:
            if k.lower() == "set-cookie" and v.startswith("tm_session="):
                self.cookie = v.split(";", 1)[0]
        return result

    def csrf(self, path):
        r = self.request(path)
        m = re.search(r'name="csrf_token" value="([^"]+)"', r["body"])
        assert m, r["body"][:400]
        return m.group(1)

    def register(self, username, display="테스터", password="StrongPass1"):
        token = self.csrf("/register")
        return self.request("/register", "POST", {"csrf_token": token, "username": username, "display_name": display, "password": password})

    def login(self, username, password="StrongPass1"):
        token = self.csrf("/login")
        return self.request("/login", "POST", {"csrf_token": token, "username": username, "password": password})


class TinyMarketTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.init_db()

    def setUp(self):
        app.limiter.hits.clear()
        with app.get_db() as conn:
            for table in ["transfers", "reports", "messages", "products", "sessions", "users"]:
                conn.execute(f"DELETE FROM {table}")

    def test_register_hashes_password_and_duplicate_rejected(self):
        c = WSGIClient()
        self.assertEqual(c.register("alice")["status"], 303)
        with app.get_db() as conn:
            row = conn.execute("SELECT * FROM users WHERE username='alice'").fetchone()
        self.assertTrue(row["password_hash"].startswith("pbkdf2_sha256$"))
        self.assertNotIn("StrongPass1", row["password_hash"])
        self.assertEqual(c.register("alice")["status"], 303)

    def test_weak_password_rejected(self):
        c = WSGIClient()
        c.register("alice", password="short")
        with app.get_db() as conn:
            count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        self.assertEqual(count, 0)

    def test_login_rotates_session_and_csrf_blocks_post(self):
        c = WSGIClient(); c.register("alice")
        old_cookie = c.cookie
        self.assertEqual(c.login("alice")["status"], 303)
        self.assertNotEqual(old_cookie, c.cookie)
        r = c.request("/products/new", "POST", {"title": "책", "description": "좋은 책입니다", "price": "1000"})
        self.assertEqual(r["status"], 400)

    def test_product_create_search_and_xss_escape(self):
        c = WSGIClient(); c.register("alice"); c.login("alice")
        token = c.csrf("/products/new")
        title = "<script>alert(1)</script>책"
        c.request("/products/new", "POST", {"csrf_token": token, "title": title, "description": "상태가 좋은 책입니다", "price": "1200", "image_url": ""})
        r = c.request("/?q=script")
        self.assertIn("&lt;script&gt;", r["body"])
        self.assertNotIn("<script>alert", r["body"])

    def test_idor_other_user_cannot_delete_product(self):
        a = WSGIClient(); a.register("alice"); a.login("alice")
        t = a.csrf("/products/new")
        a.request("/products/new", "POST", {"csrf_token": t, "title": "노트북", "description": "정상 작동합니다", "price": "50000"})
        with app.get_db() as conn: pid = conn.execute("SELECT id FROM products").fetchone()[0]
        b = WSGIClient(); b.register("bob", "밥사용자"); b.login("bob")
        token = b.csrf(f"/products/{pid}")
        r = b.request(f"/products/{pid}/delete", "POST", {"csrf_token": token})
        self.assertEqual(r["status"], 403)

    def test_transfer_atomic_validation_and_success(self):
        a = WSGIClient(); a.register("alice"); a.login("alice")
        b = WSGIClient(); b.register("bob", "밥사용자")
        token = a.csrf("/transfer")
        a.request("/transfer", "POST", {"csrf_token": token, "recipient": "bob", "amount": "5000"})
        with app.get_db() as conn:
            alice = conn.execute("SELECT balance FROM users WHERE username='alice'").fetchone()[0]
            bob = conn.execute("SELECT balance FROM users WHERE username='bob'").fetchone()[0]
            transfers = conn.execute("SELECT COUNT(*) FROM transfers").fetchone()[0]
        self.assertEqual((alice, bob, transfers), (95000, 105000, 1))
        token = a.csrf("/transfer")
        a.request("/transfer", "POST", {"csrf_token": token, "recipient": "bob", "amount": "-1"})
        with app.get_db() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM transfers").fetchone()[0], 1)

    def test_report_duplicate_prevented_and_admin_can_hide(self):
        seller = WSGIClient(); seller.register("seller"); seller.login("seller")
        token = seller.csrf("/products/new")
        seller.request("/products/new", "POST", {"csrf_token": token, "title": "의심 상품", "description": "검토가 필요한 상품", "price": "100"})
        with app.get_db() as conn: pid = conn.execute("SELECT id FROM products").fetchone()[0]
        reporter = WSGIClient(); reporter.register("reporter", "신고자"); reporter.login("reporter")
        token = reporter.csrf(f"/products/{pid}")
        reporter.request(f"/reports/product/{pid}", "POST", {"csrf_token": token, "reason": "의심스러운 상품"})
        token = reporter.csrf(f"/products/{pid}")
        reporter.request(f"/reports/product/{pid}", "POST", {"csrf_token": token, "reason": "반복 신고"})
        with app.get_db() as conn: self.assertEqual(conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0], 1)
        app.create_admin("admin", "AdminStrong1")
        admin = WSGIClient(); admin.login("admin", "AdminStrong1")
        token = admin.csrf("/admin")
        admin.request(f"/admin/product/{pid}/toggle", "POST", {"csrf_token": token})
        with app.get_db() as conn: self.assertEqual(conn.execute("SELECT hidden FROM products WHERE id=?", (pid,)).fetchone()[0], 1)

    def test_security_headers_present(self):
        r = WSGIClient().request("/")
        headers = dict(r["headers"])
        self.assertIn("Content-Security-Policy", headers)
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")


if __name__ == "__main__":
    unittest.main(verbosity=2)
