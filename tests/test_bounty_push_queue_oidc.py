"""Offline tests for OIDC-bound metadata-only GitHub Actions uploader."""
import io
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

path=Path(__file__).resolve().parents[1]/"crypto"/"push_queue_oidc.py"
spec=importlib.util.spec_from_file_location("push_queue_oidc",path)
u=importlib.util.module_from_spec(spec)
spec.loader.exec_module(u)


class FakeOpen:
    def __init__(self, value):
        self.value=value
        self.requests=[]
    def open(self, req, timeout):
        self.requests.append((req,timeout))
        class Context:
            def __init__(self, value):
                self.body=io.BytesIO(json.dumps(value).encode("utf-8"))
            def __enter__(self): return self.body
            def __exit__(self, *args): self.body.close()
        return Context(self.value)


class TestQueuePush(unittest.TestCase):
    def test_actions_oidc_requests_audience_on_scoped_https(self):
        opener=FakeOpen({"value":"x"*200})
        token=u.fetch_token(opener,"https://pipelines.actions.githubusercontent.com/job/idtoken?api-version=2.0","request-secret")
        self.assertEqual(token,"x"*200)
        self.assertEqual(opener.requests[0][0].get_method(),"GET")
        self.assertIn("audience="+u.AUDIENCE,opener.requests[0][0].full_url)

    def test_untrusted_oidc_endpoint_rejected(self):
        with self.assertRaises(RuntimeError):
            u.fetch_token(FakeOpen({}),"https://pipelines.actions.githubusercontent.com.attacker.test/token","token")

    def test_partial_export_rejected_before_network(self):
        with tempfile.TemporaryDirectory() as folder:
            file=Path(folder)/"scan.json"
            file.write_text(json.dumps({"discovered":2,"top":[{"id":"first"}]}))
            with self.assertRaisesRegex(ValueError,"incomplete"):
                u.push(file)

    def test_only_public_metadata_submission(self):
        payload={"discovered":0,"top":[]}
        with tempfile.TemporaryDirectory() as folder:
            file=Path(folder)/"scan.json"
            file.write_text(json.dumps(payload))
            out=FakeOpen({"status":"ingested","accepted":0})
            with patch.object(u,"fetch_token",return_value="token"), patch.object(u,"build_opener",return_value=out):
                u.push(file)
            request=out.requests[0][0]
            self.assertEqual(request.get_method(),"POST")
            self.assertEqual(request.full_url,u.DESTINATION)
            self.assertEqual(json.loads(request.data),payload)
