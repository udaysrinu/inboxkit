"""Checks for GmailDocuments, ported from StatementLens's gmail_source tests. Paging: No network — a fake `service` stands in for the API.

The bug these exist for: Gmail's messages.list() returns at most `maxResults` messages, NEWEST FIRST,
and silently drops the rest. There is no error and no flag — a truncated history is indistinguishable
from a short one. On a real mailbox the query matched 111 messages against a limit of 100, so the
oldest 11 were never fetched and the account looked like it began in May 2023 when statements existed
back to Sep 2022. Backfilling recovered 8 months and 555 transactions.
"""

from inboxkit.inbox import DEFAULT_LIMIT, _MAX_PAGE, Document, GmailDocuments


class _FakeMessages:
    """Pages a fixed id list the way Gmail does, honouring maxResults and pageToken."""

    def __init__(self, ids):
        self._ids = ids
        self.pages_served = 0
        self.with_pdf = set()
        self.fetched_full = []

    def list(self, userId, q, maxResults, pageToken=None):
        start = int(pageToken or 0)
        end = min(len(self._ids), start + maxResults)
        body = {"messages": [{"id": i} for i in self._ids[start:end]]}
        if end < len(self._ids):
            body["nextPageToken"] = str(end)
        self.pages_served += 1
        return _Exec(body)

    def get(self, userId, id, format=None, messageId=None):
        if messageId is not None:                 # attachments().get(): return the attachment body
            import base64
            return _Exec({"data": base64.urlsafe_b64encode(b"%PDF-1.7 " + messageId.encode()).decode()})
        if id in self.with_pdf:
            return _Exec({"payload": {
                "headers": [{"name": "Authentication-Results", "value": "mx.google.com; dkim=pass"},
                            {"name": "Subject", "value": f"Contract Note {id}"},
                            {"name": "Authentication-Results", "value": "attacker.example; dkim=pass"},
                            {"name": "From", "value": "Broker <no-reply@example.com>"},
                            {"name": "Date", "value": "Fri, 16 Oct 2026 18:04:39 +0000"}],
                "parts": [{"filename": "note.pdf", "body": {"attachmentId": "a-" + id}},
                          {"filename": "logo.png", "body": {"attachmentId": "b-" + id}}]}})
        self.fetched_full.append(id)
        return _Exec({"payload": {}})

    def attachments(self):
        return self


class _Exec:
    def __init__(self, body):
        self._body = body

    def execute(self):
        return self._body


class _FakeUsers:
    def __init__(self, msgs):
        self._msgs = msgs

    def messages(self):
        return self._msgs


class _FakeService:
    def __init__(self, ids):
        self.msgs = _FakeMessages(ids)

    def users(self):
        return _FakeUsers(self.msgs)



def _source(svc):
    return GmailDocuments("has:attachment", app="inboxkit_test", service=svc)


def test_the_default_limit_covers_a_real_mailbox():
    """The regression, stated as the number that caused it: a real mailbox matched 111 against 100."""
    assert DEFAULT_LIMIT >= 500, f"default limit {DEFAULT_LIMIT} can truncate a multi-year mailbox"
    src = _source(_FakeService([f"m{i}" for i in range(111)]))
    src.fetch()
    assert not src.truncated, "111 messages must not be truncated by the default"


def test_paging_follows_next_page_token():
    svc = _FakeService([f"m{i}" for i in range(_MAX_PAGE + 40)])
    src = _source(svc)
    src.fetch(limit=_MAX_PAGE + 200)
    assert svc.msgs.pages_served >= 2, "fetch() never asked for a second page"
    assert not src.truncated


def test_hitting_the_cap_is_reported_not_silent():
    src = _source(_FakeService([f"m{i}" for i in range(300)]))
    src.fetch(limit=100)
    assert src.truncated, "stopped early with more messages available and said nothing"


def test_a_short_mailbox_stops_without_a_second_call():
    svc = _FakeService([f"m{i}" for i in range(7)])
    src = _source(svc)
    src.fetch(limit=100)
    assert svc.msgs.pages_served == 1 and not src.truncated


def test_an_empty_mailbox_is_not_an_error():
    src = _source(_FakeService([]))
    assert src.fetch(limit=100) == [] and not src.truncated


def test_a_query_is_required():
    # an empty query would read EVERY mail with an attachment; refuse rather than guess
    for q in ("", "   "):
        try:
            GmailDocuments(q, app="inboxkit_test", service=_FakeService([]))
        except ValueError:
            continue
        raise AssertionError(f"accepted query {q!r}")


def test_documents_carry_subject_sender_and_date_and_only_matching_extensions():
    svc = _FakeService(["m1", "m2"])
    svc.msgs.with_pdf = {"m1"}
    docs = _source(svc).fetch(limit=10)
    assert len(docs) == 1, "the .png must not be returned"
    d = docs[0]
    assert isinstance(d, Document) and d.filename == "note.pdf" and d.data.startswith(b"%PDF")
    assert d.subject == "Contract Note m1" and "example.com" in d.sender and d.date.startswith("Fri, 16 Oct 2026")
    assert d.source_id == "m1" and d.source_name == "note.pdf"     # StatementLens's old field names


def test_skip_ids_are_not_downloaded_again():
    # a daily sync passes the ids it already ingested; they must cost no extra API calls
    svc = _FakeService(["m1", "m2", "m3"])
    _source(svc).fetch(limit=10, skip_ids={"m1", "m3"})
    assert svc.msgs.fetched_full == ["m2"]


def test_a_borrowed_token_is_found_in_a_fallback_dir_and_never_moved():
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as own, tempfile.TemporaryDirectory() as other:
        (Path(other) / "gmail_token.json").write_text("{}")
        src = GmailDocuments("x", app="inboxkit_test", service=_FakeService([]), config_dir=own, fallback_dirs=[other])
        assert src._token == Path(other) / "gmail_token.json" and src._borrowed()
        mine = GmailDocuments("x", app="inboxkit_test", service=_FakeService([]), config_dir=own)
        assert not mine._borrowed()


def test_authorize_is_public_and_the_old_private_name_still_works():
    assert GmailDocuments.authorize is GmailDocuments._authorize


def test_headers_keep_order_and_duplicates_so_the_first_auth_result_can_be_trusted():
    svc = _FakeService(["m1"]); svc.msgs.with_pdf = {"m1"}
    d = _source(svc).fetch(limit=5)[0]
    auth = [v for n, v in d.headers if n == "Authentication-Results"]
    assert auth == ["mx.google.com; dkim=pass", "attacker.example; dkim=pass"], auth


GOOD = [("Authentication-Results", "mx.google.com; dkim=pass header.i=@mail.example.com header.s=k1 header.b=x; "
                                   "spf=pass smtp.mailfrom=a@mail.example.com; dmarc=pass (p=REJECT) header.from=mail.example.com"),
        ("From", "Example <notes@mail.example.com>"), ("Date", "Fri, 16 Oct 2026 18:04:39 +0000"), ("Subject", "Note")]


def _doc(headers):
    return Document("m", "n.pdf", b"", headers=headers)


def test_a_genuinely_signed_mail_is_authenticated():
    assert _doc(GOOD).authenticated("mail.example.com") is None


def test_spoofing_attempts_are_refused():
    swap = lambda name, value: [(n, value if n == name else v) for n, v in GOOD]
    cases = {
        "From at another domain": swap("From", "Example <notes@evil.example>"),
        "a forged verdict on top": [("Authentication-Results", "evil.example; dkim=pass header.i=@mail.example.com; dmarc=pass header.from=mail.example.com")] + GOOD,
        "no verdict at all": [h for h in GOOD if h[0] != "Authentication-Results"],
        "DKIM signed by someone else": swap("Authentication-Results", GOOD[0][1].replace("header.i=@mail.example.com", "header.i=@evil.example")),
        "DMARC failed": swap("Authentication-Results", GOOD[0][1].replace("dmarc=pass", "dmarc=fail")),
        "lookalike domain": swap("Authentication-Results", GOOD[0][1].replace("header.from=mail.example.com", "header.from=mail.example.com.evil.example")),
        "two From headers": GOOD + [("From", "x <notes@mail.example.com>")],
    }
    for why, headers in cases.items():
        assert _doc(headers).authenticated("mail.example.com"), f"accepted: {why}"
