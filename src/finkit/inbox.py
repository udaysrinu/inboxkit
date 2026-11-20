"""GmailDocuments: fetch attachments of emails matching a Gmail query (read-only).

Extracted from StatementLens (adapters/sources/gmail_source.py) and generalised from "bank
statements" to "documents by query". Bank statements, broker contract notes and mutual-fund CAS
statements are all the same job: search, walk the MIME tree, download the PDF. The query is the
caller's, because only the caller knows which senders matter.

It only READS (scope gmail.readonly). Google libraries are imported lazily, so the package imports
without them; install the [gmail] extra to use this.

Setup, once per app: OAuth *Desktop* credentials, either passed as `client_config` or saved as
`<config_dir>/gmail_client_secret.json`. The first fetch opens a browser consent screen. The token
is then kept in the OS keychain under the app's own service name, never in a plain file.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Sequence, Union

from .secrets import SecretStore, migrate_file_secret

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]
#: Gmail's own per-page maximum for messages.list().
_MAX_PAGE = 500

#: High enough for years of monthly documents across many senders. StatementLens's first default of
#: 100 was below one real mailbox's match count (111) and cut the oldest months off without a word.
DEFAULT_LIMIT = 1000


@dataclass
class Document:
    """One attachment, with enough of its email to say what it is and when it came."""
    message_id: str
    filename: str
    data: bytes
    subject: str = ""
    sender: str = ""
    date: str = ""            # the email's Date header, as sent

    # StatementLens's old _RawStatement names, so existing callers keep working
    @property
    def source_id(self) -> str:
        return self.message_id

    @property
    def source_name(self) -> str:
        return self.filename


ClientConfig = Union[dict, Callable[[], Optional[dict]], None]


class GmailDocuments:
    """Fetch attachments from Gmail for one app.

    query         Gmail search, e.g. 'from:yourbroker has:attachment filename:pdf newer_than:1y'
    app           names the keychain service and the default config dir (~/.<app>)
    service       injectable Gmail client, for tests (no credentials needed)
    client_config the OAuth Desktop client as a dict, or a callable returning one (an app's bundled
                  client); used only when <config_dir>/gmail_client_secret.json does not exist
    config_dir    where this app keeps gmail_client_secret.json and a legacy token file
    fallback_dirs other apps' config dirs to BORROW credentials from (read, never moved)
    extensions    which attachments to return, by filename suffix
    """

    TOKEN_KEY = "gmail_token"

    def __init__(self, query: str, *, app: str, service=None, client_config: ClientConfig = None,
                 config_dir: Optional[str] = None, client_secret_path: Optional[str] = None,
                 token_path: Optional[str] = None, fallback_dirs: Sequence[str] = (),
                 extensions: Iterable[str] = (".pdf",), store: Optional[SecretStore] = None):
        if not query or not query.strip():
            raise ValueError("GmailDocuments needs a Gmail query; an empty one would read every mail")
        if not app:
            raise ValueError("GmailDocuments needs an app name for its keychain namespace")
        self._service = service
        self._query = query
        self._app = app
        self._client_config = client_config
        self._dir = Path(config_dir) if config_dir else Path.home() / f".{app}"
        self._fallback = [Path(p) for p in fallback_dirs]
        env = app.upper().replace("-", "_")
        self._secret = self._cfg("gmail_client_secret.json", client_secret_path, f"{env}_GMAIL_SECRET")
        self._token = self._cfg("gmail_token.json", token_path, f"{env}_GMAIL_TOKEN")
        self._ext = tuple(e.lower() for e in extensions)
        self._store_obj = store
        self.truncated = False

    def _cfg(self, name: str, override: Optional[str], env: str) -> Path:
        explicit = override or os.getenv(env)
        if explicit:
            return Path(explicit)
        own = self._dir / name
        if not own.exists():
            for d in self._fallback:
                if (d / name).exists():
                    return d / name
        return own

    # -- public ------------------------------------------------------------
    def fetch(self, limit: int = DEFAULT_LIMIT, skip_ids: Iterable[str] = ()) -> List[Document]:
        """Every matching message's attachments, following Gmail's pagination.

        Three things were wrong in the first version, and the third is the one that mattered:
        1. One list() call returns at most `maxResults` messages, NEWEST FIRST; there was no paging.
        2. The default limit was below a real mailbox's count, so the oldest months were never read.
        3. It was SILENT. A truncated history is indistinguishable from a short one.
        So: page properly, default high, and set `truncated` when the cap is hit with more remaining.

        `skip_ids` are message ids the caller already ingested; they are counted for paging but not
        downloaded again, which makes a daily incremental sync cheap and idempotent.
        """
        svc = self._service or self._authorize()
        skip = set(skip_ids)
        out: List[Document] = []
        self.truncated = False
        seen = 0
        token = None
        while True:
            page = min(_MAX_PAGE, limit - seen) if limit else _MAX_PAGE
            resp = svc.users().messages().list(
                userId="me", q=self._query, maxResults=page, pageToken=token).execute()
            msgs = resp.get("messages", [])
            for m in msgs:
                if m["id"] in skip:
                    continue
                head, atts = self._attachments(svc, m["id"])
                for att in atts:
                    data = self._download(svc, m["id"], att["attachment_id"])
                    out.append(Document(m["id"], att["filename"], data,
                                        head.get("subject", ""), head.get("from", ""), head.get("date", "")))
            seen += len(msgs)
            token = resp.get("nextPageToken")
            if not token:
                break
            if limit and seen >= limit:
                self.truncated = True          # more history exists than we were allowed to read
                break
        return out

    # -- helpers -----------------------------------------------------------
    def _attachments(self, svc, msg_id: str):
        full = svc.users().messages().get(userId="me", id=msg_id, format="full").execute()
        payload = full.get("payload", {}) or {}
        head = {h.get("name", "").lower(): h.get("value", "") for h in payload.get("headers", []) or []}
        found: List[dict] = []

        def walk(part):
            body = part.get("body", {}) or {}
            fn = part.get("filename", "")
            if fn.lower().endswith(self._ext) and body.get("attachmentId"):
                found.append({"filename": fn, "attachment_id": body["attachmentId"]})
            for c in part.get("parts", []) or []:
                walk(c)

        walk(payload)
        return head, found

    def _download(self, svc, msg_id: str, attachment_id: str) -> bytes:
        att = svc.users().messages().attachments().get(
            userId="me", messageId=msg_id, id=attachment_id).execute()
        return base64.urlsafe_b64decode(att["data"].encode("utf-8"))

    def _client(self) -> Optional[dict]:
        import json
        if self._secret.exists():
            return json.loads(self._secret.read_text(encoding="utf-8"))
        cfg = self._client_config
        return cfg() if callable(cfg) else cfg

    def _authorize(self):
        try:
            from google.oauth2.credentials import Credentials
            from google_auth_oauthlib.flow import InstalledAppFlow
            from google.auth.transport.requests import Request
            from googleapiclient.discovery import build
        except ImportError as e:  # pragma: no cover
            raise RuntimeError("Gmail libraries missing: pip install 'finkit[gmail]'") from e
        creds = self._load_credentials(Credentials)
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                config = self._client()
                if config is None:
                    raise RuntimeError(
                        f"Gmail isn't set up for {self._app}: pass client_config, or save Desktop OAuth "
                        f"credentials at {self._secret}.")
                creds = InstalledAppFlow.from_client_config(config, SCOPES).run_local_server(
                    port=0, open_browser=True, authorization_prompt_message="",
                    success_message=f"Connected. You can close this tab and return to {self._app}.")
            self._store().set(self.TOKEN_KEY, creds.to_json())
        return build("gmail", "v1", credentials=creds, cache_discovery=False)

    # -- token storage -----------------------------------------------------
    def _store(self) -> SecretStore:
        if self._store_obj is None:
            self._store_obj = SecretStore(service=self._app)
        return self._store_obj

    def _borrowed(self) -> bool:
        """True when the legacy token file belongs to ANOTHER app (found in a fallback dir)."""
        return any(self._token.parent == d for d in self._fallback)

    def _load_credentials(self, Credentials):
        """Prefer the OS keychain; migrate a legacy plaintext token file on first use.

        Migration deletes the file it read, which is right for this app's own legacy token and WRONG
        for a borrowed one: unlinking another app's token silently breaks the app that created it. So a
        borrowed credential is read, never moved.
        """
        import json
        store = self._store()
        raw = store.get(self.TOKEN_KEY)
        if not raw and self._token.exists():
            if self._borrowed():
                raw = self._token.read_text(encoding="utf-8")
            else:
                try:
                    migrate_file_secret(store, self.TOKEN_KEY, self._token)
                    raw = store.get(self.TOKEN_KEY)
                except Exception:
                    raw = self._token.read_text(encoding="utf-8")   # never block on a failed migration
        if not raw:
            return None
        try:
            return Credentials.from_authorized_user_info(json.loads(raw), SCOPES)
        except Exception:
            return None
