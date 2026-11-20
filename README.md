# finkit

Small, tested building blocks for personal-finance tools that read **your own** documents.

| Module | What it does |
|---|---|
| `finkit.inbox` | `GmailDocuments(query, app=…)`: attachments of emails matching a Gmail query. Read-only scope, paged, says when it truncated, and can skip ids already ingested. |
| `finkit.pdf` | `PdfDecryptor().decrypt(bytes, hints)` unlocks a password-protected PDF by trying derived candidates. `PdfTextExtractor().extract(bytes)` reads its text. |
| `finkit.passwords` | Password candidates from hints (name, DOB, mobile, card, **PAN**, custom), or from the rule a sender states ("last five digits of mobile + DOB in DDMMYY"). |
| `finkit.secrets` | `SecretStore(service)`: tokens in the OS keychain (macOS `security`, Windows DPAPI, Linux `secret-tool`). Falls back to a 0600 file and **says so**. |

Extracted from [StatementLens](https://github.com/udaysrinu/StatementLens), where these pieces read
bank statements, so that other tools (broker contract notes, mutual-fund CAS statements) reuse the
same tested code instead of a copy.

## Install

Pin a tag, so an upstream change can't break you until you choose to upgrade:

```
pip install "finkit[gmail] @ git+https://github.com/udaysrinu/finkit@v0.1.0"
```

## Example: unlock this month's documents from one sender

```python
from finkit.inbox import GmailDocuments
from finkit.pdf import PdfDecryptor, PdfTextExtractor
from finkit.secrets import SecretStore

docs = GmailDocuments('from:example-broker has:attachment filename:pdf newer_than:30d', app="mytool")
pan = SecretStore("mytool").get("pan")            # read per run, kept in memory, never written out
for d in docs.fetch(skip_ids=already_seen):
    text = PdfTextExtractor().extract(PdfDecryptor().decrypt(d.data, {"pan": pan}))
```

## Rules this code keeps
- **Read-only Gmail scope.** Nothing is ever sent, labelled or deleted.
- **Secrets live in the OS keychain.** A legacy token file is moved in once and then deleted. A token
  borrowed from another app's folder is read, never moved.
- **No silent truncation.** When `fetch()` stops at its limit with more mail remaining, `truncated` is set.
- **No real documents in this repo.** Tests generate their own locked PDFs, and `.gitignore` blocks
  `*.pdf` and token files.

## Tests

`python3 tests/run.py` (standard library only; pytest also works).
