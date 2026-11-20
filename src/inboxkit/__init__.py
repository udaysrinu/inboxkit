"""inboxkit: small, dependable pieces for personal-finance tools that read your own documents.

- inboxkit.inbox      GmailDocuments: attachments of emails matching a query (read-only)
- inboxkit.pdf        PdfDecryptor / PdfTextExtractor: unlock a password-protected PDF, read its text
- inboxkit.passwords  password candidates from hints (name, DOB, mobile, card, PAN) or a stated rule
- inboxkit.positions  parse_position: loan statements, FD advices, NPS statements → self-checked snapshots
- inboxkit.secrets    SecretStore: tokens in the OS keychain, with an honest 0600-file fallback
"""
__version__ = "0.3.7"
