"""PdfDecryptor / PdfTextExtractor against PDFs GENERATED here: real statements are never committed.

StatementLens had no direct test of these two (its ingest tests stub them), so these are new.
"""
import io

import pikepdf

from inboxkit.pdf import PdfDecryptError, PdfDecryptor, PdfTextExtractor

FAKE_PAN = "ABCDE1234F"
TEXT = "Contract Note Trade 1001 BUY 10 TCS 3000.00"


def _pdf(password=None) -> bytes:
    """A one-page PDF with real text, optionally locked with a user password."""
    pdf = pikepdf.new()
    font = pdf.make_indirect(pikepdf.Dictionary(Type=pikepdf.Name.Font, Subtype=pikepdf.Name.Type1,
                                                BaseFont=pikepdf.Name.Helvetica))
    content = pdf.make_stream(f"BT /F1 12 Tf 72 720 Td ({TEXT}) Tj ET".encode())
    page = pikepdf.Dictionary(Type=pikepdf.Name.Page, MediaBox=[0, 0, 612, 792], Contents=content,
                              Resources=pikepdf.Dictionary(Font=pikepdf.Dictionary(F1=font)))
    pdf.pages.append(pikepdf.Page(page))
    out = io.BytesIO()
    if password:
        pdf.save(out, encryption=pikepdf.Encryption(user=password, owner="owner-" + password, R=6))
    else:
        pdf.save(out)
    return out.getvalue()


def test_an_unlocked_pdf_is_returned_unchanged():
    data = _pdf()
    assert PdfDecryptor().decrypt(data, {}) == data


def test_a_pan_locked_pdf_opens_with_the_pan_hint_and_reads_back():
    locked = _pdf(FAKE_PAN)
    with_pan = PdfDecryptor().decrypt(locked, {"pan": "abcde1234f"})   # case is normalised
    assert TEXT in PdfTextExtractor().extract(with_pan)


def test_wrong_hints_raise_instead_of_returning_garbage():
    locked = _pdf(FAKE_PAN)
    try:
        PdfDecryptor().decrypt(locked, {"name": "Sample Name", "dob": "01011990"})
    except PdfDecryptError as e:
        assert "candidate" in str(e)
    else:
        raise AssertionError("a PDF opened with the wrong password")


def test_an_explicit_custom_password_wins():
    locked = _pdf("chosen-at-cams")       # CAMS CAS uses the password the user picked when requesting it
    out = PdfDecryptor().decrypt(locked, {"custom": ["chosen-at-cams"]})
    assert TEXT in PdfTextExtractor().extract(out)
