"""Sensitive-data discovery, including documents and archives. All test secrets are fake."""

import gzip
import io
import tarfile
import zipfile

from clouddetectx.sensitive import ObjectRef, discover, redact

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
CARD = "4111 1111 1111 1111"


def run(files: dict[str, bytes], **kw):
    refs = [ObjectRef(k, len(v)) for k, v in files.items()]
    return discover(refs, lambda obj, n: files[obj.key][:n], max_objects=50, max_bytes=512 * 1024,
                    max_total_bytes=100 * 1024 * 1024, **kw)


def detectors(report):
    return {h.detector for h in report.hits}


def ooxml(part: str, xml: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("[Content_Types].xml", "<Types/>")
        zf.writestr(part, xml)
    return buf.getvalue()


def test_text_and_redaction():
    report = run({"config/.env": f"AWS_ACCESS_KEY_ID={AWS_KEY}\nDB=postgres://app:S3cret@db:5432/x\n".encode()})
    assert {"aws-access-key", "db-connection"} <= detectors(report)
    assert report.classification == "RESTRICTED"
    flat = str(report.to_dict())
    assert AWS_KEY not in flat and "S3cret" not in flat
    assert redact("123-45-6789", "us-ssn") == "•••-••-6789"


def test_pdf():
    from fpdf import FPDF

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=12)
    pdf.cell(0, 10, f"Customer card {CARD}")
    report = run({"invoices/2026.pdf": bytes(pdf.output())})
    assert "credit-card" in detectors(report) and report.objects_scanned == 1


def test_office_documents():
    files = {
        "notes.docx": ooxml("word/document.xml", f"<w:t>key {AWS_KEY}</w:t>"),
        "cards.xlsx": ooxml("xl/sharedStrings.xml", f"<si><t>{CARD}</t></si>"),
    }
    report = run(files)
    assert {"aws-access-key", "credit-card"} <= detectors(report)


def test_archives_scan_members_and_flag_risky_names():
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as zf:
        zf.writestr("app/.env", f"AWS_ACCESS_KEY_ID={AWS_KEY}")
        zf.writestr("img/logo.png", b"\x89PNG")
    tbuf = io.BytesIO()
    with tarfile.open(fileobj=tbuf, mode="w:gz") as tf:
        data = f"card={CARD}".encode()
        info = tarfile.TarInfo("export/customers.csv")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    report = run({"backup.zip": zbuf.getvalue(), "dump.tar.gz": tbuf.getvalue(),
                  "events.log.gz": gzip.compress(f"leaked {AWS_KEY}".encode())})
    assert {"aws-access-key", "credit-card"} <= detectors(report)
    assert any(r["key"] == "backup.zip!/app/.env" for r in report.risky_files)


def test_parquet():
    import pyarrow as pa
    import pyarrow.parquet as pq

    buf = io.BytesIO()
    pq.write_table(pa.table({"name": ["a", "b"], "card": [CARD, "x"]}), buf)
    assert "credit-card" in detectors(run({"lake/part-0.parquet": buf.getvalue()}))


def test_zip_bomb_and_size_limits():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("huge.txt", b"0" * (5 * 1024 * 1024))       # over the per-member cap: never inflated
    report = run({"bomb.zip": buf.getvalue()})
    assert report.hits == []
    big = run({"big.pdf": b"%PDF" + b"0" * 2048}, max_file_bytes=1024)
    assert big.objects_skipped == 1 and any("over the document size limit" in n for n in big.notes)


def test_corrupt_document_is_noted_not_fatal():
    report = run({"broken.docx": b"not a zip", "ok.txt": f"{AWS_KEY}".encode()})
    assert "aws-access-key" in detectors(report)
    assert any("broken.docx" in n for n in report.notes)
