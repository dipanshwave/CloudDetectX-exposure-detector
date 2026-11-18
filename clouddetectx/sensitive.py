"""Sensitive-data discovery: what is actually inside an exposed bucket?

Reads only the first part of a bounded sample of objects, looks for secrets, credentials
and personal data, and reports **redacted** matches. Full secret values are never stored,
printed or written to reports.
"""

from __future__ import annotations

import io
import re
from dataclasses import asdict, dataclass, field
from pathlib import PurePosixPath
from typing import Callable, Iterable

from clouddetectx.models import Severity


@dataclass
class ObjectRef:
    key: str
    size: int | None = None
    container: str | None = None   # Azure container name; None for bucket-based clouds

    @property
    def display(self) -> str:
        return f"{self.container}/{self.key}" if self.container else self.key


# --------------------------------------------------------------------------- validators

def _luhn(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _card(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if len(set(digits)) == 1:
        return False
    issuer = re.match(r"^(4|5[1-5]|2[2-7]|3[47]|6(011|5)|35)", digits)
    return bool(issuer) and _luhn(digits)


_VERHOEFF_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
               [3, 4, 0, 1, 2, 8, 9, 5, 6, 7], [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
               [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3], [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
               [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_VERHOEFF_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
               [8, 9, 1, 6, 0, 4, 3, 5, 2, 7], [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
               [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]


def _aadhaar(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if len(digits) != 12 or digits[0] in "01":
        return False
    check = 0
    for i, d in enumerate(reversed(digits)):
        check = _VERHOEFF_D[check][_VERHOEFF_P[i % 8][int(d)]]
    return check == 0


def _iban(value: str) -> bool:
    v = value.replace(" ", "").upper()
    if not 15 <= len(v) <= 34:
        return False
    rearranged = v[4:] + v[:4]
    numeric = "".join(str(int(c, 36)) for c in rearranged)
    return int(numeric) % 97 == 1


_PLACEHOLDERS = re.compile(r"^(\$|\{\{|<|%|\*{3,}|x{4,}|changeme|example|password|secret|redacted|none|null|true|false)", re.I)


def _real_secret(value: str) -> bool:
    secret = re.split(r"[=:]", value, maxsplit=1)[-1].strip().strip("'\"")
    return len(secret) >= 8 and not _PLACEHOLDERS.match(secret)


# --------------------------------------------------------------------------- detectors

@dataclass(frozen=True)
class Detector:
    id: str
    name: str
    category: str            # secret | pii
    severity: Severity
    pattern: re.Pattern
    validate: Callable[[str], bool] | None = None


def _rx(p: str, flags: int = 0) -> re.Pattern:
    return re.compile(p, flags)


DETECTORS: tuple[Detector, ...] = (
    Detector("aws-access-key", "AWS access key ID", "secret", Severity.CRITICAL, _rx(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    Detector("aws-secret-key", "AWS secret access key", "secret", Severity.CRITICAL,
             _rx(r"(?i)aws_?secret_?access_?key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}")),
    Detector("private-key", "Private key (PEM)", "secret", Severity.CRITICAL,
             _rx(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    Detector("gcp-service-account", "Google Cloud service-account key", "secret", Severity.CRITICAL,
             _rx(r"\"type\"\s*:\s*\"service_account\"[\s\S]{0,2000}\"private_key\"")),
    Detector("azure-storage-key", "Azure storage connection string", "secret", Severity.CRITICAL,
             _rx(r"DefaultEndpointsProtocol=https?;AccountName=[^;\s]+;AccountKey=[A-Za-z0-9+/=]{40,}")),
    Detector("azure-sas", "Azure SAS token", "secret", Severity.HIGH,
             _rx(r"[?&]sv=\d{4}-\d{2}-\d{2}&[^\s\"']*sig=[A-Za-z0-9%+/=]{20,}")),
    Detector("github-token", "GitHub token", "secret", Severity.HIGH, _rx(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b")),
    Detector("slack-token", "Slack token", "secret", Severity.HIGH, _rx(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    Detector("stripe-live-key", "Stripe live secret key", "secret", Severity.CRITICAL, _rx(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b")),
    Detector("google-api-key", "Google API key", "secret", Severity.HIGH, _rx(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    Detector("jwt", "JSON Web Token", "secret", Severity.MEDIUM,
             _rx(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    Detector("db-connection", "Database URL with password", "secret", Severity.HIGH,
             _rx(r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|mssql|sqlserver|amqp)://[^\s:@/'\"]+:[^\s@/'\"]{3,}@[^\s'\"]+")),
    Detector("password-assignment", "Hard-coded password / API key", "secret", Severity.MEDIUM,
             _rx(r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)\s*[=:]\s*['\"]?[^\s'\",;]{8,}"),
             _real_secret),
    Detector("credit-card", "Payment card number", "pii", Severity.HIGH, _rx(r"\b(?:\d[ -]?){13,19}\b"), _card),
    Detector("us-ssn", "US Social Security number", "pii", Severity.HIGH,
             _rx(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
    Detector("aadhaar", "Aadhaar number (India)", "pii", Severity.HIGH, _rx(r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b"), _aadhaar),
    Detector("pan", "PAN (India)", "pii", Severity.MEDIUM, _rx(r"\b[A-Z]{3}[PCHABGJLFT][A-Z]\d{4}[A-Z]\b")),
    Detector("iban", "IBAN bank account", "pii", Severity.MEDIUM, _rx(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b"), _iban),
    # The lookbehind stops "user:password@host" in connection URLs from counting as an email address.
    Detector("email", "Email addresses", "pii", Severity.LOW,
             _rx(r"(?<![:/\w.%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
)

# Only flag email as personal data in bulk; one contact address in a README is not a leak.
EMAIL_BULK_THRESHOLD = 20

# (pattern on the object key, description, category, severity)
FILENAME_RULES: tuple[tuple[re.Pattern, str, str, Severity], ...] = (
    (_rx(r"(^|/)\.env(\.[\w-]+)?$", re.I), "Environment file (.env)", "secret", Severity.HIGH),
    (_rx(r"(^|/)(id_rsa|id_dsa|id_ecdsa|id_ed25519)$"), "SSH private key", "secret", Severity.CRITICAL),
    (_rx(r"\.(pem|key|p12|pfx|jks|keystore|ppk|asc|gpg)$", re.I), "Key or certificate store", "secret", Severity.HIGH),
    (_rx(r"(^|/)(credentials|\.aws/credentials|\.git-credentials|\.netrc|\.npmrc|\.pypirc|\.dockercfg|config\.json)$", re.I),
     "Credentials file", "secret", Severity.HIGH),
    (_rx(r"\.tfstate(\.backup)?$", re.I), "Terraform state (often contains secrets)", "secret", Severity.HIGH),
    (_rx(r"(^|/)(kubeconfig|\.kube/config)$", re.I), "Kubernetes config", "secret", Severity.HIGH),
    (_rx(r"\.kdbx$", re.I), "Password manager database", "secret", Severity.HIGH),
    (_rx(r"(^|/)(wp-config\.php|settings\.py|web\.config|appsettings(\.\w+)?\.json)$", re.I), "Application config", "secret", Severity.MEDIUM),
    (_rx(r"(^|/)\.git/(config|HEAD)$"), "Git repository metadata", "secret", Severity.MEDIUM),
    (_rx(r"(^|/)(shadow|passwd|htpasswd|\.htpasswd)$"), "Password file", "secret", Severity.HIGH),
    (_rx(r"\.(sql|dump|bak|backup|sqlite3?|db|mdb|accdb|bson)(\.gz|\.zip|\.7z)?$", re.I), "Database dump or backup", "backup", Severity.HIGH),
    (_rx(r"\.(csv|xlsx?|parquet)$", re.I), "Tabular data export", "data", Severity.LOW),
)

BINARY_EXT = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".ico", ".svg", ".mp4", ".mov", ".avi", ".mkv", ".mp3",
              ".wav", ".flac", ".bz2", ".xz", ".7z", ".rar",
              ".woff", ".woff2", ".ttf", ".otf", ".exe", ".dll", ".so", ".dylib", ".bin", ".iso", ".avro"}
# Read whole (up to the document size limit) and converted to text before scanning.
DOCUMENT_EXT = {".pdf", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".zip", ".jar", ".gz", ".tgz", ".parquet"}
MAX_EXTRACTED_CHARS = 4 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 500
MAX_UNCOMPRESSED = 64 * 1024 * 1024
TEXT_EXT = {".env", ".txt", ".csv", ".json", ".yml", ".yaml", ".xml", ".ini", ".cfg", ".conf", ".config", ".properties",
            ".sql", ".log", ".md", ".py", ".js", ".ts", ".php", ".rb", ".go", ".java", ".sh", ".ps1", ".tf", ".tfstate",
            ".tfvars", ".pem", ".key", ".html", ".htm", ".toml"}


def _xml_text(xml: bytes) -> str:
    text = re.sub(rb"<[^>]+>", b" ", xml).decode("utf-8", errors="replace")
    return re.sub(r"[ \t]+", " ", text)


def _zip_members(data: bytes, prefix: str, risky_names: list[str]) -> str:
    import zipfile

    out, total = [], 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()][:MAX_ARCHIVE_MEMBERS]
        for info in infos:
            risky_names.append(f"{prefix}!/{info.filename}")
            ext = PurePosixPath(info.filename.lower()).suffix
            if ext not in TEXT_EXT and ext != "":
                continue
            if info.file_size > 2 * 1024 * 1024 or total + info.file_size > MAX_UNCOMPRESSED:
                continue                     # zip-bomb guard: never inflate more than the budget
            total += info.file_size
            with zf.open(info) as fh:
                out.append(fh.read(2 * 1024 * 1024).decode("utf-8", errors="replace"))
    return "\n".join(out)


def _ooxml(data: bytes) -> str:
    import zipfile

    out, total = [], 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist()[:MAX_ARCHIVE_MEMBERS]:
            name = info.filename
            if not name.endswith(".xml") or not name.startswith(("word/", "xl/", "ppt/")):
                continue
            if total + info.file_size > MAX_UNCOMPRESSED:
                break
            total += info.file_size
            with zf.open(info) as fh:
                out.append(_xml_text(fh.read(8 * 1024 * 1024)))
    return "\n".join(out)


def extract_text(key: str, data: bytes, risky_names: list[str]) -> tuple[str | None, str | None]:
    """Text content of a document/archive. Returns (text, note). risky_names collects archive member names."""
    ext = PurePosixPath(key.lower()).suffix
    try:
        if ext == ".pdf":
            from pypdf import PdfReader

            reader = PdfReader(io.BytesIO(data))
            if reader.is_encrypted:
                return None, f"{key}: encrypted PDF not scanned"
            return "\n".join((page.extract_text() or "") for page in reader.pages[:200]), None
        if ext in (".docx", ".xlsx", ".pptx", ".docm", ".xlsm"):
            return _ooxml(data), None
        if ext in (".zip", ".jar"):
            return _zip_members(data, key, risky_names), None
        if ext in (".gz", ".tgz"):
            import gzip
            import tarfile

            raw = gzip.GzipFile(fileobj=io.BytesIO(data)).read(MAX_UNCOMPRESSED)
            inner = key[:-3] if ext == ".gz" else key[:-4] + ".tar"
            if inner.lower().endswith(".tar"):
                out = []
                with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
                    for m in tf.getmembers()[:MAX_ARCHIVE_MEMBERS]:
                        if not m.isfile():
                            continue
                        risky_names.append(f"{key}!/{m.name}")
                        if PurePosixPath(m.name.lower()).suffix in TEXT_EXT and m.size <= 2 * 1024 * 1024:
                            fh = tf.extractfile(m)    # read into memory only; nothing is written to disk
                            if fh:
                                out.append(fh.read().decode("utf-8", errors="replace"))
                return "\n".join(out), None
            return raw.decode("utf-8", errors="replace"), None
        if ext == ".parquet":
            try:
                import pyarrow.parquet as pq
            except ImportError:
                return None, "Parquet files need pyarrow (pip install pyarrow)"
            table = pq.read_table(io.BytesIO(data))
            rows = table.slice(0, 5000).to_pylist()
            return "\n".join(" ".join(str(v) for v in row.values() if v is not None) for row in rows), None
    except Exception as exc:  # noqa: BLE001 - corrupt or unsupported file
        return None, f"{key}: could not extract text ({type(exc).__name__})"
    return None, None


def redact(value: str, detector_id: str) -> str:
    v = value.strip()
    if detector_id == "us-ssn":
        return "•••-••-" + v[-4:]
    if detector_id in ("credit-card", "aadhaar"):
        digits = re.sub(r"\D", "", v)
        return "•" * (len(digits) - 4) + digits[-4:]
    if detector_id == "email":
        local, _, domain = v.partition("@")
        return f"{local[:1]}•••@{domain}"
    if detector_id == "private-key":
        return v[:40]  # just the header line, no key material
    if detector_id in ("password-assignment", "aws-secret-key"):
        name = re.split(r"[=:]", v, maxsplit=1)[0].strip()
        return f"{name[:30]}=••••••••"
    if detector_id == "db-connection":
        return re.sub(r"(://[^:/]+:)[^@]+@", r"\1••••••@", v)[:80]
    if len(v) <= 10:
        return "•" * len(v)
    return f"{v[:4]}{'•' * 8}{v[-2:]}"


@dataclass
class DetectorHit:
    detector: str
    name: str
    category: str
    severity: str
    count: int = 0
    objects: list[str] = field(default_factory=list)
    samples: list[str] = field(default_factory=list)


@dataclass
class SensitiveReport:
    objects_listed: int
    objects_scanned: int
    objects_skipped: int
    bytes_read: int
    hits: list[DetectorHit]
    risky_files: list[dict]
    classification: str      # RESTRICTED | CONFIDENTIAL | INTERNAL | NONE_FOUND
    notes: list[str]
    budget_exhausted: bool = False

    @property
    def secret_count(self) -> int:
        return sum(h.count for h in self.hits if h.category == "secret")

    @property
    def pii_count(self) -> int:
        return sum(h.count for h in self.hits if h.category == "pii" and (h.detector != "email" or h.count >= EMAIL_BULK_THRESHOLD))

    def to_dict(self) -> dict:
        d = asdict(self)
        d["secret_count"], d["pii_count"] = self.secret_count, self.pii_count
        return d


CLASSIFICATION_TEXT = {
    "RESTRICTED": "Secrets or credentials found: anyone who downloaded them may be able to access other systems.",
    "CONFIDENTIAL": "Personal or business-sensitive data found.",
    "INTERNAL": "No secrets or personal data detected, but files that usually hold internal data are present.",
    "NONE_FOUND": "Nothing sensitive was detected in the sampled objects.",
}


def _priority(obj: ObjectRef) -> tuple:
    name = obj.key
    risky = any(rx.search(name) for rx, *_ in FILENAME_RULES)
    ext = PurePosixPath(name.lower()).suffix
    texty = ext in TEXT_EXT or ext == ""
    small = (obj.size or 0) < 5 * 1024 * 1024
    return (not risky, not texty, not small, name)


def discover(
    candidates: Iterable[ObjectRef],
    read: Callable[[ObjectRef, int], bytes],
    max_objects: int,
    max_bytes: int,
    max_total_bytes: int,
    on_progress: Callable[[str], None] | None = None,
    notes: list[str] | None = None,
    max_file_bytes: int = 20 * 1024 * 1024,
) -> SensitiveReport:
    candidates = list(candidates)
    chosen = sorted(candidates, key=_priority)[:max_objects]
    hits: dict[str, DetectorHit] = {}
    risky: list[dict] = []
    notes = list(notes or [])
    scanned = skipped = total = 0
    exhausted = False

    def check_name(display: str, size):
        for rx, desc, cat, sev in FILENAME_RULES:
            if rx.search(display.rsplit("!/", 1)[-1]):
                risky.append({"key": display, "reason": desc, "category": cat, "severity": sev.value, "size": size})
                return

    # Filename rules run on every listed object (no data read needed).
    for obj in candidates:
        check_name(obj.display, obj.size)

    documents = 0
    for i, obj in enumerate(chosen, 1):
        ext = PurePosixPath(obj.key.lower()).suffix
        if ext in BINARY_EXT or obj.size == 0:
            skipped += 1
            continue
        is_doc = ext in DOCUMENT_EXT
        if is_doc and (obj.size or 0) > max_file_bytes:
            skipped += 1
            if len(notes) < 20:
                notes.append(f"Skipped {obj.display}: {obj.size // (1024 * 1024)} MB is over the document size limit.")
            continue
        if total >= max_total_bytes:
            exhausted = True
            break
        if on_progress and (i == 1 or i % 10 == 0):
            on_progress(f"Inspecting object {i}/{len(chosen)}: {obj.display}")
        try:
            data = read(obj, min(max_file_bytes if is_doc else max_bytes, max_total_bytes - total))
        except Exception as exc:  # noqa: BLE001 - one unreadable object must not stop discovery
            skipped += 1
            if len(notes) < 20:
                notes.append(f"Could not read {obj.display}: {type(exc).__name__}")
            continue
        total += len(data)
        if is_doc:
            if obj.size and len(data) < obj.size:
                skipped += 1        # read budget cut the file short; documents can't be parsed partially
                continue
            members: list[str] = []
            text, note = extract_text(obj.key, data, members)
            for m in members:
                check_name(m.replace(obj.key, obj.display, 1), None)
            if note and len(notes) < 20:
                notes.append(note)
            if text is None:
                skipped += 1
                continue
            documents += 1
            text = text[:MAX_EXTRACTED_CHARS]
        else:
            if b"\x00" in data[:2048]:
                skipped += 1
                continue
            text = data.decode("utf-8", errors="replace")
        scanned += 1
        for det in DETECTORS:
            for m in det.pattern.finditer(text):
                value = m.group(0)
                if det.validate and not det.validate(value):
                    continue
                hit = hits.setdefault(det.id, DetectorHit(det.id, det.name, det.category, det.severity.value))
                hit.count += 1
                if obj.display not in hit.objects and len(hit.objects) < 25:
                    hit.objects.append(obj.display)
                sample = redact(value, det.id)
                if sample not in hit.samples and len(hit.samples) < 3:
                    hit.samples.append(sample)

    ordered = sorted(hits.values(), key=lambda h: (-Severity(h.severity).rank, -h.count))
    report = SensitiveReport(
        objects_listed=len(candidates), objects_scanned=scanned, objects_skipped=skipped, bytes_read=total,
        hits=ordered, risky_files=risky[:200], classification="NONE_FOUND", notes=notes, budget_exhausted=exhausted,
    )
    if report.secret_count or any(r["category"] == "secret" for r in risky):
        report.classification = "RESTRICTED"
    elif report.pii_count or any(r["category"] == "backup" for r in risky):
        report.classification = "CONFIDENTIAL"
    elif risky:
        report.classification = "INTERNAL"
    if exhausted:
        report.notes.append("Read budget reached; not every sampled object was inspected (Settings > Sensitive data discovery).")
    if len(candidates) > max_objects:
        report.notes.append(f"Sampled {max_objects} of {len(candidates)} listed objects, prioritising risky names and text files.")
    if documents:
        report.notes.append(f"{documents} document(s)/archive(s) (PDF, Office, zip, gzip, Parquet) were converted to text and scanned.")
    report.notes.append("Images, video, audio, executables, 7z/rar archives and Avro files are not content-scanned.")
    return report
