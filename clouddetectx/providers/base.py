"""Interface every cloud provider implements."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime

from clouddetectx.models import AccessEvent, ChangeEvent, Finding, Posture, RemediationAction, Resource


class ProviderError(RuntimeError):
    """Raised for configuration / authentication problems the user must fix."""


class StorageProvider(ABC):
    name: str = ""
    display_name: str = ""

    @abstractmethod
    def account_label(self) -> str:
        """Human readable identity of the scanned account/subscription/project."""

    @abstractmethod
    def list_resources(self) -> list[Resource]:
        """Every storage resource visible to the current credentials."""

    @abstractmethod
    def get_resource(self, name: str) -> Resource:
        """Look up one resource by the name shown in list_resources()."""

    @abstractmethod
    def collect_posture(self, resource: Resource) -> Posture:
        """Read the security configuration of a resource (read-only)."""

    @abstractmethod
    def evaluate(self, posture: Posture) -> list[Finding]:
        """Turn raw configuration into findings. Pure function, no API calls."""

    @abstractmethod
    def collect_access_events(
        self, posture: Posture, since: datetime
    ) -> tuple[list[AccessEvent], list[str], list[str]]:
        """Return (events, log sources used, notes about missing/partial logs)."""

    @abstractmethod
    def collect_change_events(self, posture: Posture, since: datetime) -> tuple[list[ChangeEvent], list[str]]:
        """Return (control-plane changes such as 'made public', notes)."""

    # -- optional capabilities (data discovery and external verification) -------------
    def sample_objects(self, posture: Posture, limit: int) -> tuple[list, list[str]]:
        """Return (list of sensitive.ObjectRef, notes). Read-only listing."""
        raise ProviderError(f"Object listing is not supported for {self.display_name}.")

    def read_object(self, posture: Posture, obj, max_bytes: int) -> bytes:
        """Return at most max_bytes from the start of the object."""
        raise ProviderError(f"Object reads are not supported for {self.display_name}.")

    def analyze_identity(self):
        """iam.IamReport of who can access storage, or None if not supported for this cloud."""
        return None

    def account_id(self) -> str:
        """AWS account ID / Azure subscription ID / GCP project ID."""
        return "default"

    def account_checks(self) -> tuple[list[Finding], list[str], dict[str, str]]:
        """Account-wide findings beyond storage: (findings, notes, errors per check area)."""
        return [], [], {}

    def list_accounts(self) -> list[dict]:
        """Every account this login can scan: [{"id", "name"}] (Organizations / subscriptions / projects)."""
        raise ProviderError(f"Multi-account scanning is not supported for {self.display_name}.")

    def for_account(self, account_id: str) -> "StorageProvider":
        """A provider bound to another account from list_accounts()."""
        raise ProviderError(f"Multi-account scanning is not supported for {self.display_name}.")

    def rollback(self, resource: Resource, applied: list[dict], dry_run: bool) -> list[RemediationAction]:
        """Undo applied remediation actions (newest first) using the configuration saved before them."""
        raise ProviderError(f"Rollback is not supported for {self.display_name}.")

    def probe_targets(self, posture: Posture, sample: list) -> list:
        """Public URLs (probe.ProbeTarget) to request anonymously."""
        return []

    @abstractmethod
    def remediate(
        self, posture: Posture, findings: list[Finding], dry_run: bool, harden: bool
    ) -> list[RemediationAction]:
        """Remove public exposure. With dry_run=True only plan, change nothing."""
