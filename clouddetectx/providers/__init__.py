"""Provider registry. SDKs are imported lazily so you only need the ones you use."""

from __future__ import annotations

from clouddetectx.config import Settings
from clouddetectx.providers.base import ProviderError, StorageProvider

PROVIDERS = {
    "aws": "Amazon Web Services (S3)",
    "azure": "Microsoft Azure (Blob Storage)",
    "gcp": "Google Cloud (Cloud Storage)",
}


def get_provider(name: str, settings: Settings) -> StorageProvider:
    name = name.lower()
    if name == "aws":
        from clouddetectx.providers.aws import AWSProvider

        return AWSProvider(settings)
    if name == "azure":
        from clouddetectx.providers.azure import AzureProvider

        return AzureProvider(settings)
    if name == "gcp":
        from clouddetectx.providers.gcp import GCPProvider

        return GCPProvider(settings)
    raise ProviderError(f"Unknown provider '{name}'. Choose one of: {', '.join(PROVIDERS)}")


__all__ = ["PROVIDERS", "ProviderError", "StorageProvider", "get_provider"]
