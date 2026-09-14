import json
import lzma
from pathlib import Path

import requests

from fgi_ios.logger import Logger

FRIDA_RELEASES_LATEST = "https://api.github.com/repos/frida/frida/releases/latest"
FRIDA_RELEASES_TAG = "https://api.github.com/repos/frida/frida/releases/tags/%s"
GADGET_ASSET_NAME = "frida-gadget-%s-ios-universal.dylib.xz"


class Cache:
    def __init__(self) -> None:
        self.home = Path.home() / ".fgi-ios"
        self.metadata_path = self.home / "metadata.json"
        self._metadata: dict[str, str] = {}

    def ensure(self) -> None:
        """Ensure cache directory and metadata file exist."""
        self.home.mkdir(parents=True, exist_ok=True)
        if not self.metadata_path.exists():
            self.metadata_path.write_text("{}", encoding="utf-8")
        with open(self.metadata_path, "r", encoding="utf-8") as f:
            self._metadata = json.load(f)

    def _save_metadata(self) -> None:
        with open(self.metadata_path, "w", encoding="utf-8") as f:
            json.dump(self._metadata, f, indent=2)

    def get_gadget_path(self, version: str | None = None, no_cache: bool = False) -> Path:
        """Get the path to a cached FridaGadget.dylib, downloading if necessary."""
        if version is None:
            version = self._resolve_latest_version()

        cached = self.home / version / "FridaGadget.dylib"
        if cached.exists() and not no_cache:
            Logger.info(f"Using cached FridaGadget v{version}")
            return cached

        return self._download_gadget(version)

    def get_cached_gadget_path(self, version: str | None = None) -> Path | None:
        """Get cached gadget path without downloading (for offline mode)."""
        if version:
            cached = self.home / version / "FridaGadget.dylib"
            if cached.exists():
                return cached
            return None

        # Find any cached version
        for entry in sorted(self.home.iterdir(), reverse=True):
            if entry.is_dir():
                gadget = entry / "FridaGadget.dylib"
                if gadget.exists():
                    Logger.info(f"Using cached FridaGadget v{entry.name}")
                    return gadget
        return None

    def _resolve_latest_version(self) -> str:
        Logger.info("Resolving latest Frida version...")
        try:
            resp = requests.get(FRIDA_RELEASES_LATEST, timeout=15)
            resp.raise_for_status()
            version = resp.json()["tag_name"]
            Logger.info(f"Latest Frida version: {version}")
            return version
        except Exception as e:
            Logger.fatal(f"Failed to resolve latest Frida version: {e}")
            raise  # unreachable, but keeps type checker happy

    def _download_gadget(self, version: str) -> Path:
        Logger.info(f"Downloading FridaGadget v{version} for iOS (universal)...")

        asset_name = GADGET_ASSET_NAME % version
        url = f"https://github.com/frida/frida/releases/download/{version}/{asset_name}"

        try:
            resp = requests.get(url, stream=True, timeout=60)
            resp.raise_for_status()
        except Exception as e:
            Logger.fatal(f"Failed to download FridaGadget: {e}")
            raise

        # Decompress .xz
        Logger.info("Decompressing gadget...")
        xz_data = resp.content
        dylib_data = lzma.decompress(xz_data)

        # Save to cache
        version_dir = self.home / version
        version_dir.mkdir(parents=True, exist_ok=True)
        gadget_path = version_dir / "FridaGadget.dylib"
        gadget_path.write_bytes(dylib_data)

        self._metadata["frida_version"] = version
        self._save_metadata()

        Logger.info(f"Cached FridaGadget v{version} ({len(dylib_data) / 1024 / 1024:.1f} MB)")
        return gadget_path
