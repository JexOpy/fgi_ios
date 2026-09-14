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
        try:
            with open(self.metadata_path, "r", encoding="utf-8") as f:
                self._metadata = json.load(f)
        except Exception:
            self._metadata = {}

    def _save_metadata(self) -> None:
        try:
            with open(self.metadata_path, "w", encoding="utf-8") as f:
                json.dump(self._metadata, f, indent=2)
        except Exception as e:
            Logger.debug(f"Failed to save metadata: {e}")

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
        """Get cached gadget path without downloading (for offline mode or fallback)."""
        if version:
            cached = self.home / version / "FridaGadget.dylib"
            if cached.exists():
                return cached
            return None

        # Find the latest cached version by sorting directories
        if not self.home.exists():
            return None

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
            if resp.status_code == 200:
                version = resp.json()["tag_name"]
                Logger.info(f"Latest Frida version: {version}")
                return version
            elif resp.status_code == 403:
                # GitHub rate limit reached — try falling back to existing cache
                cached_gadget = self.get_cached_gadget_path()
                if cached_gadget:
                    Logger.warn("GitHub API rate limit exceeded. Falling back to cached FridaGadget.")
                    return cached_gadget.parent.name
                Logger.fatal("GitHub API rate limit exceeded and no local cached gadget found.")
            else:
                resp.raise_for_status()
        except requests.RequestException as e:
            # Network issue — fallback to cached if available
            cached_gadget = self.get_cached_gadget_path()
            if cached_gadget:
                Logger.warn(f"Could not reach GitHub ({e}). Falling back to cached FridaGadget.")
                return cached_gadget.parent.name
            Logger.fatal(f"Failed to resolve latest Frida version: {e}")

        raise SystemExit(1)

    def _download_gadget(self, version: str) -> Path:
        Logger.info(f"Downloading FridaGadget v{version} for iOS (universal)...")

        asset_name = GADGET_ASSET_NAME % version
        url = f"https://github.com/frida/frida/releases/download/{version}/{asset_name}"

        version_dir = self.home / version
        version_dir.mkdir(parents=True, exist_ok=True)
        gadget_path = version_dir / "FridaGadget.dylib"
        tmp_path = version_dir / "FridaGadget.dylib.tmp"

        try:
            with requests.get(url, stream=True, timeout=60) as resp:
                resp.raise_for_status()
                Logger.info("Decompressing gadget stream...")
                decompressor = lzma.LZMADecompressor()
                total_bytes = 0

                with open(tmp_path, "wb") as out_f:
                    for chunk in resp.iter_content(chunk_size=65536):
                        if chunk:
                            decompressed = decompressor.decompress(chunk)
                            if decompressed:
                                out_f.write(decompressed)
                                total_bytes += len(decompressed)

            # Atomic rename once download and decompression succeed completely
            tmp_path.replace(gadget_path)
        except Exception as e:
            if tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
            Logger.fatal(f"Failed to download/decompress FridaGadget: {e}")
            raise

        self._metadata["frida_version"] = version
        self._save_metadata()

        Logger.info(f"Cached FridaGadget v{version} ({total_bytes / 1024 / 1024:.1f} MB)")
        return gadget_path
