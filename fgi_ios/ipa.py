"""
IPA file operations — extract, modify, and repackage iOS app bundles.
Uses Python's built-in zipfile module with streaming I/O for minimal RAM footprint.
"""

import plistlib
import shutil
import tempfile
import zipfile
from pathlib import Path

from fgi_ios.logger import Logger
from fgi_ios.macho import inject_dylib


class IPA:
    def __init__(self, ipa_path: Path, temp_root: Path | None = None) -> None:
        self.ipa_path = ipa_path
        self.temp_dir = Path(tempfile.mkdtemp(prefix="fgi-ios-", dir=temp_root))
        self.payload_dir: Path | None = None
        self.app_dir: Path | None = None
        self.executable_path: Path | None = None
        self.frameworks_dir: Path | None = None

    def extract(self) -> None:
        """Extract IPA (zip) to temp directory."""
        Logger.info(f"Extracting IPA: {self.ipa_path.name}")
        with zipfile.ZipFile(self.ipa_path, "r") as zf:
            zf.extractall(self.temp_dir)

        # Locate Payload/*.app/
        self.payload_dir = self.temp_dir / "Payload"
        if not self.payload_dir.exists():
            Logger.fatal("Invalid IPA: 'Payload' directory not found")

        app_dirs = [d for d in self.payload_dir.iterdir() if d.is_dir() and d.suffix == ".app"]
        if not app_dirs:
            Logger.fatal("Invalid IPA: No .app directory found in Payload/")

        self.app_dir = app_dirs[0]
        Logger.debug(f"App directory: {self.app_dir.name}")

        # Read Info.plist to find the main executable
        info_plist_path = self.app_dir / "Info.plist"
        if not info_plist_path.exists():
            Logger.fatal("Info.plist not found in app bundle")

        try:
            with open(info_plist_path, "rb") as f:
                info_plist = plistlib.load(f)
        except Exception as e:
            Logger.fatal(f"Failed to parse Info.plist: {e}")
            raise

        executable_name = info_plist.get("CFBundleExecutable")
        if not executable_name:
            Logger.fatal("CFBundleExecutable not found in Info.plist")

        self.executable_path = self.app_dir / str(executable_name)
        if not self.executable_path.exists():
            Logger.fatal(f"Executable not found: {executable_name}")

        Logger.info(f"Found executable: {executable_name}")

        # Ensure Frameworks directory exists
        self.frameworks_dir = self.app_dir / "Frameworks"
        self.frameworks_dir.mkdir(exist_ok=True)

        # Remove existing _CodeSignature to allow clean resigning without signature collisions
        codesig_dir = self.app_dir / "_CodeSignature"
        if codesig_dir.exists():
            Logger.debug("Removing original _CodeSignature directory")
            shutil.rmtree(codesig_dir, ignore_errors=True)

    def inject_gadget(
        self,
        gadget_dylib_path: Path,
        config_content: str,
        library_name: str = "FridaGadget.dylib",
        script_path: Path | None = None,
        script_name: str = "agent.js",
    ) -> None:
        """
        Inject FridaGadget into the app bundle:
        1. Copy dylib to Frameworks/
        2. Write config file alongside dylib
        3. Optionally copy script file
        4. Inject LC_LOAD_DYLIB into the main binary
        """
        assert self.frameworks_dir is not None
        assert self.executable_path is not None

        # 1. Copy FridaGadget dylib
        dest_dylib = self.frameworks_dir / library_name
        shutil.copy2(gadget_dylib_path, dest_dylib)
        Logger.info(f"Copied gadget: {library_name}")

        # 2. Write config file (named after the library: FridaGadget.config or MyLib.config)
        config_name = Path(library_name).stem + ".config"
        dest_config = self.frameworks_dir / config_name
        dest_config.write_text(config_content, encoding="utf-8")
        Logger.info(f"Wrote config: {config_name}")

        # 3. Copy script if provided
        if script_path:
            dest_script = self.frameworks_dir / script_name
            shutil.copy2(script_path, dest_script)
            Logger.info(f"Copied script: {script_name}")

        # 4. Inject LC_LOAD_DYLIB into the main executable
        dylib_load_path = f"@executable_path/Frameworks/{library_name}"
        inject_dylib(self.executable_path, dylib_load_path, strip_codesig=True)

    def repackage(self, output_path: Path) -> None:
        """
        Repackage the modified app bundle into a new IPA.
        Uses 1MB buffered chunk streaming to maintain minimal RAM usage even on multi-GB IPAs,
        and sets Unix POSIX file attributes (0o755) for all executables and frameworks.
        """
        Logger.info(f"Repackaging IPA: {output_path.name}")

        output_path.parent.mkdir(parents=True, exist_ok=True)

        with zipfile.ZipFile(output_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=1) as zf:
            for file_path in sorted(self.temp_dir.rglob("*")):
                arcname = file_path.relative_to(self.temp_dir).as_posix()

                if file_path.is_dir():
                    zinfo = zipfile.ZipInfo(arcname + "/")
                    zinfo.external_attr = (0o755 & 0xFFFF) << 16
                    zf.writestr(zinfo, b"")
                elif file_path.is_file():
                    zinfo = zipfile.ZipInfo.from_file(file_path, arcname)

                    # Preserve/set Unix execution permissions (+x for binaries and dylibs)
                    is_executable = (
                        file_path == self.executable_path
                        or file_path.suffix.lower() in (".dylib", ".so")
                        or "Frameworks/" in arcname
                    )
                    mode = 0o755 if is_executable else 0o644
                    zinfo.external_attr = (mode & 0xFFFF) << 16

                    # Stream file in 1MB chunks to avoid memory spikes
                    with open(file_path, "rb") as src_f, zf.open(zinfo, "w") as dest_f:
                        shutil.copyfileobj(src_f, dest_f, length=1024 * 1024)

        size_mb = output_path.stat().st_size / 1024 / 1024
        Logger.info(f"Output IPA: {output_path} ({size_mb:.1f} MB)")

    def cleanup(self) -> None:
        """Remove temp directory."""
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            Logger.debug(f"Cleaned up: {self.temp_dir}")
