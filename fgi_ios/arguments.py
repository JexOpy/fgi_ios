import argparse
import json
from dataclasses import dataclass
from pathlib import Path
import tempfile
from typing import Any


@dataclass
class Arguments:
    input: Path
    out: Path | None
    config_type: str | None
    config_path: Path | None
    script_path: Path | None
    library_name: str
    script_name: str
    temp_root_path: Path
    no_cleanup: bool
    frida_version: str | None
    gadget_path: Path | None
    offline_mode: bool
    no_cache: bool
    verbose: bool

    @staticmethod
    def create() -> "Arguments":
        parser = argparse.ArgumentParser(
            prog="fgi-ios",
            description="Frida Gadget Injector for iOS — inject FridaGadget into IPA files",
        )

        _ = parser.add_argument("-i", "--input", type=Path, required=True, help="Target IPA file")
        _ = parser.add_argument("-o", "--out", type=Path, help="Output IPA file")

        _ = parser.add_argument(
            "-t",
            "--config-type",
            type=str,
            choices=["listen", "connect", "script"],
            default="listen",
            help="Target config type",
        )
        _ = parser.add_argument("-c", "--config-path", type=Path, help="Custom config path")
        _ = parser.add_argument("-l", "--script-path", type=Path, help="Script path")

        _ = parser.add_argument(
            "-n",
            "--library-name",
            type=str,
            default="FridaGadget.dylib",
            help='frida-gadget library name, must end with ".dylib"',
        )
        _ = parser.add_argument(
            "-s",
            "--script-name",
            type=str,
            default="agent.js",
            help="frida-gadget script name",
        )

        _ = parser.add_argument(
            "-r",
            "--temp-root-path",
            type=Path,
            default=Path(tempfile.gettempdir()),
            help="Root path where temporary directory will be created",
        )

        _ = parser.add_argument(
            "--no-cleanup",
            action="store_true",
            default=False,
            help="Do not remove temporary directory (useful for debugging)",
        )
        _ = parser.add_argument("--frida-version", type=str, help="Specific frida version (e.g 16.7.19)")
        _ = parser.add_argument("--gadget-path", type=Path, help="Use a local FridaGadget.dylib")

        _ = parser.add_argument(
            "--offline-mode",
            action="store_true",
            default=False,
            help="Disable updates check for deps / use cached gadget only",
        )
        _ = parser.add_argument(
            "--no-cache",
            action="store_true",
            default=False,
            help="Force re-download of FridaGadget",
        )
        _ = parser.add_argument(
            "-v",
            "--verbose",
            action="store_true",
            default=False,
            help="Verbose logging (useful for debugging)",
        )

        args = parser.parse_args()

        return Arguments(
            input=args.input,
            out=args.out,
            config_type=args.config_type,
            config_path=args.config_path,
            script_path=args.script_path,
            library_name=args.library_name,
            script_name=args.script_name,
            temp_root_path=args.temp_root_path,
            no_cleanup=args.no_cleanup,
            frida_version=args.frida_version,
            gadget_path=args.gadget_path,
            offline_mode=args.offline_mode,
            no_cache=args.no_cache,
            verbose=args.verbose,
        )

    def validate(self) -> None:
        from fgi_ios.logger import Logger

        if not self.input.exists():
            Logger.fatal(f"Input IPA doesn't exist: {self.input}")

        if not self.input.name.endswith(".ipa"):
            Logger.fatal(f"Input file is not an IPA: {self.input}")

        if self.out is None:
            if ".ipa" not in self.input.name:
                self.out = Path.cwd() / (self.input.absolute().name + ".patched.ipa")
            else:
                self.out = Path.cwd() / self.input.name.replace(".ipa", ".patched.ipa")

        if self.out.exists():
            Logger.fatal(f'Out path exists, delete, rename or specify manually via "-o": {self.out}')

        if not self.out.name.endswith(".ipa"):
            Logger.fatal("Out filename must end with .ipa")

        if not (self.is_builtin_config() or (self.config_path and not self.config_type)):
            Logger.fatal('Specify "config-type" or "config-path"')

        if self.config_path and not self.config_path.exists():
            Logger.fatal(f"Config file does not exist: {self.config_path}")

        if self.is_script_required():
            if not self.script_path:
                Logger.fatal(
                    'Script is required when "config-type" equals "script" '
                    'or config provided via "config-path" has "type": "script"'
                )
            if not self.script_path.exists():
                Logger.fatal(f"Script file does not exist: {self.script_path}")

        if not self.library_name.endswith(".dylib"):
            Logger.fatal('Invalid name for frida library, must end with ".dylib"')

        if not self.temp_root_path.exists():
            Logger.fatal(f"Root temp path doesn't exist: {self.temp_root_path}")

        if self.gadget_path and not self.gadget_path.exists():
            Logger.fatal(f"Gadget file does not exist: {self.gadget_path}")

        if self.offline_mode and self.no_cache:
            Logger.fatal("Cannot use --offline-mode with --no-cache")

    def is_builtin_config(self) -> bool:
        return self.config_path is None and self.config_type is not None

    def is_script_required(self) -> bool:
        if self.config_type == "script":
            return True
        if self.config_path:
            try:
                with open(self.config_path, "r", encoding="utf8") as f:
                    config_dict: dict[str, Any] = json.load(f)
                interaction = config_dict.get("interaction", {})
                return interaction.get("type") == "script"
            except Exception:
                return False
        return False
