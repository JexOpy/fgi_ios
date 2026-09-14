"""Main application — orchestrates the FridaGadget injection pipeline."""

import traceback

from fgi_ios.arguments import Arguments
from fgi_ios.cache import Cache
from fgi_ios.frida_config import get_config_content
from fgi_ios.ipa import IPA
from fgi_ios.logger import Logger


class App:
    def run(self) -> None:
        arguments = Arguments.create()
        Logger.initialize(arguments.verbose)
        arguments.validate()

        self._execute(arguments)

    @staticmethod
    def entry() -> None:
        """Entry point for console_scripts."""
        main()

    def _execute(self, args: Arguments) -> None:
        assert args.out is not None

        # 1. Resolve FridaGadget dylib
        gadget_path = self._resolve_gadget(args)

        # 2. Determine config content
        config_content = self._resolve_config(args)

        # 3. Extract, inject, repackage
        ipa = IPA(args.input, temp_root=args.temp_root_path)
        try:
            ipa.extract()
            ipa.inject_gadget(
                gadget_dylib_path=gadget_path,
                config_content=config_content,
                library_name=args.library_name,
                script_path=args.script_path,
                script_name=args.script_name,
            )
            ipa.repackage(args.out)
            Logger.info(f"IPA is ready at {args.out}")
        finally:
            if not args.no_cleanup:
                ipa.cleanup()
            else:
                Logger.info(f"Temp directory kept: {ipa.temp_dir}")

    def _resolve_gadget(self, args: Arguments):
        """Resolve FridaGadget.dylib path — from local file, cache, or download."""
        if args.gadget_path:
            Logger.info(f"Using local gadget: {args.gadget_path}")
            return args.gadget_path

        cache = Cache()
        cache.ensure()

        if args.offline_mode:
            Logger.warn("Offline mode — using cached gadget only")
            path = cache.get_cached_gadget_path(version=args.frida_version)
            if path is None:
                Logger.fatal("No cached FridaGadget found. Run without --offline-mode first.")
            return path

        return cache.get_gadget_path(version=args.frida_version, no_cache=args.no_cache)

    def _resolve_config(self, args: Arguments) -> str:
        """Resolve FridaGadget config content."""
        if args.config_path:
            Logger.info(f"Using custom config: {args.config_path}")
            return args.config_path.read_text(encoding="utf-8")

        assert args.config_type is not None
        Logger.info(f"Using built-in config: {args.config_type}")
        return get_config_content(args.config_type, args.script_name)


def main() -> None:
    app = App()
    try:
        app.run()
    except KeyboardInterrupt:
        Logger.warn("Aborting...")
    except (RuntimeError, AssertionError) as e:
        Logger.error(str(e))
    except SystemExit:
        pass
    except Exception as e:
        Logger.error(f"Unexpected exception: {e}")
        Logger.error(traceback.format_exc())


if __name__ == "__main__":
    main()
