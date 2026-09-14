import sys
import colorama


class Logger:
    _verbose = False

    @staticmethod
    def initialize(verbose: bool) -> None:
        colorama.init(autoreset=True)
        Logger._verbose = verbose

    @staticmethod
    def info(message: str) -> None:
        print(f"{colorama.Fore.GREEN}[*]{colorama.Fore.RESET} {message}")

    @staticmethod
    def warn(message: str) -> None:
        print(f"{colorama.Fore.YELLOW}[!]{colorama.Fore.RESET} {message}")

    @staticmethod
    def error(message: str) -> None:
        print(f"{colorama.Fore.RED}[-]{colorama.Fore.RESET} {message}", file=sys.stderr)

    @staticmethod
    def debug(message: str) -> None:
        if Logger._verbose:
            print(f"{colorama.Fore.CYAN}[D]{colorama.Fore.RESET} {message}")

    @staticmethod
    def fatal(message: str) -> None:
        Logger.error(message)
        sys.exit(1)
