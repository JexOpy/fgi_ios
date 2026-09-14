### frida-gadget injector for iOS (fgi-ios)

Another frida-gadget injector, built specifically for iOS IPA files:

* Windows, Linux & macOS support (pure Python Mach-O parser/injector — **no Mac, Xcode, or `insert_dylib` tool required**)
* Automatically downloads and caches FridaGadget iOS universal releases from GitHub
* Built-in configs (`listen`, `connect`, `script`) that save a lot of (copy/paste) time
* Injects `@executable_path/Frameworks/<library_name>` `LC_LOAD_DYLIB` load commands into Mach-O 64-bit binaries
* Strips code signature load commands (`LC_CODE_SIGNATURE`) automatically to allow sideloading
* Can rename frida-gadget and script files to bypass detection by name
* Clean extraction, patching, and repackaging of `.ipa` archives using standard libraries

### Installing

```bash
pip install git+https://github.com/JexOpy/fgi_ios.git
```

Or clone and install locally:

```bash
git clone https://github.com/JexOpy/fgi_ios.git
cd fgi_ios
pip install -e .
```

### Usage

Run `fgi-ios -h` to view all options:

```
usage: fgi-ios [-h] -i INPUT [-o OUT] [-t {listen,connect,script}]
               [-c CONFIG_PATH] [-l SCRIPT_PATH] [-n LIBRARY_NAME]
               [-s SCRIPT_NAME] [-r TEMP_ROOT_PATH] [--no-cleanup]
               [--frida-version FRIDA_VERSION] [--gadget-path GADGET_PATH]
               [--offline-mode] [--no-cache] [-v]

Frida Gadget Injector for iOS — inject FridaGadget into IPA files

options:
  -h, --help            show this help message and exit
  -i, --input INPUT     Target IPA file
  -o, --out OUT         Output IPA file
  -t, --config-type {listen,connect,script}
                        Target config type (default: listen)
  -c, --config-path CONFIG_PATH
                        Custom config path
  -l, --script-path SCRIPT_PATH
                        Script path (e.g. agent.js)
  -n, --library-name LIBRARY_NAME
                        frida-gadget library name (default: FridaGadget.dylib, must end with .dylib)
  -s, --script-name SCRIPT_NAME
                        frida-gadget script name (default: agent.js)
  -r, --temp-root-path TEMP_ROOT_PATH
                        Root path where temporary directory will be created
  --no-cleanup          Do not remove temporary directory (useful for debugging)
  --frida-version FRIDA_VERSION
                        Specific frida version (e.g 16.7.19)
  --gadget-path GADGET_PATH
                        Use a local FridaGadget.dylib
  --offline-mode        Disable updates check for deps / use cached gadget only
  --no-cache            Force re-download of FridaGadget
  -v, --verbose         Verbose logging (useful for debugging)
```

#### Examples

**Basic injection (listen mode):**
```bash
fgi-ios -i target.ipa
```
Output IPA will be generated at `./target.patched.ipa`.

**Script mode (auto-run Frida script on app launch):**
```bash
fgi-ios -i target.ipa -t script -l agent.js
```

**Bypass detection by renaming gadget and script:**
```bash
fgi-ios -i target.ipa -t script -l agent.js -n UnityFramework.dylib -s UnityFramework.js
```

**Specify custom output path:**
```bash
fgi-ios -i target.ipa -t script -l agent.js -o patched.ipa
```

#### Built-in configs

These configs are taken from [Frida Gadget documentation](https://frida.re/docs/gadget/):

* **`listen`** (default):
```json
{
  "interaction": {
    "type": "listen",
    "address": "0.0.0.0",
    "port": 27042,
    "on_port_conflict": "fail",
    "on_load": "wait"
  }
}
```

* **`connect`**:
```json
{
  "interaction": {
    "type": "connect",
    "address": "0.0.0.0",
    "port": 27052
  }
}
```

* **`script`**:
```json
{
  "interaction": {
    "type": "script",
    "path": "agent.js"
  }
}
```

### Signing / Sideloading

After patching, you will need to sign the output `.ipa` file using your preferred sideloading tool:
- **TrollStore** (no re-signing needed on supported iOS versions)
- **AltStore**
- **Sideloadly**
- **iOS App Signer** / **xcrun codesign**

### Acknowledgements

- Inspired by [fgi](https://github.com/commonuserlol/fgi) by commonuserlol.
- [Frida](https://frida.re/) by Ole André Vadla Ravnås.
