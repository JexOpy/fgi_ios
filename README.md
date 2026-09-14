### frida-gadget injector (fgi-ios)
Another frida-gadget injector for IPA:

* Windows & Linux support
* Automatically downloads and updates dependencies
* Injects frida-gadget into iOS IPA Mach-O binaries
* Built-in configs that save a lot of (copy/paste) time
* Can rename frida-gadget and script libraries to bypass detection by name
* Pure Python implementation without needing macOS or insert_dylib

### Installing

#### Windows (tested on Windows 11)

* Run `pip install git+https://github.com/JexOpy/fgi_ios`
* Restart current cmd/powershell/terminal session

#### Linux

* Run `pip install git+https://github.com/JexOpy/fgi_ios`
  * Add `--break-system-packages` if pip refuses to install
* Add `~/.local/bin` to path

### Usage

**NOTE**: On linux if you're using `/tmp` for temp files and working with large IPA, remount tmpfs using `mount -o remount,size=4G /tmp`

Run `fgi-ios -h` to get options

#### Built-in configs

These configs are taken from [Frida website](https://frida.re)

If you need to use other configuration options, such as changing `on_load` to `resume` or setting custom interaction parameters, consider using the `--config-path` option

#### Examples

1. `fgi-ios -i target.ipa` - inject frida-gadget into target.ipa with **listen** mode

2. `fgi-ios -i target.ipa -o out.ipa` - same as 1 + ready IPA will be named `out.ipa` instead of `target.patched.ipa`

3. `fgi-ios -i target.ipa --frida-version 16.7.19` - use specific version (16.7.19) of frida-gadget instead of the latest one

4. `fgi-ios -i target.ipa --offline-mode` - inject frida-gadget into target.ipa with **listen** mode and **skip frida-gadget update check**

5. `fgi-ios -i target.ipa -t script -l index.js` - inject frida-gadget into target.ipa with `index.js` as **script**

6. `fgi-ios -i target.ipa -c myconfig.json -r .` - inject frida-gadget into target.ipa with **myconfig.json** config and current directory as parent temporary directory **(DANGEROUS, current directory will be filled with temp files)**
    * `fgi-ios` **will check does config require script and raise exception** if no `-l` option provided
    * Parent temporary directory **also will be checked**

7. `fgi-ios -i target.ipa -t script -l index.js -n libnotafrida.dylib -s libnotascript.js` - same as 1, but use **script** type + rename frida-gadget into `libnotafrida.dylib` and script into `libnotascript.js`
    * Frida-gadget library name **must end with** `.dylib`

8. `fgi-ios -i target.ipa --config-type listen --no-cleanup -v` - same as 1 + do **NOT** remove temporary directory and enable debug logs
    * Temporary directory can be found using log message:

    ```
    Temp directory kept: /tmp/whatever...
                         ~~~~~~~~~~~~~
                             Here
    ```

### Acknowledgements

[fgi](https://github.com/commonuserlol/fgi) - Original frida-gadget injector for APK

### License

This repository is licensed under a GNU General Public v3 License.

See [LICENSE](LICENSE) file for details
