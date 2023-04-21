# libSpookyAction
*A library for interfacing with Desfire tags through a PN532*

[![pipeline status](https://git.mittelab.org/proj/libspookyaction/badges/master/pipeline.svg)](https://git.mittelab.org/proj/libspookyaction/-/commits/master)

**Repo:** https://git.mittelab.org/proj/libspookyaction  
**Documentation:** https://proj.mittelab.dev/libspookyaction/  
**PlatformIO lib:** https://platformio.org/lib/show/12999/libSpookyAction

## Using the library in your project
1. **This library requires you to enable C++17 (or above) and is developed for ESP-IDF.** If you are using another
   framework, e.g. Arduino, or a different C++ version, it might work, or it might not, but **you are on your own**.
2. On ESP32, this requires plain old DES to be enabled in MbedTLS (the library that provides SSL functionalities).
   This is because it is used in one of the Desfire implementations. So make sure that your `sdkconfig.defaults` 
   contains the following line:
   ```ini
   CONFIG_MBEDTLS_DES_C=y
   ```
3. Make sure you have enabled C++17. For ESP-IDF, this requires to unset C++11 and C++17. In your `platformio.ini`:
   ```ini
   [env:your_env]
   platform = espressif32
   framework = espidf
   ; ...
   ```
4. Check that your app compiles with these settings, first, using `pio run` or `pio test`. If it does,
5. add to `platformio.ini` the dependency on libSpookyAction:
   ```ini
   [env:your_env]
   ; ... all the above flags, plus:
   lib_deps = mittelab/libSpookyAction
   ```
6. You can now use libSpookyAction. The includes are in the subfolders `desfire/` and `pn532/`, and the objects in the
   corresponding `::desfire` and `::pn532` namespaces. You should check out some of the [examples][1] to get started,
   as you will need to piece together several things to get everything running.  
   See for example [how to initialize][2] the communication protocol.

[1]: https://platformio.org/lib/show/12999/libSpookyAction/examples
[2]: https://git.mittelab.org/proj/libspookyaction/-/blob/master/libspookyaction/examples/initialize.cpp

## Developer guide

### Folder structure
Important folders:
* `libspookyaction/`  
  Library source code, divided in headers, source code, examples.
    * `libspookyaction/{include, src, examples}/{pn532, desfire}/`  
      All sources are placed in the subfolders *pn532* and *desfire*. This reflects the namespace in which
      all the objects are located, and keeps the includes clean.
    * `libspookyaction/examples/sdkconfig.defaults`  
      This is the default ESP-IDF SDK config file that should be used when building the examples.  
    * `libspookyaction/{include, src}/esp32/`  
      All ESP32-specific code should go in a subfolder *esp32*. In the future we might support more platforms, and we 
      would like to compile this code only conditionally. Currently the ESP32-specific implementation of the
      cryptographic primitives are isolated here.
* `tests/`  
  Subfolder containing the unit test project.
    * `tests/lib/libspookyaction/`  
      Symlink to `libspookyaction/`, to allow the unit tests to pick up the local library folder
    * `tests/src/ut`  
      The UT suite suggested by ESP-IDF, Unity, is somehow limited for extensive C++ testing, so everything reusable,
      and anything that is not a direct test invocation, is implemented here in a separate `::ut` namespace. 
    * `tests/test`  
      We need to keep this folder for PlatformIO to believe we are providing unit test in our own
      custom entry point.

Secondary folders:
* `cicd/` Helper files needed by CI/CD
* `docs/` Doxygen config and additional doxygen sources
* `misc/` Helper files needed for setting up development, logos, non-source material.

### Setting up development
0. [Install PlatformIO CLI](https://platformio.org/install/cli).
1. Prepare `tests/platformio.ini`. You can, for example
    * Customize `tests/platformio.ini.sample` to your board and setup, or
    * Copy `cicd/platformio.ini`, the file used by CI/CD
2. Generate a compilation database for your IDE of choice using
   ```shell
   $> ./misc/gen-compiledb.py tests/platformio.ini       
   ```
   **You have to regenerate this when a new file is added.**
3. You are now using the unit test project to "host" the library (so you will see all usages of instantiated templates,
   for example).
4. Use the provided `.clang-format` file to format the source, e.g. by
   ```shell
   $> clang-format --style file -i libspookyaction/src/pn532/my_file.cpp
   ```

### Running the tests
**Note on the test project structure.**
We set up the unit test project in such a way that we can use both `pio run` and `pio test` to run the unit tests.
The two commands are similar but different enough that some commands are available for one and not the other (for
example, the compilation database is generated for `pio run` but not `pio test`). We work around this by providing a
test transport (similar to the one provided by `pio test`), our own `app_main()` function and building sources and tests
together.

0. Make sure you have setup your `tests/platformio.ini` as above.
1. Change directory and use either `pio test` or `pio run`, as follows:
   ```shell
   $> cd tests/
   $> pio test -vv
   ```

### Building the documentation
1. Install Doxygen (or run through Docker), and run
   ```shell
   $> doxygen ./doxygen.conf
   ```
2. The documentation can be seen at `./docs/_build/html/index.html`.