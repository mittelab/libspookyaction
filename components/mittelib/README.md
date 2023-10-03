# Mittelib
*Nice C++17 goodies made in Mittelab*

[![pipeline status](https://git.mittelab.org/proj/mittelib/badges/master/pipeline.svg)](https://git.mittelab.org/proj/mittelib/-/commits/master)

**Repo:** https://git.mittelab.org/proj/mittelib  
**Documentation:** https://proj.mittelab.dev/mittelib/  
**PlatformIO lib:** https://platformio.org/lib/show/12998/mitteLib

This library aim at providing some handy, general purpose functionalities to embedded development. The C++ STL is
rich but some functionalities (e.g. `std::variant`) require features (e.g. CTTI) that are generally disabled on
embedded platforms; other helper classes instead are common patterns when interoperating with C libraries. This was
originally developed for ESP-IDF, in C++17, but it should be platform and framework independent (depending only on
C++ 17). Among the added functionalities, binary streams, enum-based variants, and observer-pattern helper classes.

## Using the library in your project
1. **This library requires you to enable C++17 (or above) and is developed for ESP-IDF.** If you are using another
   framework, e.g. Arduino, or a different C++ version, it might work, or it might not, but **you are on your own**.
2. Make sure you have enabled C++17. For ESP-IDF, this requires to unset C++11 and C++17. In your `platformio.ini`:
   ```ini
   [env:your_env]
   platform = espressif32
   framework = espidf
   ```
3. Check that your app compiles with these settings, first, using `pio run` or `pio test`. If it does,
4. add to `platformio.ini` the dependency on mitteLib:
   ```ini
   [env:your_env]
   ; ... all the above flags, plus:
   lib_deps = mittelab/mitteLib
   ```
5. You can now use mitteLib. The includes are in the subfolder `mlab/`, and the objects in the `::mlab` namespace:
   ```c++
   #include <mlab/observable.hpp>
   
   // ...
   
   extern "C" void app_main() {
       mlab::observable<unsigned int> observable;
       // ...
   }
   ```


## Developer guide

### Folder structure
Important folders:
* `mittelib/`  
  Library source code, divided in headers and source code.
  * `mittelib/{include, src}/mlab/`  
    All sources are placed in the subfolder *mlab*. This reflects the namespace in which
    all the objects are located, and keeps the includes clean.
* `tests/`  
  Subfolder containing the unit test projects. 
  * `tests/lib/mittelib/`  
    Symlink to `mittelib/`, to allow the unit tests to pick up the local library folder
  * `tests/test/.keep`  
    We need to keep this folder for PlatformIO to believe we are providing unit test in our own
    custom entry point..

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
   $> clang-format --style file -i mittelib/src/mlab/my_file.cpp
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
   $> pio run -t upload -t monitor  # or
   $> pio test
   ```
   
### Building the documentation
1. Install Doxygen (or run through Docker), and run
   ```shell
   $> doxygen ./doxygen.conf
   ```
2. The documentation can be seen at `./docs/_build/html/index.html`.