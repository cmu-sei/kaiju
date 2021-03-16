# CERT Kaiju Binary Analysis Framework for GHIDRA

CERT Kaiju is a collection of binary analysis tools for Ghidra.

This is a Ghidra/Java implementation of some features
of the [CERT Pharos Binary Analysis Framework][pharos], 
particularly the function hashing and malware analysis tools,
but is expected to grow new tools and capabilities over time.

As this is a new effort, this implementation does not yet have full
feature parity with the original C++ implementation based on ROSE;
however, the move to Java and Ghidra has actually enabled some new
features not available in the original framework -- notably, improved
handling of non-x86 architectures. Since some significant
re-architecting of the framework and tools is taking place, and the
move to Java and Ghidra enables different capabilities than the C++
implementation, the decision was made to utilize new branding
such that there would be less confusion between implementations
when discussing the different tools and capabilities.

Our intention for the near future is to maintain both the
original Pharos framework as well as Kaiju, side-by-side,
since both can provide unique features and capabilities.

CAVEAT: As a prototype, there are many issues that may come up when
evaluating the function hashes created by this plugin. For example,
unlike the Pharos implementation, Kaiju's function hashing module will
create hashes for very small functions (e.g., ones with a single
instruction like RET causing many more unintended collisions). As
such, analytical results may vary between this plugin and Pharos
fn2hash.

## Dependencies

CERT Kaiju suggests the following dependencies:
- [Ghidra](https://ghidra-sre.org) 9.1+ (9.2+ recommended)
- [gradle](https://gradle.org/install/) 5.6+ (gradle 6.x recommended)
- Java 11+ (we suggest [OpenJDK](https://openjdk.java.net/install/))

**NOTE**: Please ensure that gradle is building against the same
JDK version in use by Ghidra on your system, or you may experience
installation problems.

This framework has been tested with the following build:
- 9.2.2 (public release), gradle 6.8.3

### Runtime Dependencies

The only external runtime dependency is Google's
[GSON](https://github.com/google/gson) library.  In most cases, Gradle
will automatically obtain this for you.  If you find that you need to
obtain it manually, you can download
[gson-2.8.6.jar](https://repo1.maven.org/maven2/com/google/code/gson/gson/2.8.6/gson-2.8.6.jar)
and place it in the
`kaiju/lib` directory.

## Gradle Build Instructions

Once dependencies are installed, Kaiju may be built as a Ghidra
extension by using the `gradle` build tool. It is recommended to
first set a Ghidra environment variable, as Ghidra installation
instructions specify.

In short: set `GHIDRA_INSTALL_DIR` as an environment
variable first, then run `gradle` without any options:
```bash
export GHIDRA_INSTALL_DIR=<Absolute path to Ghidra install dir>
gradle
```

NOTE: Your Ghidra install directory is the directory containing
the `ghidraRun` script (the top level directory after unzipping
the Ghidra release distribution into the location of your choice.)

If for some reason your environment variable is not or can not be set,
you can also specify it on the command like with:
```bash
gradle -PGHIDRA_INSTALL_DIR=<Absolute path to Ghidra install dir>
```

In either case, the newly-built Kaiju extension will appear as a
.zip file within the `dist/` directory. The filename will include
"Kaiju", the version of Ghidra it was built against, and the date
it was built. If all goes well, you should see a message like the
following that tells you the name of your built plugin.
```
Created ghidra_9.2.2_PUBLIC_20210309_kaiju.zip in /home/user/Documents/kaiju/dist
```

### Optional: Running Tests With AUTOCATS

While not required, you may want to use the Kaiju testing suite to
verify proper compilation and ensure there are no regressions
while testing new code or before you install Kaiju in a production
environment.

In order to run the Kaiju testing suite, you will need to first obtain
the AUTOCATS (AUTOmated Code Analysis Testing Suite). AUTOCATS contains
a number of executables and related data to perform tests and check
for regressions in Kaiju. These test cases are shared with the Pharos
binary analysis framework, therefore AUTOCATS is located in a separate
git repository.

Clone the AUTOCATS repository with:
```
git clone https://github.com/cmu-sei/autocats
```

We recommend cloning the AUTOCATS repository into the same parent
directory that holds Kaiju, but you may clone it anywhere you wish.

The tests can then be run with:

```
gradle -PKAIJU_AUTOCATS_DIR=path/to/autocats/dir test
```
where of course the correct path is provided to your cloned
AUTOCATS repository directory. If cloned to the same parent
directory as Kaiju as recommended, the command would look like:
```
gradle -PKAIJU_AUTOCATS_DIR=../autocats test
```

The tests cannot be run without
providing this path; if you do forget it, gradle will abort
and give an error message about providing this path.

Kaiju has a dependency on [JUnit 5](https://junit.org/junit5/)
only for running tests. Gradle should automatically retrieve
and use JUnit, but you may also download JUnit and manually place
into `lib/` directory of Kaiju if needed.

You will want to run the update command whenever you pull the
latest Kaiju source code, to ensure they stay in sync.

## Installation

The extension .zip file may be installed either interactively through
the graphical interface of Ghidra, or manually. The manual option
may be useful for "headless" installations (e.g., on servers only
available via a command line).

### Graphical Installation

Start Ghidra, and from the opening window, select from the menu:
`File > Install Extension`. Click the plus sign at the top of the
extensions window, navigate and select the .zip file in the file
browser and hit OK. The extension will be installed and a checkbox
will be marked next to the name of the extension in the window
to let you know it is installed and ready.

The interface will ask you to restart Ghidra to start using
the extension. Simply restart, and then Kaiju's extra features will
be available for use interactively or in scripts.

Some functionality may require enabling Kaiju plugins. To do this,
open the Code Browser then navigate to the menu `File > Configure`.
In the window that pops up, click the `Configure` link below
the "Experimental" category icon. A pop-up will display all available
experimental plugins, including Kaiju's plugins. Check any plugins
you wish to activate, then hit OK. You will now have access to
interactive plugin features. If a plugin is not visible, you
can find the plugin underneath the `Window` menu in the Code Browser.

### First-Time "Headless" Gradle-based Installation

You may also install the extension directly on the command line via
use of gradle. Be sure to set `GHIDRA_INSTALL_DIR` as an environment
variable first (if you built Kaiju too, then you should already have
this defined), then run `gradle` as follows:
```bash
export GHIDRA_INSTALL_DIR=<Absolute path to Ghidra install dir>
gradle install
```
or if you are unsure if the environment variable is set,
```bash
gradle -PGHIDRA_INSTALL_DIR=<Absolute path to Ghidra install dir> install
```

Extension files should be copied automatically. Kaiju will be available
for use after Ghidra is restarted.

**NOTE**: Be sure that Ghidra is NOT running before using gradle to
install. We are aware of instances when the caching does not appear
to update properly if installed while Ghidra is running, leading to
some odd bugs. If this happens to you, simply exit Ghidra and try
reinstalling again.

### Consider Removing Your Old Installation First

It might be helpful to first completely remove any older install of
Kaiju before updating to a newer release. We've seen some cases
where older versions of Kaiju files get stuck in the cache and
cause interesting bugs due to the conflicts. By removing the old
install first, you'll ensure a clean re-install and easy use.

The gradle build process now can auto-remove previous installs of Kaiju
if you enable this feature. To enable the autoremove,
add the "KAIJU_AUTO_REMOVE" property to your install command, such as
(assuming the environment variable is probably set as in previous section):
```bash
gradle -PKAIJU_AUTO_REMOVE install
```

If you'd prefer to remove your old installation manually, perform a command like:
```bash
rm -rf $GHIDRA_INSTALL_DIR/Extensions/Ghidra/*kaiju*.zip $GHIDRA_INSTALL_DIR/Ghidra/Extensions/kaiju
```


## Usage

Kaiju's tools may be used either in an interactive graphical way,
or via a "headless" mode more suited for batch jobs.

### Interactive Graphical Interface

Kaiju creates an interactive graphical interface (GUI) within Ghidra
utilizing Java Swing and Ghidra's plugin architecture.

Most of Kaiju's tools are actually Analysis plugins that run automatically
when the "Auto Analysis" option is chosen, either upon import of
a new executable to disassemble, or by directly choosing
`Analysis > Auto Analyze...` from the code browser window. You will
see several CERT Analysis plugins selected by default in the Auto Analyze
tool, but you can enable/disable any as desired.

The Analysis tools must be run before the various GUI tools will work,
however. In some corner cases, it may even be helpful to run the
Auto Analysis twice to ensure all of the metadata is produced
to create correct partitioning and disassembly information, which
in turn can influence the hashing results.

Analyzers include:
- **DisasmImprovements** = improves the function partitioning of the
  disassembly compared to the standard Ghidra partitioning.
- **Fn2Hash** = calculates function hashes for all functions in a program.

The GUI tools include:
- **Function Hash Viewer** = a plugin that displays an interactive list
of functions in a program, and their hashes. Analysts can use this
to export one or more functions from a program into YARA signatures.
- **Function Set Intersection** = a plugin that displays a simple table
comparing the programs imported to a Ghidra project. Programs with
matching PIC hashes for functions are identified. Analysts can use
this information to focus on functions held in common by multiple
programs that may be interesting or useful in identifying families
of software.
- **OOAnalyzer JSON Importer** = a plugin that can
load, parse, and apply Pharos-generated OOAnalyzer results to object
oriented C++ executables in a Ghidra project. When launched, the
plugin will prompt the user for the JSON output file produced by
OOAnalyzer that contains information about recovered C++
classes. After loading the JSON file, recovered C++ data types and
symbols found by OOAnalyzer are updated in the Ghidra Code
Browser. The plugin's design and implementation details are described
in our SEI blog post titled [Using OOAnalyzer to Reverse Engineer
Object Oriented Code with Ghidra][ooanalyzer-blog].

### Command-line "Headless" Mode

Ghidra also supports a "headless" mode allowing tools to be run
in some circumstances without use of the interactive GUI.
These commands can therefore be utilized for scripting and
"batch mode" jobs of large numbers of files.

Please see the `README.md` file in the `ghidra_scripts/`
directory for more information on using this mode.


## License
This software is licensed under a BSD-style license
by the Software Engineering Institute at Carnegie Mellon University.

Please find full details of this license in the `LICENSE.md` file
in the root of this repository.

[pharos]: https://github.com/cmu-sei/pharos
[ooanalyzer-blog]: https://insights.sei.cmu.edu/sei_blog/2019/07/using-ooanalyzer-to-reverse-engineer-object-oriented-code-with-ghidra.html

