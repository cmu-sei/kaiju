# Using CERT Kaiju in "Headless" Mode

## Overview

The following Kaiju tools are available in "headless" mode:

- **fn2hash** = automatically run Fn2Hash on a given program
and export all the hashes to a CSV file specified
- **fn2yara** = automatically run Fn2Hash on a given program
and export all hash data as YARA signatures to the file specified
- **fnxrefs** = analyze a Program and export a list of Functions
based on entry point address that have cross-references in
data or other parts of the Program

These tools are designed to work completely from the command line;
the user does not need to run the GUI version of Ghidra to utilize
this mode. This may be helpful in several scenarios, such as
an automated "batch" mode where a script runs Ghidra/Kaiju tools
automatically on a batch of samples, or to allow remote analysis
on a virtual machine/resources with only a remote terminal.

*NOTE*: These tools may not completely correspond with features available
in graphical interface tools, simply due to the nature of
how a typical user utilizes GUI versus command line tools.

## Using the Headless Analyzer

Kaiju makes use of Ghidra's built-in "Headless Analyzer" mode, as well
as some GhidraScripts, to expose functionality and tools to the command line.
Users are recommended to familiar with the official Ghidra documentation,
for details please see the [Ghidra Headless Analyzer README](https://ghidra.re/ghidra_docs/analyzeHeadlessREADME.html).

A brief overview, for the purposes of using CERT Kaiju in headless mode, is provided here.

---

The general syntax for the Headless analyzer is:

`analyzeHeadless PROJECT_DIRECTORY PROJECT_NAME [options...]`

Three main steps happen when you run this command:

1. if specified with `-preScript`, a GhidraScript is run (pre-analysis) that can be used to initialize or setup tools including Kaiju
2. one or more Ghidra analyzers, including those installed by Kaiju, are run against the provided executable in the given project environment
3. if specified with `-postScript`, a GhidraScript is then run (post-analysis) to process analyzer results (including export data to file)

We have provided several sample scripts to perform these actions:

- _setupScript.java_  
Ensures that the CERT Function Hashing plugin is enabled for headless analysis. (preScript)

- _exportCSVHeadless.java_  
Extracts the function hashing artifacts and outputs them to the specified file in CSV format. (postScript)

- _exportXrefsToCSVHeadless.java_
Counts the number of external References to Function entry points and outputs them to the specified file in CSV format. (postScript)

---

### Examples

Analyzing a single binary with Fn2Hash and export the hashes to CSV:  
`$GHIDRA_INSTALL_DIR/support/analyzeHeadless $HOME/ghidra_projects tmpProj -import exampleFile.exe -preScript setupScript.java -postScript exportCSVHeadless.java exampleFileResults.csv`

Analyzing a directory of binaries with Fn2Hash:  
`$GHIDRA_INSTALL_DIR/support/analyzeHeadless $HOME/ghidra_projects tmpProj -import path/to/binaries -preScript setupScript.java -postScript exportCSVHeadless.java exampleFileResults.csv`


Using `-okToDelete` and `-deleteProject` options on analyzeHeadless to remove tmpProj after import:  
`$GHIDRA_INSTALL_DIR/support/analyzeHeadless $HOME/ghidra_projects tmpProj -okToDelete -deleteProject -import exampleFile.exe -preScript setupScript.java -postScript exportCSVHeadless.java exampleFileResults.csv`

*** NOTE *** This will DELETE any Ghidra project named `tmpProj` in your user directory defined by `$HOME/ghidra_projects` (or throw an error if `$HOME` is undefined)!

