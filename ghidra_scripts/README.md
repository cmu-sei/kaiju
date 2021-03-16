# Sample Ghidra fn2hash scripts using kaiju

## Using the Headless Analyzer

For the official documentation please see the [Ghidra Headless Analyzer README](https://ghidra.re/ghidra_docs/analyzeHeadlessREADME.html).  
A brief overview, for the purposes of using the CERT Function Hashing plugin in a headless mode, is provided here.

---
The general syntax for the Headless analyzer is:

`analyzeHeadless PROJECT_DIRECTORY PROJECT_NAME [options...]`

When using the CERT Function Hashing plugin there are two steps that need to be accomplished in addition to the usual import and analyze steps:

- enabling the CERT Function Hashing plugin before analysis (using the `-preScript` option)
- extracting the function hashing artifacts after analysis (using the `-postScript` option)

We have provided two sample scripts to perform these actions:

- _setupScript.java_  
Ensures that the CERT Function Hashing plugin is enabled for headless analysis.

- _exportCSVHeadless.java_  
Extracts the function hashing artifacts and outputs them to the specified file in CSV format.

---

### Examples 

Analyzing a single binary:  
`$GHIDRA_INSTALL_DIR/support/analyzeHeadless $HOME/ghidra_projects tmpProj -import exampleFile.exe -preScript setupScript.java -postScript exportCSVHeadless.java exampleFileResults.csv`

Analyzing a directory of binaries:  
`$GHIDRA_INSTALL_DIR/support/analyzeHeadless $HOME/ghidra_projects tmpProj -import path/to/binaries -preScript setupScript.java -postScript exportCSVHeadless.java exampleFileResults.csv`


Using `-okToDelete` and `-deleteProject` options on analyzeHeadless to remove tmpProj after import:  
`$GHIDRA_INSTALL_DIR/support/analyzeHeadless $HOME/ghidra_projects tmpProj -okToDelete -deleteProject -import exampleFile.exe -preScript setupScript.java -postScript exportCSVHeadless.java exampleFileResults.csv`

*** NOTE *** This will DELETE any Ghidra project named `tmpProj` in your user directory defined by `$HOME/ghidra_projects` (or throw an error if `$HOME` is undefined)!

