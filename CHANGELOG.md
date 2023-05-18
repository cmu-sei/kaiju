# Next Release Goals

- New Features:
  * 
- Bugfixes:
  * 


# Current Release

## 230518

- New Features:
  * Updated to require Ghidra 10.3+ due to API changes


# Past Releases

## 230406

- Bugfixes:
  * Includes a small patch to print better debugging information, to help address #38

## 230330

- New Features:
  * Updated gradle to allow auto building Z3 from downloaded source zip
  * Gradle build to support Java 17 for Ghidra 10.2+
  * Simplified build and install instructions, in new INSTALL.md file
  * Status check tool to test for Z3, autoload library if possible
- Bugfixes:
  * Fix an FnHash error that would hang the UI (#25)
  * Fix errors loading Z3 libraries (#6, #20, #30)
  * Catch GhiHorn error from Ghidra HighVariable (#23)
  * Catch an error with java time (#34)
