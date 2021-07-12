Developer's Guide for CERT Kaiju
================================

Audience
--------

This document is for anyone that wishes to either contribute to CERT Kaiju,
or use some feature of CERT Kaiju as a basis for another tool.

General Tips
------------

The `kaiju.common` subpackage consists of common utilities and functionality
likely to be used in any Kaiju plugins and tools.
When developing new tools, it is suggested to include the line:
```
import kaiju.common.*;
```
in any new Class file. The most important features added include:
- **KaijuLogger**. This enables unified logging interface that sends messages
  to the console, file log, and/or graphical interface messages as makes
  sense for the particular tool and how a user calls it. To automatically
  use the KaijuLogger, simply include it with the `implements` keywords
  for any new classes you create, such as:
  ```
  public class SomeNewTool implements KaijuLogger {...}
  ```
  The logging interface is defined as `default` functions;
  you can override them if you wish, or simply call them directly
  by including `debug()`, `info()`, `warn()`, `error()`, in your code.
  The default implementation automatically handles getting an
  object handle to the Logger and emitting appropriate messages.
