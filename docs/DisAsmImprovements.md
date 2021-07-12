# CERT Disassembly Improvements

CERT Disassembly Improvements is a Ghidra analyzer that improves the accuracy
of the disassembly output produced within Ghidra.
    
This analyzer should be run prior to any other CERT Kaiju tools. Most tools rely on
an accurate diassembly of the binary to have a complete and useful analysis,
so the improvements created by this analyzer improve the results of other tools.

This analyzer currently only works for X86 code.

    
## Details of the Improvements
    
This analyzer works by first looking for all parts of the disassembly that are
left "undefined" by Ghidra. This means, all of the memory blocks that Ghidra
was unable to identify as a known instruction or data type.

The analyzer uses a number of heuristics for X86 programs
to identify some of these "undefined" code blocks as data like:

- embedded strings
- alignment padding.

The heuristics were developed based on knowledge and experience
from reverse engineers at CERT.

