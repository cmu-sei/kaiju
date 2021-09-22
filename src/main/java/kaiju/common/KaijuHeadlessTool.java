/***
 * CERT Kaiju
 * Copyright 2021 Carnegie Mellon University.
 *
 * NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
 * INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON UNIVERSITY
 * MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED, AS TO ANY MATTER
 * INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR PURPOSE OR
 * MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF THE MATERIAL.
 * CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF ANY KIND WITH RESPECT
 * TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT INFRINGEMENT.
 *
 * Released under a BSD (SEI)-style license, please see LICENSE.md or contact permission@sei.cmu.edu for full terms.
 *
 * [DISTRIBUTION STATEMENT A] This material has been approved for public release and unlimited distribution.
 * Please see Copyright notice for non-US Government use and distribution.
 *
 * Carnegie Mellon (R) and CERT (R) are registered in the U.S. Patent and Trademark Office by Carnegie Mellon University.
 *
 * This Software includes and/or makes use of the following Third-Party Software subject to its own license:
 * 1. OpenJDK (http://openjdk.java.net/legal/gplv2+ce.html) Copyright 2021 Oracle.
 * 2. Ghidra (https://github.com/NationalSecurityAgency/ghidra/blob/master/LICENSE) Copyright 2021 National Security Administration.
 * 3. GSON (https://github.com/google/gson/blob/master/LICENSE) Copyright 2020 Google.
 * 4. JUnit (https://github.com/junit-team/junit5/blob/main/LICENSE.md) Copyright 2020 JUnit Team.
 * 5. Gradle (https://github.com/gradle/gradle/blob/master/LICENSE) Copyright 2021 Gradle Inc.
 * 6. markdown-gradle-plugin (https://github.com/kordamp/markdown-gradle-plugin/blob/master/LICENSE.txt) Copyright 2020 Andres Almiray.
 * 7. Z3 (https://github.com/Z3Prover/z3/blob/master/LICENSE.txt) Copyright 2021 Microsoft Corporation.
 * 8. jopt-simple (https://github.com/jopt-simple/jopt-simple/blob/master/LICENSE.txt) Copyright 2021 Paul R. Holser, Jr.
 *
 * DM21-0792
 */
package kaiju.common;

// add for command line processing tools
import joptsimple.BuiltinHelpFormatter;
import joptsimple.HelpFormatter;
import joptsimple.OptionDescriptor;
import joptsimple.OptionException;
import joptsimple.OptionParser;
import joptsimple.OptionSet;
import joptsimple.OptionSpec;

/**
 * Provides an easy interface for creating tools that support headless mode.
 * Tools should implement this interface in order to get a default implementation
 * of command line parsing and handling.
 */
public interface KaijuHeadlessTool {

    /**
     * Implementers should define this function to create
     * an OptionParser with all of the needed options for
     * the tool that implements it.
     */
    OptionParser getOptionParser();
    
    default OptionSet parse(String[] arg_list) {
        OptionParser parser = getOptionParser();
        OptionSet options = null;
        try {
            options = parser.parse(arg_list);
        } catch (OptionException omrae) {
            // NOTE: since no options are returned, no further processing
            // of arguments is possible;
        }
        return options;
    }

}
/*    
    OptionParser parser = new OptionParser();
    parser.accepts("help", "Prints help information").forHelp();
    // OptionParser parser = new OptionParser( "W;" );
    // parser.recognizeAlternativeLongOptions( true ); // same effect as above

    // simple
    parser.accepts("trace", "Added output for analyzing runtime");
    parser.accepts("debug", "Added output for figuring out bugs");
    parser.accepts("dump", "Dump EXACT hash and PIC hash bytes in output/CSV file");

    // Complex
    OptionSpec<File> addrfile = parser.accepts("addrfile", "Read function addresses in from file")
      .withRequiredArg()
      // .required()
      .ofType(File.class)
      .describedAs("Address file");

    // make output file a REQUIRED option as no one can clean-up the mucked-up console output now
    OptionSpec<File> outputfile = parser.accepts("outputfile", "Save function hashes in CSV file")
    .withRequiredArg()
    .required()
    .ofType(File.class)
    .describedAs("Output file");

    // These may not need variable assignments
    OptionSpec<Void> list = parser.accepts("list", "List System properties of JVM/instance");
    OptionSpec<Void> verbose = parser.accepts("verbose", "Add extra text in output");

    // TODO: add multiple file processing here;
    //       may need to make pseudo analyzeheadless -import/-process commands
    OptionSpec<File> leftOvers = parser.nonOptions("More Files to process/import").ofType(File.class);

    OptionSet options = null;
    try {
      options = parser.parse(arg_list);
    } catch (OptionException omrae) {
        // NOTE: since no options are returned, no further processing
        // of arguments is possible;
        // catch exception and Use Msg class to avoid stack trace [jsh]
        Msg.out(omrae.toString());
        return;
        // System.exit(-1); BAD!!! leaves open Ghidra project in filesystem/repo(?)
        // OptionMissingRequiredArgumentException
    }

    // Go through the valid argument options
    // TODO: A case switch may be better here [jsh]
    if (options.has("addrfile")) {
      if (options.hasArgument("addrfile")) {
        doFileRead(addrfile.value(options).toString().replace("\'", ""));
        // TODO: stuff read-in addrs into an AddressSet
        //System.out.println(options.valueOf( addrfile ).toString());
      }
    }

    if (options.has("debug")) {
      flag_debug = true;
      
      //Msg.debug(this, "From Msg.DEBUG to -log [APPEND WITH TIMESTAMP]: Debugging ON");
      //Msg.info(this, "From Msg.INFO to -log [APPEND WITH TIMESTAMP] AND System.out/console: Debugging ON");
      //Msg.warn(this, "From Msg.WARN: to -log [APPEND WITH TIMESTAMP] AND System.out/console: Debugging ON");
      //Msg.error(this, "From Msg.ERROR to -log [APPEND WITH TIMESTAMP] AND System.out/console: Debugging ON");
      //Msg.out("From Msg.OUT to System.ERROR [NO TIMESTAMP,NOLOG]: Debugging ON");
      //System.out.println("[NO TIMESTAMP,NOLOG] Debug message from System.out.println()");
      //System.err.println("[NO TIMESTAMP,NOLOG] Debug message from System.err.println()");
      
    }

    if (options.has("dump")) {
      flag_dump = true;
    }

    if (options.has("help")) {
      BuiltinHelpFormatter bhf = new BuiltinHelpFormatter(120, 10);
      parser.formatHelpWith(bhf);
      // TODO: Could insert Usage here
      parser.printHelpOn(System.out);
    }

    if (options.has( "list" )) {
      System.getProperties().list(System.out);
    }

    // NOTE: options is currently REQUIRED, but could change if old style needed
    // [jsh]
    Msg.out(outputfile.options().toString());
    if (options.has(outputfile)) {
      if (options.hasArgument(outputfile)) {
        // TODO: fix this hack!!! NOTE hines though this would allow APPENDING [jsh]
        outfilename = new File(outputfile.value(options).toString().replace("\'", ""));
      } else {
        // TODO: print error!
        return;
      }
    } else {
      // Old design allowed first non-option argument to be the CSV file;
      // [jsh] thinks this is a bad design choice but kept the logic
      // here in case --outputfile option ever becomes not REQUIRED
      
      if (!options.nonOptionArguments().isEmpty()) {
        var fn = leftOvers.values(options).get(0).toString().replace("\'", "");
        outfilename = new File( fn );
        //findFirst().toString().replace("\'", ""));
        Msg.warn(this, "Using nonOptionArgument as CSV output file: "+fn.toString());
      }
    }

    if (options.has("trace")) {
      flag_debug = true;
      flag_trace = true;
      
      //Msg.trace(this, "From Msg.TRACE [WHERE??? -- Removed in \"production\"]: TRACE ON");
      //Msg.debug(this, "From Msg.DEBUG to -log [APPEND WITH TIMESTAMP]: Debugging ON");
      
    }

    if (options.has("verbose")) {
      flag_verbose = true;
      if (flag_debug) {
        Msg.info(this, "Verbose mode ON!");
      } else {
        // TODO: Do _useful_ verbose things!

        // print java command for now
        System.err.println("Java Command:");
        System.err.println(System.getProperty("sun.java.command"));
      }
    }
  */ 
