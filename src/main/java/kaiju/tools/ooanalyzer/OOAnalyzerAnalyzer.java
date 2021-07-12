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
 *
 * DM21-0087
 */

package kaiju.tools.ooanalyzer;

// This is an analyzer for Ghidra to semi-automatically run OOAnalyzer. For the sake
// of simplicity, this is commented out for now.

/*
import java.util.List;
import java.util.Optional;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ooanalyzerplugin.jsontypes.OOAnalyzerType;

public class OOAnalyzerAnalyzer extends AbstractAnalyzer {

  private final static String NAME = "CERT OOAnalyzer C++ class analysis";
  private final static String DESCRIPTION = "Apply OOAnalyzer JSON.";
  protected static final String OPTION_NAME_OOA_FILE = "Run CERT OOAnalyzer";
  private static final String OPTION_DESCRIPTION_OOA_FILE = "If checked, analyst will be prompted to load OOAnalyzer JSON file;";
  private File ooaJsonFile;

  public OOAnalyzerAnalyzer() {
    super(NAME, DESCRIPTION, AnalyzerType.DATA_ANALYZER);

    // Data type propogation is the latest analysis phase. OOAnalyzer will run after
    // that because it needs to update functions and data types
    setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after());

    // OO analysis is enabled by default, but it must be configured with a JSON file
    // to actually run.
    setDefaultEnablement(true);

    setSupportsOneTimeAnalysis();
  }

  @Override
  public boolean canAnalyze(Program program) {

    // Only analyze 32-bit or less X86 programs. OOAnalyzer can handle nothing else
    Processor processor = program.getLanguage().getProcessor();
    if (program.getLanguage().getDefaultSpace().getSize() > 32) {
      return false;
    }

    return processor.equals(Processor.findOrPossiblyCreateProcessor("x86"));
  }

  @Override
  public void optionsChanged(Options options, Program program) {
    ooaJsonFile = options.getFile(OPTION_NAME_OOA_FILE, null);
  }

  @Override
  public void registerOptions(Options options, Program program) {
    options.registerOption(OPTION_NAME_OOA_FILE, OptionType.FILE_TYPE, null, null, OPTION_DESCRIPTION_OOA_FILE);
  }

  @Override
  public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
    throws CancelledException {

    // if the OOAnalyzer namespace already exists, then don't reanalyze
    Namespace ooaNs = program.getSymbolTable().getNamespace(OOAnalyzer.ooanalyzerCategory.toString(), null);
    if (ooaNs==null) {
      setDefaultEnablement(false);
      return false;
    }

    if (null == ooaJsonFile) {
      ooaJsonFile = OOAnalyzerPlugin.getJson();
    }

    Optional<List<OOAnalyzerType>> optJson = OOAnalyzer.parseJsonFile(ooaJsonFile);

    if (optJson.isPresent()) {
      // Actually run the plugin

      int tid = program.startTransaction("OOA");
      boolean result = false;
      try {
        OOAnalyzer ooa = new OOAnalyzer(program);
        ooa.setMonitor(monitor);
        int count = ooa.analyzeClasses(optJson.get());

        if (count > 0) {
          Msg.info(this,
                   "OOAnalyzer loaded " + count + " classes from JSON file \"" + ooaJsonFile.getName() + "\"");
          result = true;
        } else {
          Msg.info(this,
                   "OOAnalyzer could not load classes from JSON file \"" + ooaJsonFile.getName() + "\"");
        }
      } finally {
        program.endTransaction(tid, result);
      }
    } else {
      Msg.error(this, "Could not load/parse JSON file ");
    }
    return true;
  }
}
*/
