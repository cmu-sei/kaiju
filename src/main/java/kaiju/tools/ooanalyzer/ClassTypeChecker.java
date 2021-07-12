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

import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;

/***
 * Utility class to identify the class names that Ghidra assigns by default.
 * Currently this is a separate class with a single method. It is designed this
 * way in case the definition of valid evolves over time.
 */

public class ClassTypeChecker {

  // These are the names that Ghidra attempts to give
  private final CategoryPath defaultStructCategory = new CategoryPath("/auto_structs");
  private final String defaultClassName = "AutoClass";

  /**
   * Evaluate whether a selected type name is OK
   *
   * @param dt the data type yo evaluate
   * @return true if valid, false otherwise
   */
  public boolean isValid(final DataType dt) {
    // The built-in types seem to tbe the primative types. We will avoid
    // these

    if (dt.getSourceArchive().getArchiveType().isBuiltIn()) {
      return false;
    }
    // Check for the dummy structure name / category
    else if (dt.getCategoryPath().equals(defaultStructCategory)) {
      return false;
    }
    // Check for the dummy base class name
    else if (dt.getName().indexOf(defaultClassName) != -1) {
      return false;
    }
    // The name is OK
    return true;
  }
}
