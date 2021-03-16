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

package kaiju.ooanalyzer.jsontypes;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;

/**
 * A virtual function table entry
 */

public class Vfentry {

  @Expose
  @SerializedName("ea")
  private String ea;

  @Expose
  @SerializedName("offset")
  private String offset;

  @Expose
  @SerializedName("name")
  private String name;

  @Expose
  @SerializedName("demangled_name")
  private String demangeledName;

  @Expose
  @SerializedName("import")
  private String imported;

  @Expose
  @SerializedName("type")
  private String type;

  public String getEa() {
    return ea;
  }

  public String getDemangeledNname() {
    return demangeledName;
  }

  public String getImported() {
    return this.imported;
  }

  public Integer getOffset() {
    return Integer.parseInt(offset);
  }

  public String getName() {
    return name;
  }

  public String getType() {
    return type;
  }

  public void setEa(String ea) {
    this.ea = ea;
  }

  public void setOffset(String offset) {
    this.offset = offset;
  }

  public void setName(String name) {
    this.name = name;
  }

  public void setDemangeledName(String demangeled_name) {
    this.demangeledName = demangeled_name;
  }

  public void setImported(String imported) {
    this.imported = imported;
  }

  public void setType(String type) {
    this.type = type;
  }

  @Override
  public String toString() {
    return "[ea=" + ea + ", offset=" + offset + ", name=" + name
      + ", demangled name= " + demangeledName + ", imported= "
      + imported + ", type=" + type + "]";
  }
}
