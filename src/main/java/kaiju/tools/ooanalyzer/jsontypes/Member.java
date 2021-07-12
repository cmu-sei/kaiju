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
package kaiju.tools.ooanalyzer.jsontypes;

import java.util.Optional;

import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

/**
 * JSON class to represent a member
 */
public class Member {

  public static final Integer INVALID_OFFSET = -1;

  @Expose
  @SerializedName("name")
  private String name;

  @Expose
  @SerializedName("type")
  private String type;

  @Expose
  @SerializedName("struc")
  private String struc;

  @Expose
  @SerializedName("parent")
  private String parent;

  @Expose
  @SerializedName("base")
  private Boolean base;

  @Expose
  @SerializedName("offset")
  private String offset;

  @Expose
  @SerializedName("size")
  private String size;

  public Optional<String> getStruc() {
    if (struc == null) return Optional.empty();
    return Optional.of(struc);
  }

  public boolean isParent() {
    if (parent == null) {
      return false;
    }
    return parent.equalsIgnoreCase("yes");
  }

  public String getName() {
    return name;
  }

  public String getType() {
    return type;
  }

  public Boolean getBase() {
    return base;
  }

  public Integer getOffset() {
    return Integer.decode (offset);
  }

  public Integer getSize() {
    return Integer.decode (size);
  }

  @Override
  public String toString() {
    return "[name=" + name + ", type=" + type + ", struc=" + struc
      + ", parent=" + parent + ", offset=" + offset + ", size="
      + size + "]";
  }
}
