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

import java.util.Collection;
import java.util.Optional;

import com.google.gson.JsonArray;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

import ghidra.app.util.demangler.DemangledObject;
import ghidra.app.util.demangler.Demangler;
import ghidra.app.util.demangler.microsoft.MicrosoftDemangler;

/**
 * A JSON representation of a C++ class from OOAnalyzer
 */
public class OOAnalyzerClassType {

  @Expose
  @SerializedName("name")
  private String name;

  @Expose
  @SerializedName("demangled_name")
  private String demangledName;

  @Expose
  @SerializedName("import")
  private Boolean is_import;

  // The namespace is not part of the JSON
  private String namespace;

  @Expose
  @SerializedName("size")
  private Integer size;

  @Expose
  @SerializedName("members")
  private Collection<Member> members;

  @Expose
  @SerializedName("methods")
  private Collection<Method> methods;

  @Expose
  @SerializedName("vftables")
  private Collection<Vftable> vftables;

  public OOAnalyzerClassType(String name, String demangledName, String namespace, Integer size, Collection<Member> members,
                             Collection<Method> methods, Collection<Vftable> vftables) {

    this.name = name;
    this.demangledName = demangledName;
    this.namespace = namespace;
    this.size = size;
    this.members = members;
    this.methods = methods;
    this.vftables = vftables;
  }

  /**
   * Return mangled name for this type
   *
   * @return the name recovered from JSON
   */
  public String getName() {
    return this.name;
  }

  /**
   * Return the (possibly unspecified) demangled name
   *
   * @return
   */
  public Optional<String> getDemangledName() {
    return (this.demangledName != null && this.demangledName.length() > 0) ? Optional.of(this.demangledName)
      : Optional.empty();
  }

  public String getBestName () {
    if (this.demangledName != null && this.demangledName.length() > 0) {
      return this.demangledName;
    }
    return this.name;
  }

  /**
   *
   * @return
   */
  public String getNameWithoutNamespace() {

    if (this.demangledName != null && this.demangledName.length() > 0) {
      if (this.namespace != null && this.namespace.length() > 0) {
        return this.demangledName.substring(this.namespace.length() + "::".length ());
      }
      return this.demangledName;
    }
    return this.name;
  }

  public Optional<String> getNamespace() {
    if (namespace != null && namespace.length() > 0) {
      return Optional.of(namespace);
    }
    return Optional.empty();
  }

  public void setNamespace(String namespace) {
    this.namespace = namespace;
  }

  public void setName(String name) {
    this.name = name;
  }

  public Integer getSize() {
    return this.size;
  }

  public Collection<Member> getMembers() {
    return members;
  }

  public Collection<Method> getMethods() {
    return methods;
  }

  public Collection<Vftable> getVftables() {
    return vftables;
  }

  @Override
  public String toString() {

    String str = "[name=" + name + ", demangled name= " + demangledName + ", size=" + size + ", ";
    if (members == null) {
      str += "members=[None], ";
    } else {

      str += "members=[";
      for (Member mbr : members) {
        if (mbr != null) {
          str += mbr.toString() + " ";
        }
      }
      str += "], ";
    }

    if (methods == null) {
      str += "methods=[None]";
    } else {
      str += "methods=[";
      for (Method mtd : methods) {
        if (mtd != null) {
          str += mtd.toString() + " ";
        }
      }
      str += "], ";
    }
    if (vftables == null) {
      str += "vftables=[None]";
    } else {
      str += "vftables=[";

      for (Vftable vft : vftables) {
        if (vft != null) {
          str += vft.toString() + " ";
        }
      }
      str += "]";
    }
    return str;
  }
}
