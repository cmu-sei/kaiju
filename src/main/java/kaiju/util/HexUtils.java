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
package kaiju.util;

/**
 * A collection of custom functions converting various numeric data types
 * into hex format strings. Unclear if these custom implementations are
 * really needed, or if Java provides an equivalent somewhere.
 */
public class HexUtils {
 
    // hmm...ints & longs are always signed in java, wonder if the hex will come
    // out as I might expect?  In Java 8 and above apparently there are methods
    // on the Integer class to deal w/ int in an unsigned manner explicitly, at
    // least in an arithmetic sense, but not sure about hex conversions, will
    // have to test...  I know that Integer.toHexString(val) works too but not
    // sure if any control over the format of that or not
    public static String intToHexString(int val) {
        String retval = "";
        retval += String.format("%08x ",val);
        return retval;
    }

    // same notes as above, except Long class has unsigned arithmetic methods.
    // And to convert back use Long.parseLong(hexstring,16)
    public static String longToHexString(long val) {
        String retval = "";
        retval += String.format("%016x ",val);
        return retval;
    }

    // not a super efficient way to convert bytes to string hex output but it
    // works...mildly concerned about the signedness here too since only the
    // char type is effectively unsigned (and it's 2 bytes), but I've been
    // seeing FF come out where expected so I think it's working okay in this
    // context at least.
    public static String byteArrayToHexString(byte [] bytes,String padding) {
        if (bytes == null ) return "";
        String retval = "";
        for (byte b: bytes) {
            retval += String.format("%02x%s",b,padding);
        }
        return retval;
    }
    // applies a mask for YARA generation, if mask is FF then put ?? in return String
    public static String byteArrayToHexString(byte [] bytes,String padding,byte [] masks) {
        if (bytes == null ) return "";
        String retval = "";
        for (int i = 0; i < bytes.length; ++i) {
            // NOTE: is the mask encoding relocatable addresses as a 1 or a 0?
            if (masks[i] == (byte) (0)) {
                retval += "?? ";
            } else {
                retval += String.format("%02x%s",bytes[i],padding);
            }
        }
        return retval;
    }
}
