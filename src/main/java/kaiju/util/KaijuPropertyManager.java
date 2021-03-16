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

import db.NoTransactionException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.IntPropertyMap;
import ghidra.program.model.util.PropertyMapManager;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.util.Saveable;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.NoValueException;

public class KaijuPropertyManager {

    /**
     * Returns an ObjectPropertyMap for use with a Kaiju tool.
     * Use for more consistent and brief way of accessing the property database
     * Ghidra uses to store data about a particular program.
     * @param program the program being analyzed by the tool
     * @param toolName the Kaiju tool being used, used to create a unique name in property database
     * @param saveableClass the class of the object stored in the property database, pass SomeClassName.class as parameter
     */
    public static ObjectPropertyMap getOrCreateObjectPropertyMap(Program program, String toolName, java.lang.Class<? extends Saveable> saveableClass) throws NoTransactionException {
    
        PropertyMapManager mapmgr = program.getUsrPropertyManager();
        
        // use a standard naming convention to hopefully make it easy to find
        // if anyone were to look in the database records directly
        String propertyName = "__CERT_Kaiju_" + toolName;
        
        // check if properties exist already, or if need to create
        ObjectPropertyMap kaijuobjmap;
        try {
            kaijuobjmap = mapmgr.createObjectPropertyMap​(propertyName, saveableClass);
        } catch (DuplicateNameException e) {
            kaijuobjmap = mapmgr.getObjectPropertyMap(propertyName);
        } catch (NoTransactionException e) {
            // TODO: should we do something else?
            throw e;
        }
        
        return kaijuobjmap;
    
    }
    
    /**
     * Returns an int stored in Kaiju property maps for the given program.
     * This function is meant to be a simple way to store values in Ghidra's program database
     * for later retrieval. Most likely to store user's custom analyzer options for Kaiju tools,
     * to save options for later use or for cross-tool usage.
     * If the property is not currently set, then the default value provided is set.
     * @param program the program being analyzed by the tool
     * @param toolPropName the name of the property or option to save
     * @param defaultValue if the property was not previously set, then set it to this value
     */
    public static int getOrCreateIntProperty(Program program, String toolPropName, int defaultValue) throws NoTransactionException {
    
        PropertyMapManager mapmgr = program.getUsrPropertyManager();
        
        // use a standard naming convention to hopefully make it easy to find
        // if anyone were to look in the database records directly
        String propertyName = "__CERT_Kaiju_" + toolPropName;
        
        // check if properties exist already, or if need to create
        IntPropertyMap kaijuintmap = mapmgr.getIntPropertyMap(propertyName);
        if (kaijuintmap == null) {
            // didn't exist so create it!
            try {
                kaijuintmap = mapmgr.createIntPropertyMap​(propertyName);
            } catch (DuplicateNameException e) {
                // shouldn't get here but ghidra requires catching
                kaijuintmap = mapmgr.getIntPropertyMap(propertyName);
            } catch (NoTransactionException e) {
                // TODO: should we do something else?
                throw e;
            }
        }
        
        // next get the actual value stored, or a default value if didn't exist
        // value is stored at the minimum address of the program always, for consistency
        int storedValue = defaultValue;
        try {
            storedValue = kaijuintmap.getInt(program.getMinAddress());
        } catch (NoValueException e) {
            // if there was no value stored then store the default provided
            kaijuintmap.add(program.getMinAddress(), defaultValue);
        }
        
        return storedValue;
    
    }
    
    public static void setIntProperty(Program program, String toolPropName, int newValue) throws NoTransactionException {
    
        PropertyMapManager mapmgr = program.getUsrPropertyManager();
        
        // use a standard naming convention to hopefully make it easy to find
        // if anyone were to look in the database records directly
        String propertyName = "__CERT_Kaiju_" + toolPropName;
        
        // check if properties exist already, or if need to create
        IntPropertyMap kaijuintmap = mapmgr.getIntPropertyMap(propertyName);
        if (kaijuintmap == null) {
            // didn't exist so create it!
            try {
                kaijuintmap = mapmgr.createIntPropertyMap​(propertyName);
            } catch (DuplicateNameException e) {
                // shouldn't get here but ghidra requires catching
                kaijuintmap = mapmgr.getIntPropertyMap(propertyName);
            } catch (NoTransactionException e) {
                // TODO: should we do something else?
                throw e;
            }
        }
        
        kaijuintmap.add(program.getMinAddress(), newValue);
    
    }

}

