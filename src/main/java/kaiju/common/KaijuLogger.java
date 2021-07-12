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
package kaiju.common;

import kaiju.common.MultiLogger;
import kaiju.common.MultiLogLevel;

/**
 * Provides an easy interface to the multi-logging capabability.
 * Other classes should implement this one to get default access
 * to the multilogger without needing to initialize a MultiLogger
 * in each class constructor.
 */
public interface KaijuLogger {

    default void debug(Object originator, Object message) {
        MultiLogger logger = MultiLogger.getInstance();
        logger.debug(originator, message);
    }

    default void debug(Object originator, Object message, Throwable throwable) {
        MultiLogger logger = MultiLogger.getInstance();
        logger.debug(originator, message, throwable);
    }

    default void error(Object originator, Object message) {
        MultiLogger logger = MultiLogger.getInstance();
        logger.error(originator, message);
    }

    default void error(Object originator, Object message, Throwable throwable) {
        MultiLogger logger = MultiLogger.getInstance();
        logger.error(originator, message, throwable);
    }

    default void info(Object originator, Object message) {
        MultiLogger logger = MultiLogger.getInstance();
        logger.info(originator, message);
    }

    default void info(Object originator, Object message, Throwable throwable) {
        MultiLogger logger = MultiLogger.getInstance();
        logger.info(originator, message, throwable);
    }

    default void trace(Object originator, Object message) {
        MultiLogger logger = MultiLogger.getInstance();
        logger.trace(originator, message);
    }

    default void trace(Object originator, Object message, Throwable throwable) {
        MultiLogger logger = MultiLogger.getInstance();
        logger.trace(originator, message, throwable);
    }

    default void warn(Object originator, Object message) {
        MultiLogger logger = MultiLogger.getInstance();
        logger.warn(originator, message);
    }

    default void warn(Object originator, Object message, Throwable throwable) {
        MultiLogger logger = MultiLogger.getInstance();
        logger.warn(originator, message, throwable);
    }
    
    default void setLogLevel(MultiLogLevel new_level) {
        MultiLogger logger = MultiLogger.getInstance();
        logger.setLogLevel(new_level);
    }
} 
