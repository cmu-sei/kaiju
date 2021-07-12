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
package kaiju.tools.fnhash;

import java.util.List;
import java.util.function.Predicate;

import docking.ActionContext;
import ghidra.app.context.DataLocationListContext;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.table.GhidraTable;

public class HashViewerContext extends ActionContext implements DataLocationListContext {

    private HashViewerProvider hashViewerProvider;

    HashViewerContext(HashViewerProvider provider, GhidraTable stringsTable) {
        super(provider, stringsTable);
        hashViewerProvider = provider;
    }

    GhidraTable getStringsTable() {
        return (GhidraTable) getContextObject();
    }

    @Override
    public int getCount() {
        return hashViewerProvider.getSelectedRowCount();
    }

    @Override
    public Program getProgram() {
        return hashViewerProvider.getProgram();
    }

    @Override
    public List<ProgramLocation> getDataLocationList() {
        return hashViewerProvider.getSelectedDataLocationList(null);
    }

    @Override
    public List<ProgramLocation> getDataLocationList(Predicate<Data> filter) {
        return hashViewerProvider.getSelectedDataLocationList(filter);
    }
}
