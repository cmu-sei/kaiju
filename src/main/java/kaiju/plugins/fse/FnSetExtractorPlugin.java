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
package kaiju.plugins.fse;

import javax.swing.ImageIcon;
import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.TreeMap;

import db.NoTransactionException;
import docking.ActionContext;
import docking.action.*;
import docking.widgets.OptionDialog;
import docking.widgets.dialogs.SettingsDialog;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.table.GTable;
import ghidra.MiscellaneousPluginPackage;
import ghidra.app.CorePluginPackage;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.data.DataSettingsDialog;
import ghidra.app.services.GoToService;
import ghidra.framework.main.FrontEndable;
import ghidra.framework.model.*;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.ObjectPropertyMap;
import ghidra.program.util.*;
import ghidra.util.HelpLocation;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.VersionException;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.SelectionNavigationAction;
import ghidra.util.table.actions.MakeProgramSelectionAction;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.SwingUpdateManager;
import resources.Icons;
import resources.ResourceManager;

import kaiju.KaijuPluginPackage;
import kaiju.analyzers.FnHashAnalyzer;
import kaiju.util.KaijuPropertyManager;
import kaiju.util.MultiLogger;
import kaiju.fnhash.internal.FnHashSaveable;
import kaiju.fnhash.export.GTableToYARA;

/**
 * Plugin that provides a table comparing hashes between different Programs within Ghidra Project.
 * More or less replaces fse.py from pharos tools.
 *
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.UNSTABLE, // change to RELEASED when ready
    packageName = KaijuPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "CERT Function Intersection Visualizer",
    description = "Compare sets of functions across programs in a project."
)
//@formatter:on
public class FnSetExtractorPlugin extends Plugin implements FrontEndable {

    private FnSetExtractorProvider provider;
    private MultiLogger logger;
    private SwingUpdateManager reloadUpdateMgr;
    
    // need to save which Project we're working on for later analysis
    private Project currentProject;
    private FnSetExtractor extractor;

    public FnSetExtractorPlugin(PluginTool tool) {
        super(tool);
        logger = MultiLogger.getInstance();
        currentProject = tool.getProject();
        extractor = new FnSetExtractor(currentProject.getProjectData());
    }
    
    public FnSetExtractor getExtractor() {
        return extractor;
    }

    @Override
    protected void init() {
        super.init();

        provider = new FnSetExtractorProvider(this);
        reloadUpdateMgr = new SwingUpdateManager(100, 60000, this::doReload);
        createActions();
    }

    private void createActions() {
    
        /**
         * Refresh action
         */
        DockingAction refreshAction = new DockingAction("Refresh Intersection Table", getName()) {

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return false;
            }

            @Override
            public void actionPerformed(ActionContext context) {
                reload();
            }
        };
        ImageIcon refreshIcon = Icons.REFRESH_ICON;
        refreshAction.setDescription("Refresh the intersection table data");
        refreshAction.setToolBarData(new ToolBarData(refreshIcon));
        refreshAction.setHelpLocation(new HelpLocation("FnSetExtractorPlugin", "RefreshTable"));
        tool.addLocalAction(provider, refreshAction);

    }
    
    public void doReload() {
        reload();
    }

    void reload() {
        reloadUpdateMgr.update();
    }

}
