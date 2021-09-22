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
 * 5. Gradle (https://github.com/gradle/gradle/blob/master/LICENSE) Copyright 2021 Gradle Inc.
 * 6. markdown-gradle-plugin (https://github.com/kordamp/markdown-gradle-plugin/blob/master/LICENSE.txt) Copyright 2020 Andres Almiray.
 * 7. Z3 (https://github.com/Z3Prover/z3/blob/master/LICENSE.txt) Copyright 2021 Microsoft Corporation.
 * 8. jopt-simple (https://github.com/jopt-simple/jopt-simple/blob/master/LICENSE.txt) Copyright 2021 Paul R. Holser, Jr.
 *
 * DM21-0792
 */

package kaiju.tools.ooanalyzer;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.File;
import java.util.concurrent.atomic.AtomicReference;

import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JPanel;

import docking.DialogComponentProvider;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.SystemUtilities;

/**
 * Dialog for the plugin
 *
 */
public class OOAnalyzerDialog extends DialogComponentProvider {

  // The JSON file containing OO data
  private File jsonFile = null;

  // Assume we will organize data types into
  private Boolean useOOAnalyzerNamespace = true;

  private Boolean isCancelled = false;

  /**
   * Open the dialog.
   *
   * @param c      the control manager
   * @param parent the parent window
   */
  public OOAnalyzerDialog(String title) {
    super(title);

    JPanel workPanel = new JPanel(new GridBagLayout());
    GridBagConstraints cs = new GridBagConstraints();

    cs.fill = GridBagConstraints.HORIZONTAL;

    JButton selectJsonFile = new JButton("Open JSON File");
    selectJsonFile.setToolTipText("Select the OOAnalyzer JSON file.");

    selectJsonFile.addActionListener(new ActionListener() {
        @Override
        public void actionPerformed(ActionEvent e) {

          GhidraFileChooser chooser = new GhidraFileChooser(null);
          AtomicReference<File> selectedFileRef = new AtomicReference<>();

          Runnable r = () -> {
            ExtensionFileFilter filter = new ExtensionFileFilter ("json", "JSON files");
            chooser.addFileFilter(filter);
            chooser.setTitle("OOAnalyzer JSON File");
            chooser.setSelectedFile(selectedFileRef.get());
            chooser.setApproveButtonText("Select");
            chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
            selectedFileRef.set(chooser.getSelectedFile());
          };

          SystemUtilities.runSwingNow(r);

          jsonFile = selectedFileRef.get();
          if (jsonFile != null) {
            JButton button = ((JButton) e.getSource());
            button.setText("Selected File: " + jsonFile.getName());
          }
        }
      });

    cs.gridx = 0;
    cs.gridy = 0;
    cs.gridwidth = 1;
    workPanel.add(selectJsonFile, cs);

    JCheckBox cbNamespace = new JCheckBox("Use OOAnalyzer namespace");

    cbNamespace.setToolTipText(
      "Organize standard classes added or changed by OOAnalyzer in a namespace named 'OOAnalyzer'.");
    cbNamespace.addItemListener(new ItemListener() {
        @Override
        public void itemStateChanged(ItemEvent e) {
          useOOAnalyzerNamespace = (e.getStateChange() == ItemEvent.SELECTED);
        }
      });

    cbNamespace.setSelected(useOOAnalyzerNamespace);
    cs.gridx = 0;
    cs.gridy = 1;
    cs.gridwidth = 1;
    workPanel.add(cbNamespace, cs);

    addOKButton();
    setOkEnabled(true);

    addCancelButton();
    setCancelEnabled(true);

    addWorkPanel(workPanel);
  }

  @Override
  protected void okCallback() {
    close();
  }

  @Override
  protected void cancelCallback() {
    setCancelled(true);
    close();
  }

  @Override
  protected void escapeCallback() {
    setCancelled(true);
    close();
  }

  public Boolean useOOAnalyzerNamespace() {
    return this.useOOAnalyzerNamespace;
  }

  public File getJsonFile() {
    return this.jsonFile;
  }

  /**
   * @return the isCancelled
   */
  public Boolean isCancelled() {
    return isCancelled;
  }

  /**
   * @param isCancelled the isCancelled to set
   */
  public void setCancelled(Boolean isCancelled) {
    this.isCancelled = isCancelled;
  }
}
