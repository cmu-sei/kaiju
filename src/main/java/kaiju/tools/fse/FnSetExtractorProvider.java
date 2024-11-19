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
package kaiju.tools.fse;

import java.awt.Dimension;
import java.awt.GridLayout;
import java.util.TreeMap;
import java.util.Vector;

import javax.swing.ImageIcon;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.util.HelpLocation;
import resources.ResourceManager;

/**
 * Provider for the FnHash FnSetExtractor table.
 */
public class FnSetExtractorProvider extends ComponentProviderAdapter {

    public static final ImageIcon ICON = ResourceManager.loadImage("images/Kaiju.png");
    private JComponent mainPanel;
    public FnSetExtractorProvider(FnSetExtractorPlugin plugin) {

        super(plugin.getTool(), "CERT Kaiju Function Intersection Visualizer", plugin.getName());
        
        FnSetExtractor extractor = plugin.getExtractor();

        Vector<Object> columnNames = getColumnNames(extractor);
        Vector<Vector<Object>> data = getTableData(extractor);
 
        final JTable table = new JTable(data, columnNames);
        table.setPreferredScrollableViewportSize(new Dimension(500, 70));
        table.setFillsViewportHeight(true);
 
        //Create the scroll pane and add the table to it.
        JScrollPane scrollPane = new JScrollPane(table);
 
        //Add the scroll pane to this panel.
        mainPanel = new JPanel(new GridLayout(1,0));
        mainPanel.add(scrollPane);
        
        setIcon(ICON);
        new HelpLocation(plugin.getName(), plugin.getName());
        addToTool();
    }
    
    private Vector<Object> getColumnNames(FnSetExtractor extractor) {
        
        TreeMap<String, String> fileHash2Name = extractor.getFileHash2Name();
        
        Vector<Object> columnNames = new Vector<>();
        // since we use descending key order here, should match vector in next loop
        for (String fmd5 : fileHash2Name.descendingKeySet()) {
            columnNames.add(fileHash2Name.get(fmd5));
        }
        String[] additional_cols = {"i","b","pic"};
        for (String col : additional_cols) {
            columnNames.add(col);
        }
    
        return columnNames;
    }
    
    private Vector<Vector<Object>> getTableData(FnSetExtractor extractor) {
        Vector<Vector<Object>> data = new Vector<>();
        
        TreeMap<String, Vector<ExtractedFunction>> fn2hashvec = extractor.getHashVec2Fn();
        
        for (String vec : fn2hashvec.descendingKeySet()) {
        
            // loop over all hashes of the vector
            for (ExtractedFunction fnhash : fn2hashvec.get(vec)) {
            
                Vector<Object> row = new Vector<>();
                    
                // Copy character by character into vector
                for (int i = 0; i < vec.length(); i++) {
                    if (vec.charAt(i) == '1') {
                        row.add("X");
                    } else {
                        row.add(" ");
                    }
                }
                    
                // add additional non-program columns, like PIC hash, etc.
                // NOTE: be very sure it matches the same order as the columns in getColumnNames()!
                row.add(fnhash.getNumInstructions());
                row.add(fnhash.getNumBytes());
                row.add(fnhash.getPICHash());
                    
                // finally add full row vector to data vector
                data.add(row);
                
            }
            
        }
        
        return data;
    }
    
    @Override
    public JComponent getComponent() {
        return mainPanel;
    }

}
