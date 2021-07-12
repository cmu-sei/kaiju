package kaiju.tools.ghihorn.tools.pathanalyzer;

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.HierarchyEvent;
import java.awt.event.HierarchyListener;
import java.awt.event.ItemEvent;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.SwingConstants;
import javax.swing.border.BevelBorder;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SymbolTable;
import kaiju.tools.ghihorn.GhiHornPlugin;
import kaiju.tools.ghihorn.display.GhiHornFrontEnd;
import kaiju.tools.ghihorn.hornifer.GhiHornEvent;
import kaiju.tools.ghihorn.hornifer.horn.GhiHornAnswer;
import kaiju.tools.ghihorn.tools.GhiHornEventConfig;
import kaiju.tools.ghihorn.z3.GhiHornFixedpointStatus;

@PathAnalyzerConfig(
        events = @GhiHornEventConfig(
                terminateUpdate = "PA:TU",
                statusUpdate = "PA:SU",
                resultUpdate = "PA:RU"),
        startAddress = "PA:SA",
        endAddress = "PA:EA")
public class PathAnalyzerFrontEnd extends GhiHornFrontEnd {

    public static final String NAME = "PathAnalyzer";
    private PathAnalyzerConfig configuration;
    private JPanel mainPanel;
    private JTextField goalAddrText;
    private JTextField startAddrText;
    private JCheckBox startAtEPCheckbox;
    private JTabbedPane resultsTabbedPane;
    private JTextPane statusTextPane;
    private List<GhiHornAnswer> results;

    public PathAnalyzerFrontEnd() {
        super(NAME, null);
    }

    /**
     * 
     * @param plugin
     */
    public PathAnalyzerFrontEnd(final GhiHornPlugin plugin) {

        super(NAME, plugin);


        this.mainPanel = new JPanel();

        mainPanel.setBorder(BorderFactory.createBevelBorder(BevelBorder.RAISED));
        final GridBagConstraints gbConstraints = new GridBagConstraints();
        mainPanel.setLayout(new GridBagLayout());

        final JLabel startLabel = new JLabel("Start address: ");
        final JLabel endLabel = new JLabel("End address: ");

        this.startAddrText = new JTextField(20);
        startAddrText.setMinimumSize(startAddrText.getPreferredSize());

        this.goalAddrText = new JTextField(20);
        goalAddrText.setMinimumSize(startAddrText.getPreferredSize());
        startAddrText.setEnabled(false);

        final List<Address> entryPointAddrs = new ArrayList<>();
        plugin.getCurrentProgram().getSymbolTable().getExternalEntryPointIterator()
                .forEach(entryPointAddrs::add);

        startAtEPCheckbox = new JCheckBox();
        startAtEPCheckbox.setSelected(true);
        startAddrText.setMinimumSize(startAddrText.getPreferredSize());
        if (entryPointAddrs.size() == 1) {
            startAtEPCheckbox.setText("Start at program entry point");
            startAtEPCheckbox.setSelected(true);
            startAddrText.setText(entryPointAddrs.get(0).toString());
        } else if (entryPointAddrs.size() > 1) {
            startAtEPCheckbox.setText("Start at program entry point(s)");
            startAddrText.setText("Multiple entry points possible");
        } else {
            startAtEPCheckbox.setEnabled(false);
            startAddrText.setText("No entry point found, please specify address manually");
        }

        startAtEPCheckbox
                .addItemListener(
                        e -> startAddrText.setEnabled(e.getStateChange() != ItemEvent.SELECTED));

        this.results = new ArrayList<>();

        this.resultsTabbedPane = new JTabbedPane();
        final JPanel statusPanel = makeStatusPanel();

        final JSplitPane splitPane =
                new JSplitPane(SwingConstants.VERTICAL, statusPanel, this.resultsTabbedPane);

        setDividerLocation(splitPane, 0.5);
        splitPane.setOrientation(SwingConstants.VERTICAL);

        gbConstraints.gridx = 0;
        gbConstraints.gridy = 0;
        gbConstraints.gridwidth = GridBagConstraints.REMAINDER;
        gbConstraints.gridheight = 4;
        gbConstraints.fill = GridBagConstraints.BOTH;
        gbConstraints.weightx = 1;
        gbConstraints.weighty = 1;
        gbConstraints.anchor = GridBagConstraints.NORTH;
        gbConstraints.insets.right = 10;
        mainPanel.add(splitPane, gbConstraints);

        gbConstraints.gridx = 0;
        gbConstraints.gridy = 5;
        gbConstraints.gridwidth = 1;
        gbConstraints.gridheight = 1;
        gbConstraints.fill = GridBagConstraints.HORIZONTAL;
        gbConstraints.weightx = 0;
        gbConstraints.weighty = 0;
        gbConstraints.anchor = GridBagConstraints.SOUTHWEST;
        mainPanel.add(startLabel, gbConstraints);

        gbConstraints.gridx = 1;
        gbConstraints.gridy = 5;
        gbConstraints.gridwidth = 1;
        gbConstraints.gridheight = 1;
        gbConstraints.fill = GridBagConstraints.NONE;
        gbConstraints.weightx = 0;
        gbConstraints.weighty = 0;
        gbConstraints.anchor = GridBagConstraints.SOUTHWEST;
        mainPanel.add(startAddrText, gbConstraints);

        gbConstraints.gridx = 0;
        gbConstraints.gridy = 6;
        gbConstraints.gridwidth = 1;
        gbConstraints.gridheight = 1;
        gbConstraints.fill = GridBagConstraints.NONE;
        gbConstraints.weightx = 0;
        gbConstraints.weighty = 0;
        gbConstraints.anchor = GridBagConstraints.NORTHWEST;
        mainPanel.add(endLabel, gbConstraints);

        gbConstraints.gridx = 1;
        gbConstraints.gridy = 6;
        gbConstraints.gridwidth = 1;
        gbConstraints.gridheight = 1;
        gbConstraints.fill = GridBagConstraints.NONE;
        gbConstraints.weightx = 0;
        gbConstraints.weighty = 0;
        gbConstraints.anchor = GridBagConstraints.NORTHWEST;
        mainPanel.add(goalAddrText, gbConstraints);

        gbConstraints.gridx = 2;
        gbConstraints.gridy = 5;
        gbConstraints.gridwidth = 1;
        gbConstraints.gridheight = 1;
        gbConstraints.fill = GridBagConstraints.NONE;
        gbConstraints.weightx = 0;
        gbConstraints.weighty = 0;
        gbConstraints.anchor = GridBagConstraints.NORTHWEST;
        mainPanel.add(startAtEPCheckbox, gbConstraints);
    }

    /**
     * This is a hack to properly set the slider location
     * 
     * @param splitter
     * @param proportion
     * @return
     */
    private JSplitPane setDividerLocation(final JSplitPane splitter, final double proportion) {
        if (splitter.isShowing()) {
            if (splitter.getWidth() > 0 && splitter.getHeight() > 0) {
                splitter.setDividerLocation(proportion);
            } else {
                splitter.addComponentListener(new ComponentAdapter() {
                    @Override
                    public void componentResized(ComponentEvent ce) {
                        splitter.removeComponentListener(this);
                        setDividerLocation(splitter, proportion);
                    }
                });
            }
        } else {
            splitter.addHierarchyListener(new HierarchyListener() {

                @Override
                public void hierarchyChanged(HierarchyEvent e) {
                    if ((e.getChangeFlags() & HierarchyEvent.SHOWING_CHANGED) != 0
                            && splitter.isShowing()) {
                        splitter.removeHierarchyListener(this);
                        setDividerLocation(splitter, proportion);
                    }
                }

            });
        }
        return splitter;
    }

    /**
     * Update status window
     * 
     * @param statusUpdate
     */
    public void status(final String statusUpdate) {
        try {
            synchronized (statusTextPane) {
                appendStatusEntry(statusTextPane, statusUpdate);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Fetch the results
     */
    public List<GhiHornAnswer> getResults(boolean includeErrors) {
        if (includeErrors) {
            return this.results;
        }
        if (results != null) {
            return this.results.stream().filter(r -> r.status != GhiHornFixedpointStatus.Error)
                    .collect(Collectors.toList());
        }
        return new ArrayList<>();
    }

    /**
     * Convenience function to generate a date string
     * 
     * @return
     */
    private String getDateString() {
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
    }

    /**
     * 
     * @param pane
     * @param entry
     * @throws BadLocationException
     */
    private synchronized void appendStatusEntry(JTextPane pane, final String entry)
            throws BadLocationException {

        final SimpleAttributeSet attrSet = new SimpleAttributeSet();
        final StyledDocument doc = pane.getStyledDocument();

        StyleConstants.setForeground(attrSet, Color.gray);
        doc.insertString(doc.getLength(), "[" + getDateString() + "]: ", attrSet);

        StyleConstants.setForeground(attrSet, Color.black);
        doc.insertString(doc.getLength(), entry + "\n", attrSet);

        pane.setCaretPosition(doc.getLength());
    }

    /**
     * Update the result
     * 
     * @param answer
     */
    @Override
    public void result(final GhiHornAnswer answer) {
        try {

            if (answer.status == GhiHornFixedpointStatus.Satisfiable) {
                status("A path was found");
            } else if (answer.status == GhiHornFixedpointStatus.Unsatisfiable) {
                status("A path was *not* found");
            } else if (answer.status == GhiHornFixedpointStatus.Error) {
                status("An error occurred");
                return;
            }

            this.results.clear();
            this.results.add(answer);

            plugin.getProvider().highlightAnswer(answer);

            JPanel graphPanel = installAnswerAsGraph(answer);
            JPanel textPanel = installResultsAsText(answer);

            if (graphPanel == null || textPanel == null) {
                return;
            }

            if (this.resultsTabbedPane.getTabCount() > 0) {
                this.resultsTabbedPane.removeAll();
            }
            this.resultsTabbedPane.addTab("Graph", graphPanel);
            this.resultsTabbedPane.addTab("Text", textPanel);

            this.resultsTabbedPane.revalidate();
            this.resultsTabbedPane.repaint();

        } catch (

        Exception e) {
            e.printStackTrace();
        }
    }

    /**
    * 
    */
    public void clearStatus() {
        synchronized (statusTextPane) {
            statusTextPane.setText("");
        }
    }

    private JPanel makeStatusPanel() {

        statusTextPane = new JTextPane();
        statusTextPane.setEditable(false);

        final JScrollPane statusScrollPane = new JScrollPane(statusTextPane);
        statusScrollPane.setBorder(BorderFactory.createLineBorder(Color.black, 1, true));

        final GridBagConstraints gbConstraints = new GridBagConstraints();
        final JPanel panel = new JPanel();

        panel.setBorder(BorderFactory.createBevelBorder(BevelBorder.RAISED));
        panel.setLayout(new GridBagLayout());

        gbConstraints.gridx = 0;
        gbConstraints.gridy = 0;
        gbConstraints.gridwidth = 1;
        gbConstraints.gridheight = 1;
        gbConstraints.fill = GridBagConstraints.BOTH;
        gbConstraints.weightx = 0;
        gbConstraints.weighty = 0;
        gbConstraints.anchor = GridBagConstraints.WEST;
        panel.add(new JLabel("Status"), gbConstraints);

        gbConstraints.gridx = 0;
        gbConstraints.gridy = 1;
        gbConstraints.gridwidth = 1;
        gbConstraints.gridheight = 1;
        gbConstraints.fill = GridBagConstraints.BOTH;
        gbConstraints.weightx = 2;
        gbConstraints.weighty = 2;
        gbConstraints.anchor = GridBagConstraints.NORTHWEST;
        panel.add(statusScrollPane, gbConstraints);

        return panel;
    }

    @Override
    public void reset() {
        if (this.resultsTabbedPane != null) {
            this.resultsTabbedPane.removeAll();
        }
        clearStatus();
    }

    @Override
    public void enable() {
        goalAddrText.setEnabled(true);
        startAddrText.setEnabled(true);
    }

    @Override
    public void disable() {
        goalAddrText.setEnabled(false);
        startAddrText.setEnabled(false);
    }

    /**
     * 
     */
    private Address getStartAddress() throws AddressFormatException {
        final Program program = plugin.getCurrentProgram();
        if (startAtEPCheckbox.isSelected()) {
            SymbolTable symTable = program.getSymbolTable();
            List<Address> entryPointAddrs = new ArrayList<>();
            symTable.getExternalEntryPointIterator().forEach(entryPointAddrs::add);

            if (entryPointAddrs.size() > 1) {
                return plugin.getProvider().askChoice("Select Entry Point",
                        "Select entry point to start search:", entryPointAddrs, null);
            }
            if (entryPointAddrs.size() == 1) {
                return entryPointAddrs.get(0);
            }
        }

        return program.getAddressFactory().getDefaultAddressSpace()
                .getAddress(startAddrText.getText());
    }

    @Override
    public Map<String, Object> getSettings() {

        // Map<String, Object> settings = new HashMap<>();
        final Program program = this.plugin.getCurrentProgram();
        try {

            final Address startAddr = getStartAddress();
            if (startAddr == null) {
                throw new NullPointerException();
            }
            this.startAddrText.setText(startAddr.toString());

            final Address endAddr = program.getAddressFactory().getDefaultAddressSpace()
                    .getAddress(goalAddrText.getText());

            // Make sure that the program contains the specified addresses
            if (!program.getMemory().contains(startAddr)
                    || !program.getMemory().contains(endAddr)) {
                throw new RuntimeException();
            }

            status("Looking for path from " + startAddr + " to " + endAddr);
            return new HashMap<>() {
                {
                    put(GhiHornPlugin.TOOL_NAME, getName());
                    put(configuration.startAddress(), startAddr);
                    put(configuration.endAddress(), endAddr);
                }
            };

        } catch (AddressFormatException | NullPointerException e) {
            status("Invalid start/end address specified");
        }
        return new HashMap<>();
    }

    @Override
    public void initialize() {
        this.configuration = PathAnalyzerFrontEnd.class.getAnnotation(PathAnalyzerConfig.class);
        registerEvent(configuration.events().statusUpdate(), GhiHornEvent.StatusMessage);
        registerEvent(configuration.events().resultUpdate(), GhiHornEvent.ResultMessage);
        registerEvent(configuration.events().terminateUpdate(), GhiHornEvent.TerminateMessage);
    }

    @Override
    public JComponent getMaiComponent() {
        return this.mainPanel;
    }
}
