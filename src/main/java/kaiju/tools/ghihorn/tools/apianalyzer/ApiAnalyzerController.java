package kaiju.tools.ghihorn.tools.apianalyzer;

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.HierarchyEvent;
import java.awt.event.HierarchyListener;
import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextPane;
import javax.swing.SwingConstants;
import javax.swing.border.BevelBorder;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import com.google.common.base.Preconditions;
import com.google.common.base.Verify;
import com.google.common.base.VerifyException;
import docking.widgets.OkDialog;
import docking.widgets.combobox.GhidraComboBox;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import docking.widgets.table.GTableWidget;
import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.util.SystemUtilities;
import kaiju.tools.ghihorn.GhiHornPlugin;
import kaiju.tools.ghihorn.GhiHornProvider;
import kaiju.tools.ghihorn.display.GhiHornController;
import kaiju.tools.ghihorn.hornifer.GhiHornCommandEvent;
import kaiju.tools.ghihorn.hornifer.GhiHornifier;
import kaiju.tools.ghihorn.hornifer.horn.GhiHornAnswer;
import kaiju.tools.ghihorn.tools.GhiHornEventConfig;
import kaiju.tools.ghihorn.tools.apianalyzer.json.ApiSignatureJsonParser;
import kaiju.tools.ghihorn.z3.GhiHornFixedpointStatus;

//@formatter:off
@ApiAnalyzerConfig(events = @GhiHornEventConfig(completeUpdate = "AA:TU", 
                                                statusUpdate = "AA:SU",
                                                resultUpdate = "AA:RU"), 
                    signatures = "AA:Sig")
//@formatter:on
public class ApiAnalyzerController extends GhiHornController {

    public static final String NAME = "ApiAnalyzer";
    public static final String DEFAULT_SIG_FILENAME = "signature.json";
    private ApiAnalyzerConfig configuration;
    private final JTabbedPane resultsTabbedPane;
    private final JPanel mainPanel;
    private final GhidraComboBox<ApiSignature> sigComboBox;
    private final JButton loadSignatureButton;

    private JTextPane statusTextPane;
    private GTableWidget<ApiAnalyzerTableRowData> resultsTable;
    private List<ApiSignature> signatures;
    private JPanel statusPanel;

    public ApiAnalyzerController(final GhiHornPlugin plugin) {

        super(NAME, plugin);

        this.mainPanel = new JPanel();

        mainPanel.setBorder(BorderFactory.createBevelBorder(BevelBorder.RAISED));
        final GridBagConstraints gbConstraints = new GridBagConstraints();
        mainPanel.setLayout(new GridBagLayout());

        this.resultsTabbedPane = new JTabbedPane();

        this.statusPanel = makeStatusPanel();
        final JSplitPane splitPane =
                new JSplitPane(SwingConstants.VERTICAL, statusPanel, this.resultsTabbedPane);
        loadSignatureButton = new JButton("Load Signature File");

        // Load the default signature file
        this.sigComboBox = new GhidraComboBox<>();
        final ResourceFile rf = Application.findDataFileInAnyModule(DEFAULT_SIG_FILENAME);

        File sigFile = rf.getFile(false);
        int sigCount = loadApiSignatures(sigFile);
        if (sigCount == -1) {
            OkDialog.showError("Problem Loading Signatures",
                    "There was a problem loading signatures from '" + sigFile.getName() + "'");
            return;
        }
        status("Loaded " + sigCount + " signatures from " + sigFile.getName());

        loadSigChoices();

        sigComboBox.setEnabled(true);
        this.sigComboBox.setSelectedIndex(0);

        final GhiHornProvider provider = plugin.getProvider();
        if (provider != null) {
            provider.enableAnalysis();
        }        

        gbConstraints.gridx = 1;
        gbConstraints.gridy = 1;
        gbConstraints.gridwidth = 1;
        gbConstraints.gridheight = 1;
        gbConstraints.fill = GridBagConstraints.NONE;
        gbConstraints.weightx = 0;
        gbConstraints.weighty = 0;
        gbConstraints.anchor = GridBagConstraints.NORTHWEST;
        mainPanel.add(loadSignatureButton, gbConstraints);

        gbConstraints.gridx = 2;
        gbConstraints.gridy = 1;
        gbConstraints.gridwidth = 1;
        gbConstraints.gridheight = 1;
        gbConstraints.fill = GridBagConstraints.NONE;
        gbConstraints.weightx = 0;
        gbConstraints.weighty = 0;
        gbConstraints.anchor = GridBagConstraints.WEST;
        mainPanel.add(sigComboBox, gbConstraints);

        gbConstraints.gridx = 1;
        gbConstraints.gridy = 2;
        gbConstraints.gridwidth = GridBagConstraints.REMAINDER;
        gbConstraints.gridheight = GridBagConstraints.REMAINDER;
        gbConstraints.fill = GridBagConstraints.BOTH;
        gbConstraints.weightx = 1;
        gbConstraints.weighty = 1;
        gbConstraints.anchor = GridBagConstraints.NORTH;
        gbConstraints.insets.right = 10;
        mainPanel.add(splitPane, gbConstraints);

        loadSignatureButton.addActionListener(e -> {
            try {
                File jsonFile = selectSignatureFile();
                if (jsonFile == null) {
                    // No file selected or dialog cancelled
                    return;
                }
                int count = loadApiSignatures(jsonFile);
                if (-1 == count) {
                    OkDialog.showError("Problem",
                            "There was a problem loading signatures from '" + jsonFile + "'");
                }
                status("Loaded " + count + " signatures from " + sigFile.getName());
                loadSigChoices();

            } catch (VerifyException ve) {
                OkDialog.showError("Error loading signatures", ve.getMessage());
            }
        });

        setDividerLocation(splitPane, 0.5); // middle
        splitPane.setOrientation(SwingConstants.VERTICAL);
    }

    private void loadSigChoices() {
        sigComboBox.removeAllItems();
        sigComboBox.addItem(ApiSignature.allSignatures());
        for (ApiSignature sig : this.signatures) {
            try {

                Verify.verifyNotNull(sig.getName(), "Invalid signature name");
                Verify.verifyNotNull(sig.getSequence(),
                        "Invalid signature sequence for " + sig.getName());
                Verify.verifyNotNull(sig.getSequence().isEmpty() == false,
                        "Empty signature for " + sig.getName());
                sigComboBox.addItem(sig);
            } catch (VerifyException ve) {
                status("Skipping sig: " + ve.getMessage());
            }
        }
    }

    /**
     * Select the signature file
     * 
     * @returnThe signature file or null
     */
    private File selectSignatureFile() {

        final GhidraFileChooser chooser = new GhidraFileChooser(null);
        chooser.setTitle("API Analyzer Signature File");
        final ResourceFile rf = Application.findDataFileInAnyModule(DEFAULT_SIG_FILENAME);
        chooser.setSelectedFile(rf.getFile(false));
        chooser.setApproveButtonText("Select signature file");
        chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);

        Supplier<File> supplier = () -> {
            return chooser.getSelectedFile();
        };

        final File jsonFile = SystemUtilities.runSwingNow(supplier);

        return jsonFile;
    }

    /**
     * Parse signatures out of a JSON file.
     * 
     * @param jsonFile
     */
    private int loadApiSignatures(final File jsonFile) {

        if (jsonFile != null) {
            if (this.signatures != null && !signatures.isEmpty()) {
                this.signatures.clear();
            }
            this.signatures = (new ApiSignatureJsonParser(jsonFile)).parse();
            return this.signatures.size();

        }
        return -1;
    }

    /**
     * Update status window
     * 
     * @param statusUpdate
     */
    public void status(final String statusUpdate) {
        try {
            synchronized (statusTextPane) {
                appendEntry(statusTextPane, statusUpdate);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 
     * @return a formatted date
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
    private synchronized void appendEntry(JTextPane pane, final String entry)
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
    private void displayResult(final GhiHornAnswer answer) {

        JPanel graphPanel = null;
        try {
            graphPanel = installAnswerAsGraph(answer);
        } catch (Exception e) {
            e.printStackTrace();
            graphPanel = new JPanel() {
                {
                    add(new JTextArea("Failed to generate graph for answer"));
                    setBorder(BorderFactory.createBevelBorder(BevelBorder.RAISED));
                }
            };
        }

        JPanel textPanel = null;
        try {
            textPanel = installResultsAsText(answer);
        } catch (Exception e) {
            e.printStackTrace();
            textPanel = new JPanel() {
                {
                    add(new JTextArea("Failed to generate text answer"));
                    setBorder(BorderFactory.createBevelBorder(BevelBorder.RAISED));
                }
            };

        }
        plugin.getProvider().highlightAnswer(answer);

        if (graphPanel == null || textPanel == null) {
            status("No results to show");
        }

        if (this.resultsTabbedPane.getTabCount() > 0) {
            this.resultsTabbedPane.removeAll();
        }
        this.resultsTabbedPane.addTab("Graph", graphPanel);
        this.resultsTabbedPane.addTab("Text", textPanel);

        this.resultsTabbedPane.revalidate();
        this.resultsTabbedPane.repaint();
    }

    public void clearStatus() {
        synchronized (statusTextPane) {
            statusTextPane.setText("");
        }
    }

    /**
     * Update the output log
     * 
     * @param output
     */
    @Override
    public synchronized void result(final GhiHornAnswer res) {

        Preconditions.checkNotNull(resultsTable, "GhiHorn results are improperly configured");

        List<ApiAnalyzerTableRowData> validResults = this.resultsTable.getData();
        if (validResults == null) {
            validResults = new ArrayList<>();
        }

        if (res.status != GhiHornFixedpointStatus.Error) {
            ApiAnalyzerTableRowData rowData = new ApiAnalyzerTableRowData();
            rowData.result = res;
            rowData.searchCoordinates = (ApiAnalyzerArgument) res.arguments;
            validResults.add(rowData);
        }
        refresh();
    }

    /**
     * Refresh the table data
     */
    public void refresh() {

        synchronized (this.resultsTable) {
            List<ApiAnalyzerTableRowData> validResults = this.resultsTable.getData();
            final var model = this.resultsTable.getModel();
            model.setModelData(validResults);
            model.refresh();
        }
    }

    /**
     * Bean for the result table
     */
    public class ApiAnalyzerTableRowData {
        private GhiHornAnswer result;
        private ApiAnalyzerArgument searchCoordinates;

        public String getMatch() {
            return searchCoordinates.getSignature().getName();
        }

        public Address getEntry() {
            return searchCoordinates.getEntryAsAddress();
        }

        public Address getStart() {
            return searchCoordinates.getStartAsAddress();
        }

        public Address getGoal() {
            return searchCoordinates.getGoalAsAddress();
        }

        public GhiHornFixedpointStatus getStatus() {
            return result.status;
        }
    }

    /**
     * Make the status panel
     * 
     * @return
     */
    private JPanel makeStatusPanel() {

        this.resultsTable = new GTableWidget<>(NAME, ApiAnalyzerTableRowData.class, "getMatch",
                "getEntry", "getStart", "getGoal", "getStatus");

        this.resultsTable.setToolTipText(
                "Display ApiAnalyzer results. Entry: entry point selected; Start: first API found; Goal: the last API found");

        resultsTable.addSelectionListener(rowData -> {
            if (rowData != null) {
                displayResult(rowData.result);
            }
        });
        resultsTable.setItemPickListener(rowData -> {
            if (rowData != null) {
                displayResult(rowData.result);
            }
        });
        final JScrollPane resultsTableScrollPane = new JScrollPane(resultsTable);
        resultsTableScrollPane.setBorder(BorderFactory.createLineBorder(Color.black, 1, true));

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
        panel.add(resultsTableScrollPane, gbConstraints);

        gbConstraints.gridx = 0;
        gbConstraints.gridy = 2;
        gbConstraints.gridwidth = GridBagConstraints.HORIZONTAL;
        gbConstraints.gridheight = 2;
        gbConstraints.fill = GridBagConstraints.BOTH;
        gbConstraints.weightx = 2;
        gbConstraints.weighty = 2;
        gbConstraints.anchor = GridBagConstraints.SOUTHWEST;
        panel.add(statusScrollPane, gbConstraints);

        return panel;
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

    @Override
    public void enable() {
        this.sigComboBox.setEnabled(true);
        this.loadSignatureButton.setEnabled(true);
    }

    @Override
    public void disable() {
        this.sigComboBox.setEnabled(false);
        this.loadSignatureButton.setEnabled(true);
    }

    @Override
    public void reset() {
        this.resultsTable.setData(new ArrayList<>());
        clearStatus();
    }

    /**
     * 
     */
    @Override
    public List<Map<String, Object>> getCommandParameters() {

        List<Map<String, Object>> cmdParams = new ArrayList<>();

        final List<ApiSignature> signatures = new ArrayList<>();

        final ApiSignature selectedSig = (ApiSignature) sigComboBox.getSelectedItem();
        if (selectedSig.getName().equals(ApiSignature.ALL_SIGS)) {
            for (int i = 1; i < sigComboBox.getItemCount(); i++) {
                signatures.add(sigComboBox.getItemAt(i));
            }
            status("Looking for all API signatures");
        } else {
            signatures.add(selectedSig);
            status("Looking for API signature: " + selectedSig.getName());
        }

        // Each signature will get a command
        for (ApiSignature sig : signatures) {
            cmdParams.add(new HashMap<>() {
                {
                    put(configuration.signatures(), sig);
                }
            });
        }
        return cmdParams;
    }

    @Override
    public String getName() {
        return super.getName();
    }

    @Override
    public void initialize() {
        this.configuration = ApiAnalyzerController.class.getAnnotation(ApiAnalyzerConfig.class);

        registerCommandEvent(configuration.events().statusUpdate(),
                GhiHornCommandEvent.StatusMessage);
        registerCommandEvent(configuration.events().resultUpdate(),
                GhiHornCommandEvent.ResultReady);
        registerCommandEvent(configuration.events().completeUpdate(),
                GhiHornCommandEvent.Completed);
        registerCommandEvent(configuration.events().cancelUpdate(), GhiHornCommandEvent.Cancelled);
    }

    @Override
    public List<GhiHornAnswer> getResults(boolean includeErrors) {
        if (includeErrors) {
            return this.resultsTable.getData()
                    .stream()
                    .map(r -> r.result)
                    .filter(r -> r.status != GhiHornFixedpointStatus.Error)
                    .collect(Collectors.toList());
        }
        return this.resultsTable.getData()
                .stream()
                .map(r -> r.result)
                .collect(Collectors.toList());

    }

    @Override
    public JComponent getMainComponent() {
        return mainPanel;
    }

    @Override
    public String getControllerName() {
        return NAME;
    }

    @Override
    public GhiHornifier getHornifiier() {
        return new ApiAnalyzerHornifier();
    }
}
