package kaiju.tools.ghihorn.display;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Font;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextPane;
import javax.swing.border.BevelBorder;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import ghidra.util.Msg;
import kaiju.tools.ghihorn.GhiHornPlugin;
import kaiju.tools.ghihorn.answer.format.GhiHornDisplaySettings;
import kaiju.tools.ghihorn.answer.format.GhiHornTextFormatter;
import kaiju.tools.ghihorn.display.graph.GhiHornAnswerGraphComponent;
import kaiju.tools.ghihorn.hornifer.GhiHornEvent;
import kaiju.tools.ghihorn.hornifer.GhiHornifier;
import kaiju.tools.ghihorn.hornifer.GhiHornifier.TerminateReason;
import kaiju.tools.ghihorn.hornifer.horn.GhiHornAnswer;
import kaiju.tools.ghihorn.z3.GhiHornFixedpointStatus;

/**
 * Common properties for Horn displays
 */
public abstract class GhiHornFrontEnd implements PropertyChangeListener {

    private GhiHornAnswer currentResult;
    private final String name;
    protected final GhiHornPlugin plugin;
    private Map<GhiHornEvent, String> eventConfig;

    // The IDs for properties all displays must handle
    protected String updateMessageID;
    protected String terminateMessageID;
    protected String resultMessageID;


    protected GhiHornDisplaySettings displaySettings;

    protected GhiHornFrontEnd(final String n, final GhiHornPlugin p) {

        this.name = n;
        this.plugin = p;
        this.displaySettings = new GhiHornDisplaySettings();
        this.eventConfig = new HashMap<>();

        // Initialize specific tools
        initialize();
    }

    public Map<GhiHornEvent, String> getEventConfig() {
        return this.eventConfig;
    }

    public void registerEvent(final String id, final GhiHornEvent evt) {
        eventConfig.put(evt, id);
    }

    /**
     * @param displaySettings the displaySettings to set
     */
    public void setDisplaySettings(GhiHornDisplaySettings displaySettings) {
        this.displaySettings = displaySettings;
    }

    public String getName() {
        return name;
    }

    /**
     * Receive events from the ApiAnalyzer command, either log or output
     */
    @Override
    public void propertyChange(PropertyChangeEvent evt) {

        final String propName = evt.getPropertyName();

        if (propName.equalsIgnoreCase(eventConfig.get(GhiHornEvent.StatusMessage))) {
            final String msg = (String) evt.getNewValue();
            status(msg);

        } else if (propName.equalsIgnoreCase(eventConfig.get(GhiHornEvent.TerminateMessage))) {
            final GhiHornifier.TerminateReason reason =
                    (GhiHornifier.TerminateReason) evt.getNewValue();
            terminate(reason);

        } else if (propName.equalsIgnoreCase(eventConfig.get(GhiHornEvent.ResultMessage))) {
            currentResult = (GhiHornAnswer) evt.getNewValue();
            result(currentResult);

        } else {
            Msg.info(this, "Unknown event received: " + propName);
        }
    }

    public void terminate(GhiHornifier.TerminateReason reason) {
        this.plugin.getProvider().analysisComplete(reason);
        if (reason == TerminateReason.Cancelled) {
            this.plugin.cancel();
        }
    }

    /**
     * Present the results as a graph
     * 
     * @param newGraph
     * @param mon
     * @return
     */
    protected JPanel installAnswerAsGraph(final GhiHornAnswer result) throws Exception {
        GhiHornAnswerGraphComponent graph =
                new GhiHornAnswerGraphComponent(plugin, result.answerGraph);

        if (displaySettings == null) {
            displaySettings = new GhiHornDisplaySettings();
        }

        graph.build(displaySettings);
        return graph.getComponent();
    }

    /**
     * Install the result as text
     * 
     * @param result
     * @return
     * @throws Exception
     */
    protected JPanel installResultsAsText(final GhiHornAnswer result) throws Exception {

        JTextPane textPane = new JTextPane();
        SimpleAttributeSet attributeSet = new SimpleAttributeSet();

        Font font = new Font("Monospaced", Font.BOLD, 12);
        textPane.setFont(font);

        if (result.status == GhiHornFixedpointStatus.Satisfiable) {
            StyleConstants.setForeground(attributeSet, Color.blue);
        } else if (result.status == GhiHornFixedpointStatus.Unsatisfiable) {
            StyleConstants.setForeground(attributeSet, Color.red);
        }

        textPane.setCharacterAttributes(attributeSet, true);

        if (result.answerGraph != null) {
            StringBuilder sb = new StringBuilder();
            new GhiHornTextFormatter(displaySettings).format(result.answerGraph, sb);
            textPane.setText(sb.toString());
        }
        return new JPanel(new BorderLayout()) {
            {
                setBorder(BorderFactory.createBevelBorder(BevelBorder.RAISED));
                add(new JScrollPane(textPane), BorderLayout.CENTER);
            }
        };
    }

    public void refresh() {
        result(currentResult);
    }

    ///////////////////////////////////////////////////////////////////////////////////////////////
    ////
    //// The API that specifc tools must implement
    ////
    ///////////////////////////////////////////////////////////////////////////////////////////////

    public abstract void initialize();

    public abstract Map<String, Object> getSettings();

    public abstract void enable();

    public abstract void disable();

    public abstract void result(GhiHornAnswer result);

    public abstract void status(String message);

    public abstract List<GhiHornAnswer> getResults(boolean includeErrors);

    public abstract void reset();

    public abstract JComponent getMaiComponent();
}
