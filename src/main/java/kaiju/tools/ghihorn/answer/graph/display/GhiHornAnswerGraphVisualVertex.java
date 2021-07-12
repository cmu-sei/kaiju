package kaiju.tools.ghihorn.answer.graph.display;


import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.KeyboardFocusManager;
import java.awt.event.KeyEvent;
import java.awt.event.KeyListener;
import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import docking.GenericHeader;
import ghidra.graph.viewer.vertex.AbstractVisualVertex;
import kaiju.tools.ghihorn.answer.GhiHornUnsatAttributes;
import kaiju.tools.ghihorn.answer.GhiHornAnswerAttributes;
import kaiju.tools.ghihorn.answer.format.GhiHornDisplaySettings;
import kaiju.tools.ghihorn.answer.format.GhiHornTextFormatter;
import kaiju.tools.ghihorn.hornifer.horn.element.HornElement;
import kaiju.tools.ghihorn.z3.GhiHornFixedpointStatus;

/**
 * A vertex for the {@link GhiHornVisualAnswerGraph}
 */
public class GhiHornAnswerGraphVisualVertex extends AbstractVisualVertex {
    private final GhiHornAnswerAttributes attributes;
    private JPanel mainPanel = new JPanel(new BorderLayout());
    private JTextArea textArea;
    private GenericHeader genericHeader;

    public GhiHornAnswerGraphVisualVertex(GhiHornAnswerAttributes attrs,
            GhiHornDisplaySettings settings) {

        this.attributes = attrs;

        if (attributes != null) {

            textArea = new JTextArea();
            textArea.setLineWrap(false);

            genericHeader = new GenericHeader();
            genericHeader.setTitle(attrs.getName());

            final StringBuilder sb = new StringBuilder();
            new GhiHornTextFormatter(settings).format(attributes, sb);
            textArea.setText(sb.toString());

            textArea.setBackground(Color.white);

            if (attributes.getStatus() == GhiHornFixedpointStatus.Satisfiable) {
                if (attributes.isGoal()) {
                    textArea.setBackground(Color.red.brighter());
                } else if (attributes.isStart()) {
                    textArea.setBackground(Color.green.brighter());
                } else {
                    // Not the start or goal in a sat result
                    final HornElement elm = attributes.getHornElement();

                    if (elm != null) {
                        if (elm.isExternal()) {
                            textArea.setBackground(Color.magenta.brighter());
                        } else if (elm.isImported()) {
                            textArea.setBackground(Color.cyan.brighter());
                        } else {
                            textArea.setBackground(Color.white);
                        }
                    }
                }
            } else if (attributes.getStatus() == GhiHornFixedpointStatus.Unsatisfiable) {
                final boolean result =
                        ((GhiHornUnsatAttributes) attributes).getResult();
                if (result) {
                    textArea.setBackground(Color.green.brighter());
                } else {
                    textArea.setBackground(Color.red.brighter());
                }
            }

            textArea.setLineWrap(false);
            textArea.setBorder(BorderFactory.createRaisedBevelBorder());
        }
        mainPanel.addKeyListener(new KeyListener() {

            @Override
            public void keyTyped(KeyEvent e) {
                if (!textArea.isEditable()) {
                    return;
                }

                KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
                kfm.redispatchEvent(textArea, e);
                e.consume(); // consume all events; signal that our text area will handle them
            }

            @Override
            public void keyReleased(KeyEvent e) {

                if (!textArea.isEditable()) {
                    return;
                }

                KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
                kfm.redispatchEvent(textArea, e);
                e.consume(); // consume all events; signal that our text area will handle them
            }

            @Override
            public void keyPressed(KeyEvent e) {

                if (!textArea.isEditable()) {
                    return;
                }

                KeyboardFocusManager kfm = KeyboardFocusManager.getCurrentKeyboardFocusManager();
                kfm.redispatchEvent(textArea, e);
                e.consume(); // consume all events; signal that our text area will handle them
            }
        });

        mainPanel.add(genericHeader, BorderLayout.NORTH);
        mainPanel.add(textArea, BorderLayout.CENTER);
    }

    public void setVertexColor(Color c) {
        textArea.setBackground(c);
    }

    @Override
    public String toString() {
        return textArea.getText();
    }

    /**
     * @return the textArea
     */
    public GhiHornAnswerAttributes getAttributes() {
        return attributes;
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }

    @Override
    public void dispose() {
        genericHeader.dispose();

    }
}
