package kaiju.tools.ghihorn.display.graph;

import java.awt.BorderLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.JPanel;
import javax.swing.border.BevelBorder;
import ghidra.graph.viewer.PathHighlightMode;
import ghidra.graph.viewer.VisualGraphView;
import ghidra.graph.viewer.layout.LayoutProvider;
import ghidra.graph.viewer.layout.VisualGraphLayout;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import kaiju.tools.ghihorn.GhiHornPlugin;
import kaiju.tools.ghihorn.answer.GhiHornAnswerAttributes;
import kaiju.tools.ghihorn.answer.format.GhiHornDisplaySettings;
import kaiju.tools.ghihorn.answer.graph.GhiHornAnswerGraph;
import kaiju.tools.ghihorn.answer.graph.display.GhiHornAnswerGraphVisualEdge;
import kaiju.tools.ghihorn.answer.graph.display.GhiHornAnswerGraphVisualVertex;
import kaiju.tools.ghihorn.answer.graph.display.GhiHornVisualAnswerGraph;
import kaiju.tools.ghihorn.hornifer.horn.element.HornElement;

public class GhiHornAnswerGraphComponent {
    private final GhiHornPlugin plugin;
    private final GhiHornAnswerGraph graph;
    private JPanel graphPanel;

    public GhiHornAnswerGraphComponent(final GhiHornPlugin p, GhiHornAnswerGraph g) {
        this.plugin = p;
        this.graph = g;
    }

    public void build(final GhiHornDisplaySettings settings) {

        GhiHornVisualAnswerGraph vizGraph = graph.toVisualGraph(settings);
        if (vizGraph != null) {

            // filter out extraneous vertices import bodies
            List<GhiHornAnswerGraphVisualVertex> filterVtxList = new ArrayList<>();
            Iterator<GhiHornAnswerGraphVisualVertex> vi = vizGraph.getAllVertices();
            while (vi.hasNext()) {
                GhiHornAnswerGraphVisualVertex vtx = vi.next();
                GhiHornAnswerAttributes attributes = vtx.getAttributes();
                HornElement elm = vtx.getAttributes().getHornElement();

                if (elm.isExternal() || elm.isImported()) {
                    if (!attributes.isPrecondition()) {
                        if (settings.hideExternalFunctions()) {
                            filterVtxList.add(vtx);
                        }
                    }
                } else {
                    // not external vertex, print if a precondition
                    if (attributes.isPostcondition()) {
                        filterVtxList.add(vtx);
                    }
                }
            }
            if (!filterVtxList.isEmpty()) {
                for (GhiHornAnswerGraphVisualVertex vtx : filterVtxList) {
                    if (vizGraph.getPredecessorCount(vtx) > 0
                            && vizGraph.getSuccessorCount(vtx) > 0) {
                        GhiHornAnswerGraphVisualVertex prev =
                                vizGraph.getPredecessors(vtx).iterator().next();
                        GhiHornAnswerGraphVisualVertex next =
                                vizGraph.getSuccessors(vtx).iterator().next();
                        while (next.getAttributes().getHornElement().isImported()) {
                            next = vizGraph.getSuccessors(next).iterator().next();
                        }

                        vizGraph.addEdge(new GhiHornAnswerGraphVisualEdge(prev, next));
                    }
                }

                vizGraph.filterVertices(filterVtxList);
            }

            // We are displaying these results in Ghidra

            VisualGraphView<GhiHornAnswerGraphVisualVertex, GhiHornAnswerGraphVisualEdge, GhiHornVisualAnswerGraph> view =
                    new VisualGraphView<>();

            // these default to off; they are typically controlled via a UI element; the
            // values set here are arbitrary and are for demo purposes
            view.setVertexFocusPathHighlightMode(PathHighlightMode.OUT);
            view.setVertexHoverPathHighlightMode(PathHighlightMode.IN);

            LayoutProvider<GhiHornAnswerGraphVisualVertex, GhiHornAnswerGraphVisualEdge, GhiHornVisualAnswerGraph> layoutProvider =
                    new GhiHornAnswerGraphLayoutProvider();
            view.setLayoutProvider(layoutProvider);

            final TaskMonitor mon = this.plugin.getTaskMonitor();
            try {
                VisualGraphLayout<GhiHornAnswerGraphVisualVertex, GhiHornAnswerGraphVisualEdge> layout =
                        layoutProvider
                                .getLayout(vizGraph, mon);

                vizGraph.setLayout(layout);
            } catch (CancelledException e) {
                mon.setMessage("Cancelled graph layout genaration");
            }

            view.setGraph(vizGraph);
            view.getPrimaryGraphViewer().addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent event) {
                    GhiHornAnswerGraphVisualVertex vtx = view.getFocusedVertex();
                    if (vtx != null) {
                        HornElement hornElm = vtx.getAttributes().getHornElement();
                        ProgramLocation loc = hornElm.getLocator();
                        plugin.goTo(loc.getAddress());

                        try {
                            final SimpleBlockModel basicBlockModel =
                                    new SimpleBlockModel(loc.getProgram());
                            CodeBlock focBlk =
                                    basicBlockModel.getFirstCodeBlockContaining(loc.getAddress(),
                                            TaskMonitor.DUMMY);
                            if (focBlk != null) {

                                plugin.getProvider().setSelection(
                                        new ProgramSelection(focBlk.getMinAddress(),
                                                focBlk.getMaxAddress()));
                            }
                        } catch (CancelledException e) {
                            /* Should not happen */ }
                    }
                }
            });

            graphPanel = new JPanel(new BorderLayout());
            graphPanel.setBorder(BorderFactory.createBevelBorder(BevelBorder.RAISED));
            graphPanel.add(view.getViewComponent(), BorderLayout.CENTER);
        }

    }

    /**
     * Fetch the component tha holds the graph
     * 
     * @return
     */
    public JPanel getComponent() {
        return this.graphPanel;
    }
}
