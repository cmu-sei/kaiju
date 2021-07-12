package kaiju.tools.ghihorn.answer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Expr;
import com.microsoft.z3.Quantifier;
import com.microsoft.z3.Sort;
import org.python.google.common.base.Verify;
import ghidra.graph.DefaultGEdge;
import ghidra.graph.GDirectedGraph;
import kaiju.tools.ghihorn.answer.graph.GhiHornAnswerGraph;
import kaiju.tools.ghihorn.answer.graph.GhiHornAnswerGraphEdge;
import kaiju.tools.ghihorn.answer.graph.GhiHornAnswerGraphVertex;
import kaiju.tools.ghihorn.hornifer.horn.GhiHornFixedPoint;
import kaiju.tools.ghihorn.hornifer.horn.HornProgram;
import kaiju.tools.ghihorn.hornifer.horn.element.HornElement;
import kaiju.tools.ghihorn.hornifer.horn.element.HornPredicate;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable;
import kaiju.tools.ghihorn.z3.GhiHornFixedpointStatus;

/**
 * Build the GHiHorn answer graph
 */
public class GhiHornAnswerGraphBuilder {
    private GhiHornAnswerGraph answerGraph;
    private Map<String, HornElement> hornElements = new HashMap<>();
    private HornProgram hornProgram;

    /**
     * 
     * @param status
     * @param hfp
     * @param answer
     */
    public GhiHornAnswerGraphBuilder(final HornProgram hp, final GhiHornFixedpointStatus status,
            GhiHornFixedPoint hfp,
            final Expr<? extends Sort> answer) {

        this.hornProgram = hp;

        hfp.getRules().forEach(c -> {

            HornElement body = c.getBody();
            String bodyName = (body instanceof HornPredicate) ? ((HornPredicate) body).getFullName()
                    : body.getName();
            hornElements.put(bodyName, body);

            HornElement head = c.getHead();
            String headName = (head instanceof HornPredicate) ? ((HornPredicate) head).getFullName()
                    : head.getName();
            hornElements.put(headName, head);
        });

        try {
            if (status == GhiHornFixedpointStatus.Satisfiable) {
                buildSatProof(answer);
            } else if (status == GhiHornFixedpointStatus.Unsatisfiable) {
                buildUnsatProofGraph(answer);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        List<GhiHornAnswerGraphVertex> vertices = answerGraph.getVerticesInPreOrder();

        GhiHornAnswerGraphVertex sink = vertices.get(vertices.size() - 1);
        GhiHornAnswerGraphVertex nextToSink = vertices.get(vertices.size() - 2);
        GhiHornAnswerGraphVertex source = vertices.get(0);

        // This is Z3/Spacer cruft that has no bearing on the
        if (sink.getName().contains("query!")) {
            this.answerGraph.removeVertex(sink);
        }

        if (nextToSink.getName().equals("goal")) {
            nextToSink.makeGoal();
        }
        source.makeStart();
    }

    /**
     * Fetch the graph
     * 
     * @return
     */
    public GhiHornAnswerGraph getGraph() {
        return this.answerGraph;
    }

    /**
     * Get the children for this expression
     * 
     * @param expr
     * @return
     */
    private Expr<?>[] children(Expr<? extends Sort> expr) {
        if (!expr.isApp()) {
            return new Expr[0];
        }
        return expr.getArgs();
    }

    /**
     * Get the fact for the answer expression
     * 
     * @param expr
     * @return the fact
     */
    private Expr<? extends Sort> getFact(final Expr<? extends Sort> expr) {
        Expr<? extends Sort>[] kids = children(expr);
        if (kids != null && kids.length > 0) {
            return kids[kids.length - 1];
        }
        return null;
    }

    /**
     * An unsat proof is a conjunciton of states
     * 
     * @return
     * @throws Exception
     */
    private void buildUnsatProofGraph(final Expr<? extends Sort> answer) throws Exception {

        Verify.verify(answer.isAnd(), "Assumption about UNSAT format proven incorrect");

        Expr<? extends Sort>[] children = children(answer);

        answerGraph =
                new GhiHornAnswerGraph(this.hornProgram, GhiHornFixedpointStatus.Unsatisfiable);

        if (children.length > 0) {

            Map<HornElement, GhiHornAnswerGraphVertex> unsatVertices = new HashMap<>();
            for (int i = 0; i < children.length; i++) {
                GhiHornAnswerGraphVertex vtx =
                        new GhiHornAnswerGraphVertex(makeUnsatVertexAttributes(children[i]));
                unsatVertices.put(vtx.getAttributes().hornElement, vtx);
            }

            GDirectedGraph<HornElement, DefaultGEdge<HornElement>> clauseGraph =
                    hornProgram.buildClauseGraph();

            for (DefaultGEdge<HornElement> clauseEdge : clauseGraph.getEdges()) {

                GhiHornAnswerGraphVertex src = unsatVertices.get(clauseEdge.getStart());
                GhiHornAnswerGraphVertex tgt = unsatVertices.get(clauseEdge.getEnd());
                if (src != null && tgt != null) {
                    if (!answerGraph.containsVertex(src)) {
                        answerGraph.addVertex(src);
                    }
                    if (!answerGraph.containsVertex(tgt)) {
                        answerGraph.addVertex(tgt);
                    }
                    GhiHornAnswerGraphEdge ansEdge = new GhiHornAnswerGraphEdge(src, tgt);
                    if (!answerGraph.containsEdge(ansEdge)) {
                        answerGraph.addEdge(ansEdge);
                    }
                }
            }
        }
    }

    /**
     * 
     * @param expr
     * @param g
     * @param visited
     */
    private void generateSatGraph(final Expr<? extends Sort> expr, GhiHornAnswerGraph g,
            final Map<Expr<? extends Sort>, GhiHornAnswerGraphVertex> exprToVtxMap) {

        if (exprToVtxMap.containsKey(expr)) {
            return;
        }

        final GhiHornAnswerGraphVertex exprVtx =
                new GhiHornAnswerGraphVertex(makeSatVertexAttributes(expr));
        exprToVtxMap.put(expr, exprVtx);

        final Expr<? extends Sort> dst = getFact(expr);
        Expr<? extends Sort>[] kids = children(expr);
        for (int i = 1; i < kids.length - 1; i++) {

            Expr<? extends Sort> kFact = getFact(kids[i]);
            if (!exprToVtxMap.containsKey(kFact)) {

                final GhiHornAnswerGraphVertex vtx =
                        new GhiHornAnswerGraphVertex(makeSatVertexAttributes(kFact));
                g.addVertex(vtx);

                exprToVtxMap.put(kFact, vtx);

                generateSatGraph(kids[i], g, exprToVtxMap);
            }

            GhiHornAnswerGraphVertex srcVtx = null;
            if (exprToVtxMap.containsKey(kFact)) {
                srcVtx = exprToVtxMap.get(kFact);
            } else {
                srcVtx = new GhiHornAnswerGraphVertex(makeSatVertexAttributes(kFact));
            }

            GhiHornAnswerGraphVertex tgtVtx = null;
            if (exprToVtxMap.containsKey(dst)) {
                tgtVtx = exprToVtxMap.get(dst);
            } else {
                tgtVtx = new GhiHornAnswerGraphVertex(makeSatVertexAttributes(dst));
            }

            g.addEdge(new GhiHornAnswerGraphEdge(srcVtx, tgtVtx));
        }
    }

    /**
     * Build the proof graph if satisfiable
     * 
     * @return
     */
    private void buildSatProof(Expr<? extends Sort> answer) throws Exception {

        this.answerGraph =
                new GhiHornAnswerGraph(this.hornProgram, GhiHornFixedpointStatus.Satisfiable);
        Map<Expr<? extends Sort>, GhiHornAnswerGraphVertex> exprToVtxMap = new HashMap<>();

        answer = children(answer)[0];
        Expr<? extends Sort> fact = getFact(answer);
        final GhiHornAnswerGraphVertex vtx =
                new GhiHornAnswerGraphVertex(makeSatVertexAttributes(fact));

        answerGraph.addVertex(vtx);

        exprToVtxMap.put(fact, vtx);

        generateSatGraph(answer, answerGraph, exprToVtxMap);

    }

    /**
     * 
     * @param expr
     * @return
     */
    private GhiHornUnsatAttributes makeUnsatVertexAttributes(
            final Expr<? extends Sort> expr) {

        String vtxName = "";
        Boolean vtxResult = false;
        if (expr.isQuantifier()) {
            Quantifier q = (Quantifier) expr;
            BoolExpr qBody = q.getBody();
            if (qBody.getNumArgs() == 2) {
                Expr<?>[] vars = qBody.getArgs();
                vtxName = vars[0].getFuncDecl().getName().toString();
                vtxResult = Boolean.valueOf(vars[1].toString());
            }
        } else if (expr.isEq()) {
            if (expr.getNumArgs() == 2) {
                Expr<?>[] args = expr.getArgs();
                vtxName = args[0].getFuncDecl().getName().toString();
                vtxResult = Boolean.valueOf(args[1].toString());
            }
        }

        final HornElement elm = hornElements.get(vtxName);
        return new GhiHornUnsatAttributes(vtxName, elm, vtxResult);
    }

    /**
     * 
     * @param arrayExpr
     * @return
     */
    private String formatArrayExpr(Expr<?> arrayExpr) {
        // Sort s = arrayExpr.getSort();
        // return s.toString();
        return "N/A";
    }

    /**
     * Create satifiable vertex attributes.
     * 
     * @param expr
     * @return
     */
    private GhiHornSatAttributes makeSatVertexAttributes(
            final Expr<? extends Sort> expr) {

        final String vtxName = expr.getFuncDecl().getName().toString();

        Map<HornVariable, String> varVals = new HashMap<>();
        if (hornElements.containsKey(vtxName) && !vtxName.isEmpty()) {

            HornElement hornElm = hornElements.get(vtxName);
            List<HornVariable> elmVars = new ArrayList<>(hornElm.getVariables());
            Expr<?>[] vals = expr.getArgs();

            for (int i = 0; i < elmVars.size(); i++) {
                if (vals[i].isArray() || vals[i].isSelect()) {
                    varVals.put(elmVars.get(i), formatArrayExpr(vals[i]));
                } else {
                    varVals.put(elmVars.get(i), vals[i].toString());
                }
            }
        }

        final HornElement elm = hornElements.get(vtxName);
        return new GhiHornSatAttributes(vtxName, elm, varVals);
    }
}
