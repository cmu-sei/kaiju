package kaiju.tools.ghihorn.answer.format;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import kaiju.tools.ghihorn.answer.GhiHornAnswerAttributes;
import kaiju.tools.ghihorn.answer.GhiHornSatAttributes;
import kaiju.tools.ghihorn.answer.GhiHornUnsatAttributes;
import kaiju.tools.ghihorn.answer.graph.GhiHornAnswerGraph;
import kaiju.tools.ghihorn.answer.graph.GhiHornAnswerGraphVertex;
import kaiju.tools.ghihorn.hornifer.horn.GhiHornAnswer;
import kaiju.tools.ghihorn.hornifer.horn.element.HornElement;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable.Scope;
import kaiju.tools.ghihorn.tools.apianalyzer.ApiAnalyzerArgument;
import kaiju.tools.ghihorn.tools.pathanalyzer.PathAnalyzerArgument;
import kaiju.tools.ghihorn.z3.GhiHornFixedpointStatus;

/**
 * Format answers into something reasonable
 */
public class GhiHornAnswerTextFormatter implements GhiHornOutputFormatter {
    private GhiHornDisplaySettings settings;

    @SuppressWarnings("unused")
    private GhiHornAnswerTextFormatter() {}

    public GhiHornAnswerTextFormatter(final GhiHornDisplaySettings s) {
        settings = s;
    }

    //
    // Vertex attributes
    //

    @Override
    public String format(final GhiHornAnswerAttributes attributes) {

        StringBuilder formatter = new StringBuilder();
        if (attributes != null) {
            var status = attributes.getStatus();

            if (status == GhiHornFixedpointStatus.Satisfiable) {
                GhiHornSatAttributes satAttrs =
                        (GhiHornSatAttributes) attributes;

                final Map<HornVariable, String> varValMap = satAttrs.getValueMap();
                if (varValMap != null) {

                    for (Map.Entry<HornVariable, String> entry : varValMap.entrySet()) {
                        final HornVariable variable = entry.getKey();
                        final String value = entry.getValue();

                        boolean showVariable = true;

                        if (variable.getScope() == Scope.Global) {
                            showVariable = settings.showGlobalVariables();
                        } else {

                            // Only show variables defined in the current vertice's function. This
                            // makes the state make much more sense
                            HornElement elm = attributes.getHornElement();
                            String varFunc = variable.getVariableName().getFuncId();
                            Address funcAddr = elm.getLocator().getAddress();
                            Function elmFunc = elm.getLocator()
                                    .getProgram()
                                    .getFunctionManager()
                                    .getFunctionContaining(funcAddr);

                            showVariable = settings.showLocalVariables()
                                    && elmFunc.getName().equals(varFunc);
                        }

                        if (settings.hideTempVariables() && !variable.hasHighVariable()) {
                            showVariable = false;
                        }

                        if (showVariable) {

                            // If you show all the state
                            String varName = (settings.showAllState())
                                    ? variable.getVariableName().getFullName()
                                    : variable.getVariableName().getName();

                            String formatVal = value;
                            try {
                                BigInteger bigNum = new BigInteger(value);
                                formatVal = String.format("0x%02x", bigNum);
                            } catch (NumberFormatException e) {
                                formatVal = value;
                            }

                            formatter.append(varName).append(" = ")
                                    .append(formatVal)
                                    .append("\n");
                        }
                    }

                    if (formatter.length() > 0) {
                        formatter.deleteCharAt(formatter.length() - 1);
                    }
                }
            } else if (status == GhiHornFixedpointStatus.Unsatisfiable) {
                GhiHornUnsatAttributes unsatAttrs =
                        (GhiHornUnsatAttributes) attributes;
                String result = unsatAttrs.getConditionAsString();
                if (result != null) {
                    formatter.append(unsatAttrs.getConditionAsString());
                }
            } else if (status == GhiHornFixedpointStatus.Undefined) {
                formatter.append("UNDEFINED");
            }
        }
        return formatter.toString();

    }

    //
    // Vertex
    //

    @Override
    public String format(GhiHornAnswerGraphVertex vertex) {

        StringBuilder formatter = new StringBuilder();
        if (vertex != null) {

            GhiHornAnswerAttributes attributes = vertex.getAttributes();
            final HornElement elm = attributes.getHornElement();

            boolean printVtx = false;
            if (elm.isExternal() || elm.isImported()) {
                if (attributes.isPrecondition()) {
                    // Always print the 1st vertex in an API
                    printVtx = true;
                } else if (!settings.hideExternalFunctions() && !attributes.isPostcondition()) {
                    // Print external functions if configured. Never print post conditions
                    printVtx = true;
                }
            } else {
                // not external vertex, print if a precondition
                if (!attributes.isPostcondition()) {
                    printVtx = true;
                }
            }
            if (!printVtx) {
                return "";
            }

            if (settings.showAllState()) {
                formatter.append(attributes.getVertexName());
            } else {
                formatter.append(attributes.getName());
            }

            String attrsStr = format(attributes);

            if (attrsStr.length() == 0) {
                formatter.append("()");
            } else {
                final GhiHornFixedpointStatus status = attributes.getStatus();
                if (status == GhiHornFixedpointStatus.Unsatisfiable) {
                    formatter.append(" -> ").append(attrsStr.replace("\n", ", "));
                } else if (status == GhiHornFixedpointStatus.Satisfiable) {
                    formatter.append("(")
                            .append(attrsStr.toString().replace("\n", ", "))
                            .append(")");
                }
            }
        }
        return formatter.toString();
    }

    //
    // Graph
    //

    @Override
    public String format(GhiHornAnswerGraph graph) {

        List<GhiHornAnswerGraphVertex> vertices = graph.getVerticesInPreOrder();
        StringBuilder formatter = new StringBuilder();

        List<String> pathList = new ArrayList<>();
        List<Integer> depthList = new ArrayList<>();
        int curDepth = 0;


        for (int pos = 0; pos < vertices.size(); pos++) { 
            GhiHornAnswerGraphVertex vtx = vertices.get(pos);

            GhiHornAnswerAttributes attrs = vtx.getAttributes();

            if (attrs.isPrecondition() && pos > 0) {
                curDepth += 3;
            } else if (attrs.isPostcondition() && curDepth > 0) {
                curDepth -= 3;
            }
            String vtxString = format(vtx);
            if (!vtxString.isBlank()) {
                depthList.add(curDepth);
                pathList.add(vtxString);
            }
        }

        for (int i = 0; i < pathList.size(); i++) {
            String ith = "[" + i + "]";

            StringBuilder ithElm = new StringBuilder();
            int depth = depthList.get(i);
            for (int j = 0; j < depth; j++) {
                ithElm.append(".");
            }
            ithElm.append(pathList.get(i));
            formatter.append(String.format("%-5s %-15s\n", ith, ithElm.toString()));
        }
        return formatter.toString();
    }

    @Override
    public String format(GhiHornAnswer answer) {

        StringBuilder fommatter = new StringBuilder();
        return fommatter.append(answer.toString())
                .append("\n---\n")
                .append("Path:\n")
                .append(format(answer.answerGraph))
                .append("===")
                .toString();
    }

    @Override
    public String format(ApiAnalyzerArgument argument) {
        return argument.toString();
    }

    @Override
    public String format(PathAnalyzerArgument argument) {
        return argument.toString();
    }

    @Override
    public String format(Set<GhiHornAnswer> solution) {

        StringBuilder formatter = new StringBuilder();
        solution.forEach(answer -> formatter.append(format(answer)).append("\n"));

        return formatter.toString();
    }
}
