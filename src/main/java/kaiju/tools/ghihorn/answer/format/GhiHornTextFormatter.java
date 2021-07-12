package kaiju.tools.ghihorn.answer.format;

import java.math.BigInteger;
import java.util.List;
import java.util.Map;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import kaiju.tools.ghihorn.answer.GhiHornAnswerAttributes;
import kaiju.tools.ghihorn.answer.GhiHornSatAttributes;
import kaiju.tools.ghihorn.answer.GhiHornUnsatAttributes;
import kaiju.tools.ghihorn.answer.graph.GhiHornAnswerGraph;
import kaiju.tools.ghihorn.answer.graph.GhiHornAnswerGraphVertex;
import kaiju.tools.ghihorn.hornifer.horn.element.HornElement;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable;
import kaiju.tools.ghihorn.hornifer.horn.variable.HornVariable.Scope;
import kaiju.tools.ghihorn.z3.GhiHornFixedpointStatus;

/**
 * Format answers into something reasonable
 */
public class GhiHornTextFormatter implements GhiHornFormatter<StringBuilder> {
    private GhiHornDisplaySettings settings;

    @SuppressWarnings("unused")
    private GhiHornTextFormatter() {}

    public GhiHornTextFormatter(final GhiHornDisplaySettings s) {
        settings = s;
    }

    //
    // Vertex attributes
    //

    @Override
    public void format(final GhiHornAnswerAttributes attrs, StringBuilder formatter) {

        if (attrs != null && formatter != null) {
            var status = attrs.getStatus();

            if (status == GhiHornFixedpointStatus.Satisfiable) {
                HornElement elm = attrs.getHornElement();

                Address funcAddr = elm.getLocator().getAddress();
                Function elmFunc = elm.getLocator().getProgram().getFunctionManager()
                        .getFunctionContaining(funcAddr);

                GhiHornSatAttributes satAttrs =
                        (GhiHornSatAttributes) attrs;

                final Map<HornVariable, String> varValMap = satAttrs.getValueMap();
                if (varValMap != null) {

                    for (Map.Entry<HornVariable, String> entry : varValMap.entrySet()) {
                        final HornVariable variable = entry.getKey();
                        final String value = entry.getValue();
                        boolean showVariable = true;

                        if (variable.getScope() == Scope.Global) {
                            showVariable = settings.showGlobalVariables();
                        } else {

                            // not a global variable so determine is it should
                            // be shown based on other criteria

                            showVariable = settings.onlyShowDecompilerVariables()
                                    && variable.hasDecompilerHighVariable();

                            // Hide variables not defined in this element
                            if (!settings.showAllStateVariables()) {
                                String varFunc = variable.getVariableName().getFuncId();
                                showVariable = showVariable && elmFunc.getName().equals(varFunc);
                            }
                        }

                        if (showVariable) {
                            
                            String varName = variable.getVariableName().getFullName();
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
                        (GhiHornUnsatAttributes) attrs;
                Boolean result = unsatAttrs.getResult();
                if (result != null) {
                    formatter.append(unsatAttrs.getResult());
                }
            } else if (status == GhiHornFixedpointStatus.Undefined) {
                formatter.append("UNDEFINED");
            }
        }

    }

    //
    // Vertex
    //

    @Override
    public void format(GhiHornAnswerGraphVertex vtx, StringBuilder formatter) {

        if (vtx != null) {
            formatter.append(vtx.getName());

            StringBuilder attrsSb = new StringBuilder();
            GhiHornAnswerAttributes attrs = vtx.getAttributes();
            format(attrs, attrsSb);

            if (attrsSb.length() == 0) {
                formatter.append("()\n");
            } else {
                final GhiHornFixedpointStatus status = attrs.getStatus();
                if (status == GhiHornFixedpointStatus.Unsatisfiable) {
                    formatter.append(" -> ").append(attrsSb.toString().replace("\n", ", "));
                } else if (status == GhiHornFixedpointStatus.Satisfiable) {
                    formatter.append("(").append(attrsSb.toString().replace("\n", ", "))
                            .append(")");
                }
            }
        }
    }

    //
    // Graph
    //

    @Override
    public void format(GhiHornAnswerGraph graph, StringBuilder formatter) {
        List<GhiHornAnswerGraphVertex> vertices = graph.getVerticesInPreOrder();

        for (int i = 0; i < vertices.size(); i++) {

            final GhiHornAnswerGraphVertex vtx = vertices.get(i);

            StringBuilder vtxSb = new StringBuilder();
            format(vtx, vtxSb);

            formatter.append("[").append(i).append("] ").append(vtxSb.toString()).append("\n\n");
        }
    }
}
