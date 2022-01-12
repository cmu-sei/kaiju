package kaiju.tools.ghihorn.answer.format;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import com.google.gson.FieldNamingPolicy;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
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


public class GhiHornAnswerJsonFormatter implements GhiHornOutputFormatter {

    private GhiHornDisplaySettings settings;
    private Gson gson;

    @SuppressWarnings("unused")
    private GhiHornAnswerJsonFormatter() {
        this.settings = null;
        this.gson = null;
    }

    public GhiHornAnswerJsonFormatter(final GhiHornDisplaySettings s) {
        settings = s;
        this.gson = new GsonBuilder()
                .disableHtmlEscaping()
                .setFieldNamingPolicy(FieldNamingPolicy.UPPER_CAMEL_CASE)
                .setPrettyPrinting()
                .serializeNulls()
                .create();
    }

    @Override
    public String format(GhiHornAnswerGraph graph) {

        List<GhiHornAnswerGraphVertex> vertices = graph.getVerticesInPreOrder();
        List<JsonObject> pathJson = new ArrayList<>();

        String curApiName = "";
        for (GhiHornAnswerGraphVertex vtx : vertices) {

            final HornElement elm = vtx.getAttributes().getHornElement();

            // Collapse API functions
            JsonObject vtxJson =
                    JsonParser.parseString(format(vtx)).getAsJsonObject();

            if (elm.isExternal() || elm.isImported()) {
               
                if (elm.getName().contains("_pre")) {
                    // 1st element of API, always add it
                    curApiName = vtx.getAttributes().getName();
                    vtxJson.addProperty("API", curApiName);
                    pathJson.add(vtxJson);
                } else {
                    // Not the 1st element, either middle or end. If the name is set record it
                    if (!curApiName.isEmpty()) {
                        vtxJson.addProperty("API", curApiName);
                    }
                    if (elm.getName().contains("_post")) {
                        curApiName = "";
                    }
                    if (!settings.hideExternalFunctions()) {
                        pathJson.add(vtxJson);
                    }
                }
            } else {
                // Not an external vertex
                pathJson.add(vtxJson);
            }
        }

        JsonArray ansJson = new JsonArray();
        for (int i = 0; i < pathJson.size(); i++) {
            JsonObject ithVtxJson = pathJson.get(i);
            ithVtxJson.addProperty("Index", i);
            ansJson.add(ithVtxJson);
        }

        return gson.toJson(ansJson);
    }

    @Override
    public String format(GhiHornAnswerGraphVertex vertex) {

        final GhiHornAnswerAttributes attributes = vertex.getAttributes();

        JsonObject attrJson = JsonParser.parseString(attributes.format(this)).getAsJsonObject();
        attrJson.addProperty("Address", attributes.getAddress().toString());

        // this is undefined
        return gson.toJson(attrJson);

    }

    @Override
    public String format(GhiHornAnswerAttributes attributes) {

        JsonObject attrJson = new JsonObject();

        if (attributes.getStatus() == GhiHornFixedpointStatus.Satisfiable) {
            JsonArray varArray = new JsonArray();
            GhiHornSatAttributes satAttrs = (GhiHornSatAttributes) attributes;
            final Map<HornVariable, String> varValMap = satAttrs.getValueMap();

            if (varValMap != null) {
                for (Map.Entry<HornVariable, String> entry : varValMap.entrySet()) {
                    final HornVariable variable = entry.getKey();
                    final String value = entry.getValue();

                    boolean showVariable = true;
                    if (!settings.showAllState()) {
                        if (settings.hideTempVariables() && !variable.hasHighVariable()) {
                            showVariable = false;

                        }
                        // Still showing, so not a temp
                        if (showVariable) {
                            if (variable.getScope() == Scope.Global) {
                                showVariable = settings.showGlobalVariables();
                            } else if (variable.getScope() == Scope.Local) {
                                showVariable = settings.showLocalVariables();
                            }
                        }
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
                        JsonObject varEntry = new JsonObject();
                        varEntry.addProperty(varName, formatVal);
                        varArray.add(varEntry);
                    }
                }
                if (varArray.size() > 0) {
                    attrJson.add("Variables", varArray);
                }
            }
        } else {
            if (attributes.getStatus() == GhiHornFixedpointStatus.Unsatisfiable) {
                GhiHornUnsatAttributes unsatAttrs =
                        (GhiHornUnsatAttributes) attributes;
                attrJson.addProperty("Result", unsatAttrs.getConditionAsString());

            } else {
                attrJson.addProperty("Result", "Undefined");
            }
        }
        return gson.toJson(attrJson);
    }

    @Override
    public String format(GhiHornAnswer answer) {

        // The answer has a set of arguments and a path
        JsonObject ansJson =
                JsonParser.parseString(answer.arguments.format(this)).getAsJsonObject();
        JsonArray pathJson =
                JsonParser.parseString(format(answer.answerGraph)).getAsJsonArray();
        ansJson.add("Path", pathJson);
        return gson.toJson(ansJson);
    }

    @Override
    public String format(ApiAnalyzerArgument argument) {
        JsonObject argJson = new JsonObject();
        argJson.addProperty("Signature", argument.getSignature().getName());
        argJson.addProperty("Entry", argument.getEntryAsAddress().toString());
        argJson.addProperty("Start", argument.getStartAsAddress().toString());
        argJson.addProperty("Goal", argument.getGoalAsAddress().toString());

        return gson.toJson(argJson);
    }

    @Override
    public String format(PathAnalyzerArgument argument) {

        final JsonObject argJson = new JsonObject();
        argJson.addProperty("Start", argument.getEntryAsAddress().toString());
        argJson.addProperty("Goal", argument.getGoalAsAddress().toString());

        return argJson.toString();
    }

    @Override
    public String format(Set<GhiHornAnswer> solution) {

        final JsonArray solutionJsonArray = new JsonArray();
        solution.forEach(answer -> solutionJsonArray
                .add(JsonParser.parseString(format(answer)).getAsJsonObject()));

        final JsonObject slnJson = new JsonObject();
        slnJson.add("Matches", solutionJsonArray);

        return gson.toJson(slnJson);
    }
}
