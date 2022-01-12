package kaiju.tools.ghihorn.answer.format;

import java.util.Set;
import kaiju.tools.ghihorn.answer.GhiHornAnswerAttributes;
import kaiju.tools.ghihorn.answer.format.GhiHornDisplaySettings.OutputFormat;
import kaiju.tools.ghihorn.answer.graph.GhiHornAnswerGraph;
import kaiju.tools.ghihorn.answer.graph.GhiHornAnswerGraphVertex;
import kaiju.tools.ghihorn.hornifer.horn.GhiHornAnswer;
import kaiju.tools.ghihorn.tools.apianalyzer.ApiAnalyzerArgument;
import kaiju.tools.ghihorn.tools.pathanalyzer.PathAnalyzerArgument;

public interface GhiHornOutputFormatter {

    public String format(final Set<GhiHornAnswer> solution);
    
    public String format(final GhiHornAnswer answer);

    public String format(final GhiHornAnswerGraph graph);

    public String format(final GhiHornAnswerGraphVertex vertex);
    
    public String format(final GhiHornAnswerAttributes attributes);
    
    public String format(final ApiAnalyzerArgument argument);
    
    public String format(final PathAnalyzerArgument argument);

    public static GhiHornOutputFormatter create(final GhiHornDisplaySettings settings) {
         return (settings.getOutputFormat() == OutputFormat.JSON)
                ? new GhiHornAnswerJsonFormatter(settings)
                : new GhiHornAnswerTextFormatter(settings);
    }

}
