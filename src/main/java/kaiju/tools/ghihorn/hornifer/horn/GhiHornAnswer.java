package kaiju.tools.ghihorn.hornifer.horn;

import kaiju.tools.ghihorn.answer.graph.GhiHornAnswerGraph;
import kaiju.tools.ghihorn.z3.GhiHornFixedpointStatus;

/**
 * Convenience class for ApiAnalyzer results
 */
public class GhiHornAnswer {

    public GhiHornArgument<?> arguments;
    public String errorMessage;
    public String fxString;
    public GhiHornAnswerGraph answerGraph;
    public GhiHornFixedpointStatus status;

    /**
     * Create a new answer
     */
    public GhiHornAnswer() {
        status = GhiHornFixedpointStatus.Unknown;
        errorMessage = "";
        fxString = "";
        answerGraph = null;
        arguments = null;
    }

    @Override
    public String toString() {
        return new StringBuilder(arguments.toString()).append(": ").append(status).toString();
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((arguments == null) ? 0 : arguments.hashCode());
        result = prime * result + ((errorMessage == null) ? 0 : errorMessage.hashCode());
        result = prime * result + ((fxString == null) ? 0 : fxString.hashCode());
        result = prime * result + ((answerGraph == null) ? 0 : answerGraph.hashCode());
        result = prime * result + ((status == null) ? 0 : status.hashCode());
        return result;
    }

    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#equals(java.lang.Object)
     */

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        GhiHornAnswer other = (GhiHornAnswer) obj;
        if (arguments == null) {
            if (other.arguments != null)
                return false;
        } else if (!arguments.equals(other.arguments))
            return false;
        if (errorMessage == null) {
            if (other.errorMessage != null)
                return false;
        } else if (!errorMessage.equals(other.errorMessage))
            return false;
        if (fxString == null) {
            if (other.fxString != null)
                return false;
        } else if (!fxString.equals(other.fxString))
            return false;
        if (answerGraph == null) {
            if (other.answerGraph != null)
                return false;
        } else if (!answerGraph.equals(other.answerGraph))
            return false;
        if (status != other.status)
            return false;
        return true;
    }
}

