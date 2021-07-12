package kaiju.tools.ghihorn.tools.apianalyzer;

import java.util.List;

public class ApiSignature {
    private final String name;
    private final String description;
    private final List<String> sequence;

    /**
     * @param name
     * @param description
     * @param sequence
     */
    public ApiSignature(String name, String description, List<String> sequence) {
        this.name = name;
        this.description = description;
        this.sequence = sequence;
    }

    /**
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * @return the description
     */
    public String getDescription() {
        return description;
    }

    /**
     * @return the sequence
     */
    public List<String> getSequence() {
        return sequence;
    }

    @Override
    public String toString() {
        return new StringBuilder(name).append(": ").append(description).toString();
    }

}
