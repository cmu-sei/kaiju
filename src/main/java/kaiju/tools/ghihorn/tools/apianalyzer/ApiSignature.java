package kaiju.tools.ghihorn.tools.apianalyzer;

import java.util.ArrayList;
import java.util.List;

public class ApiSignature {
    public static final String ALL_SIGS = "All";
    private final String name;
    private final String description;
    private final List<ApiFunction> sequence;

    /**
     * Create an empty signature
     */
    public ApiSignature() {
        this.name = "";
        this.description = "";
        this.sequence = new ArrayList<>();
    }

    /**
     * @param name
     * @param description
     * @param sequence
     */
    public ApiSignature(String name, String description, List<ApiFunction> sequence) {
        this.name = name;
        this.description = description;
        this.sequence = sequence;
    }

    public static ApiSignature allSignatures() {
        return new ApiSignature(ALL_SIGS, "Search for all signatures", null);
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
    public List<ApiFunction> getSequence() {
        return sequence;
    }

    @Override
    public String toString() {
        return new StringBuilder(name).append(": ").append(description).toString();
    }

}
