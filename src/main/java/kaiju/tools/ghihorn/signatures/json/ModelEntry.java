package kaiju.tools.ghihorn.signatures.json;

import java.util.List;
import java.util.Optional;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class ModelEntry {

    @Expose
    @SerializedName("API")
    private String apiName;

    @Expose
    @SerializedName("Id")
    private int id;   

    @Expose
    @SerializedName("Parameters")
    private List<String> apiParameters;

    @Expose
    @SerializedName("Retn")
    private String apiRetnValue;

    @Expose
    @SerializedName("Preconditions")
    private List<String> preconditions;

    @Expose
    @SerializedName("Postconditions")
    private List<String> postconditions;

    public ModelEntry(final String a, final int i, final List<String> params, final String retn,
            final List<String> pre, final List<String> post) {

        this.apiName = a;
        this.id = i;
        this.apiParameters = params;
        this.apiRetnValue = retn;
        this.preconditions = pre;
        this.postconditions = post;
    }

    public String getAPI() {
        return this.apiName;
    }

    public int getId() {
        return this.id;
    }

    public List<String> getPreconditions() {
        return this.preconditions;
    }

    public List<String> getPostconditions() {
        return this.postconditions;
    }

    public Optional<List<String>> getParameters() {
        return Optional.ofNullable(this.apiParameters);
    }

    public Optional<String> getRetn() {
        return Optional.ofNullable(this.apiRetnValue);
    }

    @Override
    public String toString() {
        final StringBuilder b = new StringBuilder("API: " + apiName + ", Parameters: ");
        if (this.apiParameters != null && !this.apiParameters.isEmpty()) {
            this.apiParameters.forEach(b::append);
        } else {
            b.append("None");
        }
        if (this.apiRetnValue != null) {
            b.append(", Retn: " + this.apiRetnValue);
        } else {
            b.append(", Retn: None");
        }

        if (preconditions != null) {
            b.append(", Preconditions");
            preconditions.forEach(b::append);
        }

        if (postconditions != null) {
            b.append(", Postconditions");
            postconditions.forEach(b::append);
        }

        return b.toString();

    }
}
