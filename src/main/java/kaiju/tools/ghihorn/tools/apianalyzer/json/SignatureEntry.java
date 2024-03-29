package kaiju.tools.ghihorn.tools.apianalyzer.json;

import java.util.List;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class SignatureEntry {

    @Expose
    @SerializedName("Name")
    private String name;

    @Expose
    @SerializedName("Description")
    private String description;

    @Expose
    @SerializedName("Sequence")
    private List<SignatureApiFunction> sequence;

    public SignatureEntry(final String n, final String d, final List<SignatureApiFunction> s) {

        this.name = n;
        this.description = d;
        this.sequence = s;
    }

    public String getName() {
        return this.name;
    }

    public String getDescription() {
        return this.description;
    }

    public List<SignatureApiFunction> getSequence() {
        return this.sequence;
    }

    @Override
    public String toString() {

        final StringBuilder sb = new StringBuilder("Sig: ")
                .append(name)
                .append(", Description: ")
                .append(description)
                .append(", Sequence: ");

        this.sequence.forEach(s -> sb.append(s.toString()).append(", "));

        return sb.toString();
    }
}
