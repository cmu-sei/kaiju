package kaiju.tools.ghihorn.signatures.json;

import java.util.List;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

/**
 * Skeleton class to hold a model read from JSON
 */
public class ModelType {

    @Expose
    @SerializedName("Name")
    private String name;

    @Expose
    @SerializedName("Description")
    private String description;

    @Expose
    @SerializedName("Model")
    private List<ModelEntry> model;

    public ModelType(final String n, final String d, final List<ModelEntry> m) {
        this.name = n;
        this.description = d;
        this.model = m;
    }

    public List<ModelEntry> getModel() {
        return this.model;
    }

    public String getName() {
        return this.name;
    }

    public String getDescription() {
        return this.description;
    }

    @Override
    public String toString() {

        return new StringBuilder("Sig: ")
                .append(name)
                .append(", Description: ")
                .append(description)
                .append(", Model: ")
                .append(model)
                .toString();
    }
}
