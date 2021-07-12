package kaiju.tools.ghihorn.signatures;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * An API model is a configurable representatation that expresses the semantics
 * of an API call 
 */
public class ApiModel {
    private final String name;
    private final String description;
    private final Map<String, ApiFunctionModel> model;
    
    public ApiModel(final String n, final String description) {

        this.name = n.toUpperCase();
        this.description = description;
        // this.variables = new HashSet<>();
        this.model = new HashMap<>();
    }

    /**
     * Fetch an iterator to check the APIs in a sequence
     * 
     * @return
     */
    public Collection<ApiFunctionModel> getModel() {
        return this.model.values();
    }

    public String getDescription() {
        return this.description;
    }

    public String getName() {
        return this.name;
    }

    public void addApi(final ApiFunctionModel api) {
        this.model.put(api.getName().toUpperCase(), api);
    }
    
    public Optional<ApiFunctionModel> getApiByName(final String n) {
        ApiFunctionModel f = model.get(n.toUpperCase());
        return (f == null) ? Optional.empty() : Optional.of(f);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, description, model);
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == null) {
            return false;
        }
        ApiModel other = (ApiModel) obj;
        if (name == null || other.name == null) {
            return false;
        }
        return this.name.equalsIgnoreCase(other.name);
    }

    @Override
    public String toString() {
        return this.name + ": " + this.description;
    }
}
