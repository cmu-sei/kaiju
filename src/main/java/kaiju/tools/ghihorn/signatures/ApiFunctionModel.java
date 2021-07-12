package kaiju.tools.ghihorn.signatures;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * A function in the API model
 */
public class ApiFunctionModel {
    private Map<Integer, String> parameters;
    private String returnValue;
    private final String name;
    private final List<String> preconditions;
    private final List<String> postconditions;

    public ApiFunctionModel(final String name, final List<String> pre, final List<String> pst) {
        this.name = name;
        this.parameters = new HashMap<>();
        this.returnValue = null;

        this.preconditions = new ArrayList<>();
        if (pre != null) {
            this.preconditions.addAll(pre);
        }

        this.postconditions = new ArrayList<>();
        if (pst != null) {
            this.postconditions.addAll(pst);
        }
    }

    public String getName() {
        return this.name;
    }

    /**
     * Fetch the preconditions if they exist
     * 
     * @return the preconditions or empty
     */
    public Optional<List<String>> getPreconditions() {

        if (this.preconditions.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new ArrayList<String>() {
            {
                addAll(preconditions);
            }
        });
    }

    /**
     * Fetch the postconditions if they exist
     * 
     * @return the postconditions or empty
     */
    public Optional<List<String>> getPostconditions() {
        if (this.postconditions.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(new ArrayList<String>() {
            {
                addAll(postconditions);
            }
        });
    }

    public Map<Integer, String> getApiParameters() {

        return this.parameters;
    }

    public Optional<String> getReturnValue() {
        if (this.returnValue == null) {
            return Optional.empty();
        }
        return Optional.of(this.returnValue);
    }

    public void addReturnValue(final String ret) {
        this.returnValue = ret;
    }

    public void addParameter(final Integer ord, final String n) {
        this.parameters.put(ord, n);
    }

    @Override
    public boolean equals(Object o) {
        if (o == this)
            return true;
        if (!(o instanceof ApiFunctionModel)) {
            return false;
        }
        ApiFunctionModel apiFunction = (ApiFunctionModel) o;
        return Objects.equals(parameters, apiFunction.parameters)
                && Objects.equals(returnValue, apiFunction.returnValue)
                && Objects.equals(name, apiFunction.name)
                && Objects.equals(preconditions, apiFunction.preconditions)
                && Objects.equals(postconditions, apiFunction.postconditions);
    }

    @Override
    public int hashCode() {
        return Objects.hash(parameters, returnValue, name, preconditions, postconditions);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("', preconditions='[");
        this.preconditions.forEach(s -> sb.append(s + " "));

        sb.append("]', postconditions='[");
        this.postconditions.forEach(s -> sb.append(s + ", "));

        return "{" + " apiParameters='" + getApiParameters() + "'" + ", returnValue='"
                + this.returnValue + "'" + ", apiName='" + getName() + sb.toString() + "]'}";
    }
}
