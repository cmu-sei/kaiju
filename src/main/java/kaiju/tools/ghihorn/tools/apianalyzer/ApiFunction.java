package kaiju.tools.ghihorn.tools.apianalyzer;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.SortedSet;
import java.util.TreeSet;

public class ApiFunction {

    public static final String API_NAME_SEPARATOR = "::";
    private String apiName;
    private final Map<Integer, String> apiParameters = new HashMap<>();
    private String apiRetnValue = null;

    public ApiFunction(final String a, final List<String> params, final String retn) {
        this.apiName = a;

        if (params != null) {
            setApiParameters(params);
        }
        this.apiRetnValue = retn;
    }

    /**
     * @return the apiName
     */
    public String getApiName() {
        return apiName;
    }

    /**
     * @param apiName the apiName to set
     */
    public void setApiName(String apiName) {
        this.apiName = apiName;
    }

    /**
     * @return the apiParameters
     */
    public Map<Integer, String> getApiParameters() {
        return apiParameters;
    }

    /**
     * @param apiParameters the apiParameters to set
     */
    public void setApiParameters(List<String> params) {
        for (int i = 0; i < params.size(); i++) {
            String p = params.get(i);
            if (p.length() > 0) {
                apiParameters.put(i, p);
            }
        }
    }

    /**
     * @return the apiRetnValue
     */
    public String getApiRetnValue() {
        return apiRetnValue;
    }

    /**
     * @param apiRetnValue the apiRetnValue to set
     */
    public void setApiRetnValue(String apiRetnValue) {
        this.apiRetnValue = apiRetnValue;
    }

    public boolean hasParameters() {
        return !this.apiParameters.isEmpty();
    }

    public boolean hasRetVal() {
        return this.apiRetnValue != null;
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
        result = prime * result + ((apiName == null) ? 0 : apiName.hashCode());
        result = prime * result + ((apiParameters == null) ? 0 : apiParameters.hashCode());
        result = prime * result + ((apiRetnValue == null) ? 0 : apiRetnValue.hashCode());
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
        ApiFunction other = (ApiFunction) obj;
        if (apiName == null) {
            if (other.apiName != null)
                return false;
        } else if (!apiName.equals(other.apiName))
            return false;
        if (apiParameters == null) {
            if (other.apiParameters != null)
                return false;
        } else if (!apiParameters.equals(other.apiParameters))
            return false;
        if (apiRetnValue == null) {
            if (other.apiRetnValue != null)
                return false;
        } else if (!apiRetnValue.equals(other.apiRetnValue))
            return false;
        return true;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder(apiName).append("(");

        SortedSet<Integer> ordinals = new TreeSet<>(apiParameters.keySet());
        int i = 0;
        for (Integer ord : ordinals) {
            String param = apiParameters.get(ord);
            sb.append(param);
            if (i + 1 < ordinals.size()) {
                sb.append(", ");
            }
            ++i;
        }
        sb.append(") -> ").append(apiRetnValue);

        return sb.toString();
    }

}
