package kaiju.tools.ghihorn.tools.apianalyzer.json;

import java.util.List;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class SignatureApiFunction {
    @Expose
    @SerializedName("API")
    private String apiName;

    @Expose
    @SerializedName("Args")
    private List<String> apiParameters;

    @Expose
    @SerializedName("Retn")
    private String apiRetnValue;

    public SignatureApiFunction(final String a, final List<String> params, final String retn) {
        this.apiName = a;
        this.apiParameters = params;
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
    public List<String> getApiParameters() {
        return apiParameters;
    }

    /**
     * @param apiParameters the apiParameters to set
     */
    public void setApiParameters(List<String> apiParameters) {
        this.apiParameters = apiParameters;
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


}
