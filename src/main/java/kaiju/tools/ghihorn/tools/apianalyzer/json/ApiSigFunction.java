package kaiju.tools.ghihorn.tools.apianalyzer.json;

import java.util.List;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class ApiSigFunction {

    @Expose
    @SerializedName("API")
    private String api;

    @Expose
    @SerializedName("Parameters")
    private List<String> parameters;

    @Expose
    @SerializedName("ReturnValue")
    private String returnValue;

    /**
     * @param api
     * @param parameters
     * @param returnValue
     */
    public ApiSigFunction(String api, List<String> parameters, String returnValue) {
        this.api = api;
        this.parameters = parameters;
        this.returnValue = returnValue;
    }

    /**
     * @return the api
     */
    public String getApi() {
        return api;
    }

    /**
     * @return the parameters
     */
    public List<String> getParameters() {
        return parameters;
    }

    /**
     * @return the returnValue
     */
    public String getReturnValue() {
        return returnValue;
    }
}
