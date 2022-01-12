package kaiju.tools.ghihorn.tools.apianalyzer.json;

import java.util.ArrayList;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

public class SignaturesType {
    @Expose
    @SerializedName("Signatures")
    public ArrayList<SignatureEntry> signatures;
}