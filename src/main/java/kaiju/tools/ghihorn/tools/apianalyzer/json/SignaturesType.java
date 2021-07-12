package kaiju.tools.ghihorn.tools.apianalyzer.json;

import java.util.ArrayList;
import com.google.gson.annotations.Expose;
import com.google.gson.annotations.SerializedName;

class SignaturesType {
    @Expose
    @SerializedName("Signatures")
    ArrayList<SignatureEntry> signatures;
}