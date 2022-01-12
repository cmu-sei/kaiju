package kaiju.tools.ghihorn.tools.apianalyzer.json;

import java.io.File;
import java.io.Reader;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import com.google.gson.Gson;
import kaiju.tools.ghihorn.tools.apianalyzer.ApiFunction;
import kaiju.tools.ghihorn.tools.apianalyzer.ApiSignature;

/**
 * Parse the JSON signature file
 */
public class ApiSignatureJsonParser {

    private File jsonFile;

    public ApiSignatureJsonParser(final File jf) {
        this.jsonFile = jf;
    }       

    /**
     * Parse the signature file
     * 
     * @return
     */
    public List<ApiSignature> parse() {

        if (jsonFile == null) {
            return new ArrayList<>();
        }

        try (Reader reader = Files.newBufferedReader(jsonFile.toPath())) {
            Gson gson = new Gson();
            SignaturesType sigs = gson.fromJson(reader, SignaturesType.class);

            List<ApiSignature> sigList = new ArrayList<>();
            for (SignatureEntry sig : sigs.signatures) {

                List<ApiFunction> apiFuncList = new ArrayList<>();
                sig.getSequence().forEach(s -> 
                    apiFuncList.add(new ApiFunction(s.getApiName(), s.getApiParameters(), s.getApiRetnValue())));

                sigList.add(new ApiSignature(sig.getName(), sig.getDescription(),
                       apiFuncList));
            }
            return sigList;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return new ArrayList<>();
    }
}
