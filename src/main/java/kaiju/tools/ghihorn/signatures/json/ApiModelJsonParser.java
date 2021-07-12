package kaiju.tools.ghihorn.signatures.json;

import java.io.File;
import java.io.Reader;
import java.nio.file.Files;
import java.util.List;
import com.google.common.base.Preconditions;
import com.google.gson.Gson;
import ghidra.util.Msg;
import kaiju.tools.ghihorn.signatures.ApiFunctionModel;
import kaiju.tools.ghihorn.signatures.ApiModel;

/**
 * Parse the JSON signature file
 */
public class ApiModelJsonParser {

    private File jsonFile;

    public ApiModelJsonParser(final File jf) {
        this.jsonFile = jf;
    }

    public ApiModel parse() {

        Preconditions.checkNotNull(jsonFile, "Invalid JSON file specified");

        try (Reader reader = Files.newBufferedReader(jsonFile.toPath())) {

            Gson gson = new Gson();
            ModelType model = gson.fromJson(reader, ModelType.class);
            List<ModelEntry> modelList = model.getModel();
            ApiModel apiModel = new ApiModel(model.getName(), model.getDescription());
            
            if (modelList != null) {

                // Add the model, which includes the constraints imposed by
                // different APIs

                for (ModelEntry m : modelList) {

                    ApiFunctionModel apiFunc =
                            new ApiFunctionModel(m.getAPI(), m.getPreconditions(),
                                    m.getPostconditions());

                    m.getParameters().ifPresent(paramList -> {
        
                        for (int ord = 0; ord < paramList.size(); ord++) {
                            String param = paramList.get(ord);
                            apiFunc.addParameter(ord, param);
                        }
                    });
                    
                    m.getRetn().ifPresent(apiFunc::addReturnValue);

                    apiModel.addApi(apiFunc);
                }

            }
            return apiModel;

            // return modelEntryList;

        } catch (Exception x) {
            Msg.warn(ApiModelJsonParser.class, "There was a problem loading JSON file:" + jsonFile);

        }
        return null;
    }
}
