package kaiju.tools.ghihorn.api;

import java.io.FileNotFoundException;
import java.util.List;
import java.util.Optional;
import ghidra.framework.plugintool.ServiceInfo;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.exception.CancelledException;

@ServiceInfo(
        defaultProvider = {ApiDatabasePlugin.class},
        description = "Open API database")
/**
 * This service fetches high functions for APIs
 */
public interface ApiDatabaseService {
    public final static String ApiDirectory = "apidb";
    public final static String ApiDatabaseProjectName = "apidb";

    public boolean loadApiLibraries() throws CancelledException;

    public List<HighFunction> loadApiLibrary(final String apiPath) throws FileNotFoundException;

    public List<String> getLoadedLibraries();
    
    public boolean freeApiLibraries();

    /**
     * 
     * @param libName
     * @param exportedName
     * @return
     */
    public Optional<HighFunction> getApiFunction(String libName, String exportedName);
}
