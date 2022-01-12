package kaiju.tools.ghihorn.api;

import java.util.List;
import java.util.Optional;
import ghidra.program.model.pcode.HighFunction;

/**
 * This interface defines what API databases need to support
 */
public interface ApiDatabase {
   
    public boolean loadApiLibraries();

    /**
     * Fetch the names of loaded libraries
     * @return
     */
    public List<String> getLoadedLibraries();
    
    /**
     * Get the loaded APIs
     * @return
     */
    public List<String> getLoadedApis();
    
    /**
     * Release the API DB 
     * @return
     */
    public boolean freeApiLibraries();

    /**
     * 
     * @param libName
     * @param exportedName
     * @return
     */
    public Optional<HighFunction> getApiFunction(String libName, String exportedName);

}
