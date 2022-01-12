package kaiju.ghihorn;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import ghidra.program.model.pcode.HighFunction;
import kaiju.tools.ghihorn.api.ApiDatabase;

/**
 * Simulates an API database without the overhead of loading the real plugin
 */
class DummyApiDatabase implements ApiDatabase {

    private Map<String, List<HighFunction>> preInstalledApis = new HashMap<>();

    public void installPreloadedLibrary(String name, List<HighFunction> funcs) {

        preInstalledApis.put(name, funcs);
    }

    @Override
    public boolean loadApiLibraries() {

        return true;
    }

    @Override
    public List<String> getLoadedLibraries() {
        String[] libs = preInstalledApis.keySet().toArray(new String[0]);
        if (libs.length == 0) {
            return new ArrayList<>();
        }
        return new ArrayList<String>(Arrays.asList(libs));
    }

    public List<String> getLoadedApis() {
        return this.preInstalledApis.entrySet()
                .stream()
                .map(e -> e.getKey() + "::" + e.getValue())
                .collect(Collectors.toList());
    }

    @Override
    public boolean freeApiLibraries() {
        return true;
    }

    @Override
    public Optional<HighFunction> getApiFunction(String libName, String funcName) {
        if (preInstalledApis.containsKey(libName)) {
            List<HighFunction> hfList = preInstalledApis.get(libName);
            for (HighFunction hf : hfList) {
                if (hf.getFunction().getName().equalsIgnoreCase(funcName)) {
                    return Optional.of(hf);
                }
            }
        }
        return Optional.empty();
    }

    @Override
    public String toString() {
        return "Dummy API DB";
    }
}
