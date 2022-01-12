package kaiju.tools.ghihorn.api;

import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import generic.jar.ResourceFile;
import generic.jar.ResourceFileFilter;
import ghidra.GhidraException;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import kaiju.tools.ghihorn.decompiler.GhiHornDecompiler;

public class GhiHornApiDatabase implements ApiDatabase {

    public final static String DEFAULT_API_DIRECTORY = "apidb";
    public final static String API_PROJECT = "apidb";

    private final Map<ApiEntry, HighFunction> loadedApiEntries;
    private final GhiHornDecompiler decompiler;
    private GhidraProject apiProject;
    private ResourceFile apidbDir;

    public GhiHornApiDatabase(final GhiHornDecompiler decompiler) {
        this.loadedApiEntries = new ConcurrentHashMap<>();
        this.decompiler = decompiler;
    }

    @Override
    public synchronized Optional<HighFunction> getApiFunction(final String libName, final String apiName) {

        final ApiEntry key = ApiEntry.create(libName, apiName);

        if (this.loadedApiEntries.containsKey(key)) {
            return Optional.of(loadedApiEntries.get(key));
        }
        return Optional.empty();
    }

    /**
     * 
     */
    @Override
    public synchronized boolean loadApiLibraries() {

        try {
            this.apidbDir = Application.getModuleDataSubDirectory(DEFAULT_API_DIRECTORY);
        } catch (IOException e) {
            apidbDir = null;
            Msg.error(this, "Could not find API directory: " + DEFAULT_API_DIRECTORY);
        }
        if (apiProject != null) {
            return true;
        }
        try {
            final List<Program> libraries = new ArrayList<>();

            this.apiProject =
                    GhidraProject.createProject(apidbDir.getAbsolutePath(), API_PROJECT,
                            // discard project
                            true);
            apiProject.setDeleteOnClose(true);

            ResourceFile[] apiFiles = apidbDir.listFiles(new ResourceFileFilter() {
                @Override
                public boolean accept(ResourceFile f) {
                    return f.getName().endsWith(".dll");
                }
            });

            for (ResourceFile apiLib : apiFiles) {

                try {
                    FileSystem fs = FileSystems.getDefault();
                    Path apiPath = fs.getPath(apiLib.getCanonicalPath());
                    Program program = apiProject.importProgramFast(apiPath.toFile());

                    apiProject.analyze(program, true);


                    libraries.add(program);

                } catch (IOException ioe) {
                    ioe.printStackTrace();

                }
            }

            if (libraries.isEmpty()) {
                throw new GhidraException(
                        "No libraries found in " + API_PROJECT);
            }

            for (Program program : libraries) {

                Msg.info(this, "loaded library " + program.getName() + " with "
                        + program.getFunctionManager().getFunctionCount() + " functions");

                List<HighFunction> funcs =
                        decompiler.decompileProgram(program, TaskMonitor.DUMMY);

                for (HighFunction hf : funcs) {
                    ApiEntry apiEntry =
                            ApiEntry.create(program.getName(), hf.getFunction().getName());
                    this.loadedApiEntries.put(apiEntry, hf);
                }
            }
        } catch (Exception e) {
            return false;
        }

        return true;
    }

    @Override
    public synchronized boolean freeApiLibraries() {
        dispose();
        return true;
    }

    protected void dispose() {
        if (apiProject != null) {
            apiProject.close();
        }
    }

    public synchronized List<String> getLoadedLibraries() {
        return this.loadedApiEntries.entrySet().stream().map(e -> e.getKey().getLibName())
                .collect(Collectors.toList());
    }

    public List<String> getLoadedApis() {
        return this.loadedApiEntries.entrySet()
                .stream()
                .map(e -> e.getKey().getLibName() + "::" + e.getValue())
                .collect(Collectors.toList());
    }

    @Override
    public String toString() {
        
        StringBuilder sb = new StringBuilder("APIs loaded from: ");
        sb.append(this.apidbDir.getAbsolutePath()).append("\n");
        sb.append(getLoadedLibraries().stream().map(s -> " * " + s + "\n")
                .collect(Collectors.joining()));
        
                return sb.toString();
    }
}
