package kaiju.tools.ghihorn.api;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import generic.jar.ResourceFile;
import generic.jar.ResourceFileFilter;
import ghidra.GhidraException;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import kaiju.tools.ghihorn.decompiler.GhiHornParallelDecompiler;

@PluginInfo(
        status = PluginStatus.UNSTABLE,
        packageName = ApiDatabasePlugin.PLUGIN_NAME,
        category = PluginCategoryNames.SUPPORT,
        shortDescription = "CERT API database loader",
        description = "Various applications of horn clause analysis in Ghidra.",
        servicesProvided = {ApiDatabaseService.class})
/**
 * A plugin for the API database plugin
 */
public class ApiDatabasePlugin extends Plugin implements ApiDatabaseService {
    public final static String PLUGIN_NAME = "API Database";
    private final Map<ApiEntry, HighFunction> loadedApiEntries;
    private final GhiHornParallelDecompiler decompiler;
    private GhidraProject apiProject;
    private ResourceFile apidbDir;

    public ApiDatabasePlugin(PluginTool tool) {
        super(tool);

        this.loadedApiEntries = new HashMap<>();
        this.decompiler = new GhiHornParallelDecompiler(tool);

        try {
            apidbDir = Application.getModuleDataSubDirectory(ApiDirectory);
        } catch (IOException e) {
            apidbDir = null;
            Msg.error(this, "Could not find API directory: " + ApiDirectory);
        }
    }

    @Override
    public Optional<HighFunction> getApiFunction(final String libName, final String apiName) {

        ApiEntry key = ApiEntry.create(libName, apiName);
        if (this.loadedApiEntries.containsKey(key)) {
            return Optional.of(loadedApiEntries.get(key));
        }
        return Optional.empty();
    }

    /**
     * 
     */
    @Override
    public boolean loadApiLibraries() {
        if (apiProject != null) {
            return true;
        }
        try {
            final List<Program> libraries = new ArrayList<>();

            this.apiProject =
                    GhidraProject.createProject(apidbDir.getAbsolutePath(), ApiDatabaseProjectName,
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
                        "No libraries found in " + ApiDatabaseService.ApiDatabaseProjectName);
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

    /**
     * 
     * @param apiFile
     * @return
     */
    private Program importLibrary(File apiFile) {

        if (apiProject == null) {
            try {
                this.apiProject =
                        GhidraProject.createProject(apidbDir.getAbsolutePath(),
                                ApiDatabaseProjectName,
                                // discard project
                                true);
            } catch (IOException e) {
                return null;
            }
            apiProject.setDeleteOnClose(true);
        }
        FileSystem fs = FileSystems.getDefault();

        Path apiPath = null;
        Program program = null;
        try {
            apiPath = fs.getPath(apiFile.getCanonicalPath());
            program = apiProject.openProgram(String.valueOf(apiPath.getParent()),
                    String.valueOf(apiPath.getFileName()), false);

        } catch (Exception e) {
            try {
                program = apiProject.importProgram(apiPath.toFile());
            } catch (Exception e2) {
                return null;
            }
        }

        apiProject.analyze(program, true);
        return program;

    }

    /**
     * Load a specific API library
     */
    @Override
    public List<HighFunction> loadApiLibrary(final String apiPath)
            throws FileNotFoundException {

        final File libFile = new File(apiPath);
        if (libFile.exists()) {
            Program libProgram = importLibrary(libFile);

            if (libProgram != null) {

                Msg.info(this, "loaded library with "
                        + libProgram.getFunctionManager().getFunctionCount() + " functions");

                try {
                    return decompiler.decompileProgram(libProgram, TaskMonitor.DUMMY);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            } else {
                throw new FileNotFoundException(apiPath + " not found!");
            }
        }

        return new ArrayList<>();
    }

    @Override
    public boolean freeApiLibraries() {
        dispose();
        return true;
    }

    @Override
    protected void dispose() {
        if (apiProject != null) {
            apiProject.close();
        }
    }

    @Override
    public List<String> getLoadedLibraries() {
        return this.loadedApiEntries.entrySet().stream().map(e -> e.getKey().getLibName())
                .collect(Collectors.toList());
    }
}
