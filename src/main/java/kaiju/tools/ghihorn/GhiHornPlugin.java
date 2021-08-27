package kaiju.tools.ghihorn;

import kaiju.common.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import docking.action.builder.ActionBuilder;
import ghidra.app.events.ProgramSelectionPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.app.services.GhidraScriptService;
import ghidra.app.services.GoToService;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.SystemUtilities;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import kaiju.tools.ghihorn.api.ApiDatabaseService;
import kaiju.tools.ghihorn.display.GhiHornFrontEnd;
import kaiju.tools.ghihorn.hornifer.GhiHornifier;
import kaiju.tools.ghihorn.tools.apianalyzer.ApiAnalyzerFrontEnd;
import kaiju.tools.ghihorn.tools.apianalyzer.ApiAnalyzerHornifier;
import kaiju.tools.ghihorn.tools.pathanalyzer.PathAnalyzerFrontEnd;
import kaiju.tools.ghihorn.tools.pathanalyzer.PathAnalyzerHornifier;

//@formatter:off
@PluginInfo(
	status = PluginStatus.UNSTABLE,
	packageName = KaijuPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "CERT Analyze horn clauses",
	description = "Generate and analyze horn clauses using z3 and Ghidra.",
    servicesRequired = {GoToService.class, 
                        ColorizingService.class,       
                        GhidraScriptService.class, 
                        ProgramManager.class,
                        ApiDatabaseService.class},
	eventsProduced = { ProgramSelectionPluginEvent.class }	
)
//@formatter:on
/**
 * The main plugin class
 */
public class GhiHornPlugin extends ProgramPlugin {

    public static final String PLUGIN_NAME = "GhiHorn";
    public static final String API_DB = "GH:API";

    // Universal configuration settings used by all tools
    public static final String TOOL_NAME = "GH:ToolName";
    public static final String Z3_PARAMS = "GH:Z3PARAMS";

    // The API service
    private ApiDatabaseService apiDatabaseService;

    // The configuration of tools
    private final Map<String, GhiHornToolConfig> ghiHornTools;
    
    private TaskMonitor monitor;

    // This is the base component provider for the plugin
    private GhiHornProvider provider;

    // Utility class to maintain the mapping of front end to back end
    private class GhiHornToolConfig {
        public GhiHornToolConfig(GhiHornFrontEnd front, GhiHornifier back) {
            frontEnd = front;
            backEnd = back;
            backEnd.registerListener(frontEnd, front.getEventConfig());
        }
        GhiHornFrontEnd frontEnd;
        GhiHornifier backEnd;
    }

    /**
     * Plugin constructor
     * 
     * @param tool The plugin tool that this plugin is added to.
     */
    public GhiHornPlugin(final PluginTool tool) {

        super(tool, true, true);

        provider = null;
        monitor = new TaskMonitorAdapter(true);
        ghiHornTools = new HashMap<>();

        Msg.info(this, PLUGIN_NAME + " plugin loaded.");
    }

    /**
     * Execute the plugin by launching a background command
     * 
     * @param model
     */
    public boolean execute(Map<String, Object> settings) throws RuntimeException {

        if (settings == null) {
            return false;
        }

        final String toolName = (String) settings.get(TOOL_NAME);
        if (toolName == null) {
            return false;
        }
        var toolConfig = ghiHornTools.get(toolName);
        if (toolConfig == null) {
            throw new RuntimeException("Could not find hornifier for tool: " + toolName);
        }

        final GhiHornCommand cmd = new GhiHornCommand(this, toolConfig.backEnd, settings);
        this.tool.executeBackgroundCommand(cmd, currentProgram);

        return true;
    }

    public void cancel() {
        if (this.tool != null) {
            this.tool.terminateBackgroundCommands(false);
        }
    }

    @Override
    public boolean goTo(Address addr) {
        return super.goTo(addr);
    }

    @Override
    protected void dispose() {
        if (apiDatabaseService != null) {
            apiDatabaseService.freeApiLibraries();
        }
    }

    /**
     * Called when a new program is activated
     */
    @Override
    protected void programActivated(final Program program) {

        super.programActivated(program);

        ghiHornTools.put(PathAnalyzerFrontEnd.NAME, new GhiHornToolConfig(
                new PathAnalyzerFrontEnd(this), new PathAnalyzerHornifier()));

        ghiHornTools.put(ApiAnalyzerFrontEnd.NAME, new GhiHornToolConfig(
                new ApiAnalyzerFrontEnd(this), new ApiAnalyzerHornifier()));

        // Rerun auto analysis to remove/fix badness, such as non-returning
        // functions
        AutoAnalysisManager aam = AutoAnalysisManager.getAnalysisManager(program);
        if (!aam.isAnalyzing()) {
            aam.reAnalyzeAll(program.getMemory());
        }

        // Install a new action to show the GhiHorn interface
        if (!SystemUtilities.isInHeadlessMode()) {

            final List<GhiHornFrontEnd> frontEnds =
                    ghiHornTools.values().stream().map(p -> p.frontEnd)
                            .collect(Collectors.toList());

            this.provider = new GhiHornProvider(tool, this, frontEnds);
            new ActionBuilder("Open GhiHorn", getName())
                    .supportsDefaultToolContext(true)
                    .menuPath("&Kaiju", "GhiHorn")
                    .onAction(c -> provider.setVisible(true))
                    .menuIcon(null)
                    .keyBinding("ctrl G")
                    .buildAndInstall(tool);
        } else {
            Msg.info(this, "Running in headless mode, use the GhiHorn script!");
        }

        this.apiDatabaseService = this.tool.getService(ApiDatabaseService.class);

        Msg.info(this, PLUGIN_NAME + " activated");
    }

    /**
     * @return TaskMonitor return the monitor
     */
    public TaskMonitor getTaskMonitor() {
        return monitor;
    }

    /**
     * @return ApiAnalyzerProvider return the provider
     */
    public GhiHornProvider getProvider() {
        return provider;
    }

    public ProgramSelection getCurrentSelection() {
        return getCurrentSelection();
    }

    public ProgramSelection getCurrentHighlight() {
        return getCurrentHighlight();
    }

    /**
     * @param provider the provider to set
     */
    public void setProvider(GhiHornProvider provider) {
        this.provider = provider;
    }

    public ApiDatabaseService getApiService() {
        return this.apiDatabaseService;
    }
}
