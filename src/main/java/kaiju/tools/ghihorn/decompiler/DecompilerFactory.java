package kaiju.tools.ghihorn.decompiler;

import java.io.IOException;
import generic.cache.CountingBasicFactory;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.framework.plugintool.util.OptionsService;
import ghidra.program.model.listing.Program;

public class DecompilerFactory extends CountingBasicFactory<DecompInterface> {

    private Program program;
    private ServiceProvider serviceProvider;

    public DecompilerFactory(Program program, ServiceProvider plugin) {
        this.serviceProvider = plugin;
        this.program = program;
    }

    public DecompInterface createDecompiler() {
        DecompInterface decompiler = new DecompInterface();
        if (decompiler.openProgram(program)) {

            DecompileOptions options;
            options = new DecompileOptions();
            try {
                final OptionsService service = serviceProvider.getService(OptionsService.class);
                if (service != null) {
                    final ToolOptions opt = service.getOptions("Decompiler");
                    options.grabFromToolAndProgram(null, opt, program);
                }
            } catch (final NullPointerException npx) {
                npx.printStackTrace();
               return null;
            }

            decompiler.setOptions(options);
            decompiler.toggleCCode(false);
            decompiler.toggleSyntaxTree(true);
            decompiler.setSimplificationStyle("decompile");
        }
        return decompiler;
    }

    @Override
    public DecompInterface doCreate(int itemNumber) throws IOException {
        return createDecompiler();
    }

    @Override
    public void doDispose(DecompInterface decompiler) {
        decompiler.dispose();
    }
}
