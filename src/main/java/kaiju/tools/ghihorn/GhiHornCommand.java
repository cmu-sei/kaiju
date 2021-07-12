package kaiju.tools.ghihorn;

import java.util.List;
import java.util.Map;
import com.google.common.base.VerifyException;
import com.microsoft.z3.Z3Exception;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.cmd.BackgroundCommand;
import ghidra.framework.model.DomainObject;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.CancelledListener;
import ghidra.util.task.TaskMonitor;
import kaiju.tools.ghihorn.decompiler.GhiHornParallelDecompiler;
import kaiju.tools.ghihorn.hornifer.GhiHornifier;

public class GhiHornCommand extends BackgroundCommand implements CancelledListener {
    private final GhiHornifier ghihornTool;
    // notify the plugin that analysis is complete. This is done through a
    // property change evnent, which is asynchronous.
    private final Map<String, Object> settings;
    private final ProgramPlugin plugin;

    /**
     * 
     * @param plugin
     */
    public GhiHornCommand(final ProgramPlugin plugin, GhiHornifier tool,
            final Map<String, Object> s) {

        super(plugin.getName(), true, true, false);

        this.plugin = plugin;
        this.ghihornTool = tool;
        this.settings = s;

    }

    @Override
    public void taskCompleted() {
        ghihornTool.complete();

    }

    @Override
    protected void setStatusMsg(final String message) {

        super.setStatusMsg(message);
        ghihornTool.statusUpdate(message);
    }

    /**
     * Execute this command
     */
    @Override
    public boolean applyTo(final DomainObject obj, final TaskMonitor monitor) {

        final Program program = (Program) obj;
        if (program == null) {
            setStatusMsg("Invalid program");
            return false;
        }

        try {

            // The analysis information must be generated for the entire CFG
            // ahead of time to accumulate the required variables
            if (!ghihornTool.configure(settings)) {
                setStatusMsg("Invalid configurtion");
                return false;
            }

            monitor.addCancelledListener(this);


            final GhiHornParallelDecompiler ghpd =
                    new GhiHornParallelDecompiler(this.plugin.getTool());

            final List<HighFunction> funcList = ghpd.decompileProgram(program, monitor);

            ghihornTool.evaluate(ghihornTool.hornify(funcList, monitor), monitor);

        } catch (Z3Exception z3x) {
            z3x.printStackTrace();
            setStatusMsg("Error during encoding " + z3x);
            return false;
        } catch (CancelledException cx) {
            setStatusMsg("Cancelled: " + cx.getMessage());
            return false;
        } catch (VerifyException | IllegalStateException ve) {
            setStatusMsg("Could not complete analysis: " + ve.getMessage());
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            setStatusMsg("Error: " + e.getMessage());
            return false;
        }

        setStatusMsg(getName() + " completed.");

        return true;
    }

    @Override
    public void cancelled() {
        ghihornTool.cancel();
    }
}
