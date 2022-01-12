package kaiju.tools.ghihorn.decompiler;

import java.util.ArrayList;
import java.util.List;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * A simple, sequential decompiler
 */
public class GhiHornSimpleDecompiler implements GhiHornDecompiler {

    @Override
    public List<HighFunction> decompileProgram(Program program, TaskMonitor monitor)
            throws CancelledException, Exception {

        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(program);
        List<HighFunction> funcList = new ArrayList<>();
        for (Function f : program.getFunctionManager().getFunctions(true)) {
            DecompileResults decompResults = decompiler.decompileFunction(f,
                    DecompileOptions.SUGGESTED_DECOMPILE_TIMEOUT_SECS, monitor);
            funcList.add(decompResults.getHighFunction());
        }

        return funcList;
    }
}
