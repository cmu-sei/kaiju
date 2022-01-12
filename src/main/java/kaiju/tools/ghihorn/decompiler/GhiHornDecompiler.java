package kaiju.tools.ghihorn.decompiler;

import java.util.List;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public interface GhiHornDecompiler {
    public List<HighFunction> decompileProgram(Program program, TaskMonitor monitor)
    throws CancelledException, Exception;
}
