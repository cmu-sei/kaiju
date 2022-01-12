package kaiju.tools.ghihorn;

import java.util.Map;
import com.google.common.base.Verify;
import com.google.common.base.VerifyException;
import ghidra.program.model.address.Address;
import kaiju.tools.ghihorn.api.ApiDatabase;
import kaiju.tools.ghihorn.decompiler.GhiHornDecompiler;
import kaiju.tools.ghihorn.hornifer.GhiHornifier;
import kaiju.tools.ghihorn.hornifer.horn.HornProgram;
import kaiju.tools.ghihorn.tools.apianalyzer.ApiAnalyzerController;
import kaiju.tools.ghihorn.tools.apianalyzer.ApiAnalyzerHornifier;
import kaiju.tools.ghihorn.tools.pathanalyzer.PathAnalyzerController;
import kaiju.tools.ghihorn.tools.pathanalyzer.PathAnalyzerHornifier;
import kaiju.tools.ghihorn.z3.GhiHornZ3Parameters;

public class GhiHornifierBuilder {
    private final String name;
    private GhiHornDecompiler decompiler;
    private ApiDatabase apiDatabase;
    private GhiHornZ3Parameters z3Parameters;
    private Map<String, Object> parameters;
    private HornProgram hornProgram;
    private Address entryPoint;

    public GhiHornifierBuilder(String name) {
        this.name = name;
        this.decompiler = null;
        this.apiDatabase = null;
        this.z3Parameters = null;
        this.parameters = null;
        this.hornProgram = null;
        this.entryPoint = null;
    }

    public GhiHornifierBuilder withDecompiler(GhiHornDecompiler d) {
        this.decompiler = d;
        return this;
    }

    public GhiHornifierBuilder withParameters(Map<String, Object> p) {
        this.parameters = p;
        return this;
    }

    public GhiHornifierBuilder withApiDatabase(ApiDatabase apiDb) {
        this.apiDatabase = apiDb;
        return this;
    }

    public GhiHornifierBuilder withZ3Params(GhiHornZ3Parameters z3Params) {
        this.z3Parameters = z3Params;
        return this;
    }

    public GhiHornifierBuilder withHornProgram(HornProgram hornProg) {
        this.hornProgram = hornProg;
        return this;
    }

    public GhiHornifierBuilder withEntryPoint(Address ep) {
        this.entryPoint = ep;
        return this;
    }

    public GhiHornifier build() throws VerifyException {

        Verify.verify(this.decompiler != null, "Cannot build: No decompiler");
        Verify.verify(this.apiDatabase != null, "Cannot build: No API database");
        Verify.verify(this.entryPoint != null, "Cannot build: invalid entry point");
                
        GhiHornifier hornifier = null;
        if (name.equals(PathAnalyzerController.NAME)) {
            hornifier = new PathAnalyzerHornifier();
        } else if (name.equals(ApiAnalyzerController.NAME)) {
            hornifier = new ApiAnalyzerHornifier();
        }
        if (this.z3Parameters != null) {
            hornifier.setZ3Parameters(this.z3Parameters);
        }
        if (hornProgram != null) {
            hornifier.setHornProgram(this.hornProgram);
        }

        // these are required
        hornifier.setEntryPoint(this.entryPoint);
        hornifier.setDecompiler(this.decompiler);
        hornifier.setApiDatabase(this.apiDatabase);
        hornifier.setParameters(this.parameters);

        return hornifier;
    }

}
