package kaiju.tools.ghihorn.z3;

public enum GhiHornType {
    Int, Bool, Char, BitVec, Float, String, Array, Tuple, Struct, Undefined;

    public static GhiHornDataType create(GhiHornType type) {

        switch (type) {
            case Int:
                return new GhiHornIntegerType();
            case Bool:
                return new GhiHornBooleanType();
            case BitVec:
                return new GhiHornBitVectorType();
            case Array:
                return new GhiHornArrayType();

            // Not sure what to do with these, so they are now undefined types (which are
            // uninterpreted sorts)
            case Char:
            case Float:
            case String:
            case Struct:
            case Tuple:
            case Undefined:
            default:
                return new GhiHornUndefinedType();
        }
    }
}
