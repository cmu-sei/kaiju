package kaiju.tools.ghihorn.z3;

import com.microsoft.z3.Status;

/**
 * Represents status of a proof
 */
public enum GhiHornFixedpointStatus {

    Satisfiable {
        @Override
        public String toString() {
            return "Satisfiable";
        }
    },
    Unsatisfiable {
        @Override
        public String toString() {
            return "Unsatisfiable";
        }
    },
    /**
     * Z3 Unknown answer
     */
    Unknown {
        @Override
        public String toString() {
            return "Unknown";
        }
    },

    /**
     * This means the query has yet to be performed
     */
    Undefined {
        @Override
        public String toString() {
            return "Undefined";
        }
    },
    /**
     * Something went wrong
     */
    Error {
        @Override
        public String toString() {
            return "Error";
        }
    };

    public static GhiHornFixedpointStatus translate(Status s) {
        if (s == Status.SATISFIABLE) {
            return GhiHornFixedpointStatus.Satisfiable;
        } else if (s == Status.UNSATISFIABLE) {
            return GhiHornFixedpointStatus.Unsatisfiable;
        } else if (s == Status.UNKNOWN) {
            return GhiHornFixedpointStatus.Unknown;
        }
        return GhiHornFixedpointStatus.Undefined;
    }
}
