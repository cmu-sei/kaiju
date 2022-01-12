package kaiju.tools.ghihorn.z3;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class GhiHornZ3Parameters {
    final Map<String, String> strParams;
    final Map<String, Integer> intParams;
    final Map<String, Boolean> boolParams;

    public GhiHornZ3Parameters() {
        strParams = new HashMap<>();
        intParams = new HashMap<>();
        boolParams = new HashMap<>();

    }

    public void put(final String key, final Object value) {
        if (value instanceof Integer) {
            putInt(key, (Integer) value);
        } else if (value instanceof String) {
            putStr(key, (String) value);

        } else if (value instanceof Boolean) {
            putBool(key, (Boolean) value);
        }
    }

    public void putAll(final Map<String, Object> map) {
        for (Map.Entry<String, Object> entry : map.entrySet()) {
            String key = entry.getKey();
            Object value = entry.getValue();
            if (value instanceof Integer) {
                putInt(key, (Integer) value);
            } else if (value instanceof String) {
                putStr(key, (String) value);

            } else if (value instanceof Boolean) {
                putBool(key, (Boolean) value);
            }
        }
    }

    public Object get(String key) {

        if (intParams.containsKey(key)) {
            return getInt(key);
        } else if (strParams.containsKey(key)) {
            return getStr(key);
        } else if (boolParams.containsKey(key)) {
            return getBool(key);
        }
        return null;
    }

    private Integer getInt(final String key) {
        return intParams.get(key);
    }

    private Integer putInt(final String key, final Integer value) {
        return intParams.put(key, value);
    }

    private String getStr(final String key) {
        return strParams.get(key);
    }

    private String putStr(final String key, final String value) {
        return strParams.put(key, value);
    }

    private Boolean getBool(final String key) {
        return boolParams.get(key);
    }

    private Boolean putBool(final String key, final Boolean value) {
        return boolParams.put(key, value);
    }

    public Set<Map.Entry<String, Object>> entrySet() {

        final Map<String, Object> masterMap = new HashMap<>();
        masterMap.putAll(boolParams);
        masterMap.putAll(strParams);
        masterMap.putAll(intParams);

        return masterMap.entrySet();
    }

    public boolean isEmpty() {
        return boolParams.isEmpty() && strParams.isEmpty() && intParams.isEmpty();
    }

    public void clear() {
        boolParams.clear();
        strParams.clear();
        intParams.clear();
    }

    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();
        entrySet()
                .forEach(e -> sb.append(e.getKey()).append("=").append(e.getValue()).append("\n"));

        return sb.toString();
    }
}
