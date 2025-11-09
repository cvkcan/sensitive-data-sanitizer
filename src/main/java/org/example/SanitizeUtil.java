package org.example;

import com.google.gson.Gson;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;

import java.lang.reflect.Field;
import java.util.*;
import java.util.logging.Logger;

public class SanitizeUtil {

    private static final List<String> SENSITIVE_FIELDS = List.of(
            "username", "password", "ssn", "apikey", "authtoken", "accesstoken", "secretkey", "privatekey",
            "bankaccountnumber", "creditcardnumber", "cvv", "pin"
    );

    private static final Gson gson = new Gson();
    private static final Logger LOGGER = Logger.getLogger(SanitizeUtil.class.getName());

    public static String toJson(Object object) {
        return sanitize(object);
    }

    private static <T> String sanitize(T object) {
        if (ObjectUtils.isEmpty(object)) {
            return StringUtils.EMPTY;
        }
        String jsonString;
        try {
            Class<T> clazz = (Class<T>) object.getClass();
            T tObject = clazz.getDeclaredConstructor().newInstance();
            for (Class<T> c = clazz; !ObjectUtils.isEmpty(c) && ObjectUtils.notEqual(c, Object.class); c = (Class<T>) c.getSuperclass()) {
                Field[] declaredFields = object.getClass().getDeclaredFields();
                for (Field field : declaredFields) {
                    field.setAccessible(true);
                    Object value = field.get(object);
                    if (SENSITIVE_FIELDS.contains(field.getName().toLowerCase())) {
                        field.set(tObject, "***");
                    } else if (value instanceof Collection<?>) {
                        Collection<Object> sanitizedCollection = new ArrayList<>();
                        Collection<?> collection = (Collection<?>) value;
                        String fieldName = field.getName();
                        boolean anyFieldsMatch = SENSITIVE_FIELDS.stream()
                                .anyMatch(fieldName::startsWith);
                        for (Object o : collection) {
                            boolean isPojo = o != null
                                    && !o.getClass().isPrimitive()
                                    && !(o instanceof String)
                                    && !(o instanceof Number)
                                    && !(o instanceof Boolean)
                                    && !(o instanceof Character)
                                    && !(o instanceof Collection)
                                    && !(o instanceof Map)
                                    && !o.getClass().getPackageName().startsWith("java.");

                            if (!isPojo && anyFieldsMatch) {
                                sanitizedCollection.add("***");
                            } else if (isPojo) {
                                sanitizedCollection.add(sanitize(o));
                            } else {
                                sanitizedCollection.add(o);
                            }
                        }
                        field.set(tObject, sanitizedCollection);

                    } else if (value instanceof Map<?, ?>) {
                        Map<?, ?> map = (Map<?, ?>) value;
                        Map<Object, Object> sanitizedMap = new HashMap<>();
                        for (Map.Entry<?, ?> entry : map.entrySet()) {
                            Object key = entry.getKey();
                            Object val = entry.getValue();
                            if (key instanceof String strKey) {
                                String lowerKey = strKey.toLowerCase();
                                sanitizedMap.put(key, SENSITIVE_FIELDS.contains(lowerKey) ? "****" : val
                                );
                            } else {
                                sanitizedMap.put(key, sanitize(key));
                            }
                        }
                        field.set(tObject, sanitizedMap);
                    } else {
                        field.set(tObject, value);
                    }
                }
            }
            jsonString = gson.toJson(tObject);
        } catch (Exception e) {
            LOGGER.severe("Error during sanitization: " + e.getMessage());
            jsonString = StringUtils.EMPTY;
        }
        return jsonString;
    }

}
