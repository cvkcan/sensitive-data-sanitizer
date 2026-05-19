package org.example;

import com.google.gson.Gson;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;

import java.lang.reflect.Field;
import java.util.*;
import java.util.regex.Pattern;

@Slf4j
public class SanitizeUtil {

    /**
     * Regex pattern that matches field/key names containing sensitive data terms in
     * both Turkish and English (case-insensitive). Applied with {@code find()} so any
     * field whose name contains one of these terms is treated as sensitive.
     *
     * Turkish terms: sifre/şifre (password), parola (password), kullanıcı (username),
     *   tckn/tc_no/kimlik (national ID), banka/hesap (bank account), kredi/kart (credit card),
     *   eposta/e-posta (e-mail), adres (address), telefon/gsm (phone), vergi (tax number)
     *
     * English terms: password/passwd/pass, username, ssn, api_key, auth_token,
     *   access_token, secret, private_key, token, bank_account, credit_card,
     *   cvv/cvc, pin, email, address, phone, tax
     */
    private static final Pattern SENSITIVE_KEY_PATTERN = Pattern.compile(
            "(?i)" +
            // Turkish
            "sifre|şifre|parola|kullan[iı]c[iı]|tckn|tc[_\\s]?no|kimlik|" +
            "banka|hesap|kredi|kart[\\s_]?no|eposta|e[_\\-]?posta|adres|telefon|gsm|vergi|" +
            // English
            "password|passwd|pass|username|ssn|" +
            "api[_\\-]?key|auth[_\\-]?token|access[_\\-]?token|" +
            "private[_\\-]?key|secret|token|bank[_\\-]?account|credit[_\\-]?card|" +
            "cvv|cvc|pin|email|address|phone|tax"
    );

    private static final Gson gson = new Gson();

    private static boolean isSensitive(String fieldName) {
        return SENSITIVE_KEY_PATTERN.matcher(fieldName).find();
    }

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
                    if (value instanceof Collection<?>) {
                        Collection<Object> sanitizedCollection = new ArrayList<>();
                        Collection<?> collection = (Collection<?>) value;
                        String fieldName = field.getName();
                        boolean anyFieldsMatch = isSensitive(fieldName);
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
                                sanitizedMap.put(key, isSensitive(strKey) ? "****" : val);
                            } else {
                                sanitizedMap.put(key, sanitize(key));
                            }
                        }
                        field.set(tObject, sanitizedMap);
                    } else if (isSensitive(field.getName())) {
                        field.set(tObject, "***");
                    } else {
                        field.set(tObject, value);
                    }
                }
            }
            jsonString = gson.toJson(tObject);
        } catch (Exception e) {
            log.error("Error during sanitization: {}", e.getMessage());
            jsonString = StringUtils.EMPTY;
        }
        return jsonString;
    }

}
