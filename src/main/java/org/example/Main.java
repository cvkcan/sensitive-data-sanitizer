package org.example;

import com.google.gson.Gson;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

public class Main {

    public static void main(String[] args) {
        Logger LOGGER = Logger.getLogger(Main.class.getName());
        Gson gson = new Gson();

        User user = new User();
        user.setUsername("can");
        user.setPassword("123456");
        user.setEmail("can@example.com");
        user.setSsn("123-45-6789");
        user.setAge(27);
        user.setBalance(15000L);

        Map<String, String> preferences = new HashMap<>();
        preferences.put("theme", "dark");
        preferences.put("language", "tr");
        preferences.put("notification", "enabled");
        preferences.put("apiKey", "ABCD-1234-SECRET");
        preferences.put("authToken", "XYZ987TOKEN");
        user.setPreferences(preferences);

        List<Credential> credentialList = new ArrayList<>();
        Credential credential = new Credential();
        credential.setSsn("987-65-4320");
        credential.setCustomerId("CUST-001");
        credentialList.add(credential);
        user.setCredentials(credentialList);

        List<String> ssns = new ArrayList<>();
        ssns.add("111-22-3333");
        ssns.add("444-55-6666");
        user.setSsns(ssns);

        List<String> addresses = new ArrayList<>();
        addresses.add("123 Main St, Anytown, USA");
        addresses.add("456 Oak St, Othertown, USA");
        user.setAddresses(addresses);

        LOGGER.info("Before Sanitization:\n" + gson.toJson(user));
        String jsonOjbect = SanitizeUtil.toJson(user);
        LOGGER.info("After Sanitization:\n" + jsonOjbect);
    }
}