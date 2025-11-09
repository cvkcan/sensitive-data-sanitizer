package org.example;

import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Map;

@Getter
@Setter
public class User {
    private String username;
    private String password;
    private String email;
    private String ssn;
    private int age;
    private Long balance;
    private Map<String,String> preferences;
    private List<Credential> credentials;
    private List<String> ssns;
    private List<String> addresses;
}
