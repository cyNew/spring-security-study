package dev.zcy.springstarter.entity;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class RegistryRequest {
    private String username;
    private String email;
    private String password;

}
