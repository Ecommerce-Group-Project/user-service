package com.ecommerce.userservice.dto;


import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class RegisterRequest {
    private String name;
    private String email;
    private String password;
}
