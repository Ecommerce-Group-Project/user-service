package com.ecommerce.userservice.dto;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class ProfileResponse {
    private String email;
    private String role;
}
