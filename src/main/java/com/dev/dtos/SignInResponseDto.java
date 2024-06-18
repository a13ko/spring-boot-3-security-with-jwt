package com.dev.dtos;

import java.util.List;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class SignInResponseDto {
    private String token;
    private Long id;
    private String username;
    private String email;
    private List<String> roles;
}
