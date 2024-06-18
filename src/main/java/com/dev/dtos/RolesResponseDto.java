package com.dev.dtos;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class RolesResponseDto {
    private List<String> roles;
}
