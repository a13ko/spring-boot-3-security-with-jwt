package com.dev.controller;

import com.dev.dtos.ApiResponseDto;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/test")
public class TestController {

    @GetMapping("/user")
    @PreAuthorize("hasRole('ROLE_USER')")
    public ResponseEntity<ApiResponseDto<String>> getUserDashboard() {
        ApiResponseDto<String> response = ApiResponseDto.<String>builder()
                .isSuccess(true)
                .message("User dashboard!")
                .build();
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<ApiResponseDto<String>> getAdminDashboard() {
        ApiResponseDto<String> response = ApiResponseDto.<String>builder()
                .isSuccess(true)
                .message("Admin dashboard!")
                .build();
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @GetMapping("/superAdmin")
    @PreAuthorize("hasRole('ROLE_SUPER_ADMIN')")
    public ResponseEntity<ApiResponseDto<String>> getSuperAdminDashboard() {
        ApiResponseDto<String> response = ApiResponseDto.<String>builder()
                .isSuccess(true)
                .message("Super Admin dashboard!")
                .build();
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @GetMapping("/AdminOrSuperAdmin")
    @PreAuthorize("hasRole('ROLE_ADMIN') or hasRole('ROLE_SUPER_ADMIN')")
    public ResponseEntity<ApiResponseDto<String>> getAdminOrSuperAdminContent() {
        ApiResponseDto<String> response = ApiResponseDto.<String>builder()
                .isSuccess(true)
                .message("Admin or Super Admin Content!")
                .build();
        return new ResponseEntity<>(response, HttpStatus.OK);
    }
}
