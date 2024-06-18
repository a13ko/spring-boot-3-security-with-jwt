package com.dev.controller;

import com.dev.dtos.RolesResponseDto;
import com.dev.service.AuthService;
import com.dev.dtos.ApiResponseDto;
import com.dev.dtos.SignInRequestDto;
import com.dev.dtos.SignUpRequestDto;
import com.dev.exceptions.RoleNotFoundException;
import com.dev.exceptions.UserAlreadyExistsException;
import com.dev.security.jwt.JwtUtils;
import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final JwtUtils jwtUtils;

    @PostMapping("/signup")
    public ApiResponseDto<?> signUpUser(@RequestBody @Valid SignUpRequestDto signUpRequestDto)
            throws UserAlreadyExistsException, RoleNotFoundException {
        return authService.signUpUser(signUpRequestDto);
    }

    @PostMapping("/signin")
    public ApiResponseDto<?> signInUser(@RequestBody @Valid SignInRequestDto signInRequestDto){
        return authService.signInUser(signInRequestDto);
    }

    @GetMapping("/roles")
    public RolesResponseDto getUserRolesFromJwtToken(@RequestHeader("Authorization") String tokenHeader) {
        String token = tokenHeader.substring(7);
        List<String> roles = jwtUtils.getUserRolesFromJwtToken(token);
        return new RolesResponseDto(roles);
    }

}
