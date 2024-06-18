package com.dev.service;

import com.dev.dtos.ApiResponseDto;
import com.dev.dtos.SignInRequestDto;
import com.dev.dtos.SignUpRequestDto;
import com.dev.exceptions.RoleNotFoundException;
import com.dev.exceptions.UserAlreadyExistsException;

public interface AuthService {
    ApiResponseDto<?> signUpUser(SignUpRequestDto signUpRequestDto) throws UserAlreadyExistsException, RoleNotFoundException;

    ApiResponseDto<?> signInUser(SignInRequestDto signInRequestDto);
}
