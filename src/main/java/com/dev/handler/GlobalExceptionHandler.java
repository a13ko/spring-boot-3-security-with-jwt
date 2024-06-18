package com.dev.handler;

import com.dev.dtos.ApiResponseDto;
import com.dev.exceptions.RoleNotFoundException;
import com.dev.exceptions.UserAlreadyExistsException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.ArrayList;
import java.util.List;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponseDto<List<String>>> methodArgumentNotValidExceptionHandler(MethodArgumentNotValidException exception) {
        List<String> errorMessage = new ArrayList<>();
        exception.getBindingResult().getFieldErrors().forEach(error -> errorMessage.add(error.getDefaultMessage()));

        return ResponseEntity
                .badRequest()
                .body(ApiResponseDto.<List<String>>builder()
                        .isSuccess(false)
                        .message("Registration Failed: Please provide valid data.")
                        .response(errorMessage)
                        .build());
    }

    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<ApiResponseDto<Void>> userAlreadyExistsExceptionHandler(UserAlreadyExistsException exception) {
        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(ApiResponseDto.<Void>builder()
                        .isSuccess(false)
                        .message(exception.getMessage())
                        .build());
    }

    @ExceptionHandler(RoleNotFoundException.class)
    public ResponseEntity<ApiResponseDto<Void>> roleNotFoundExceptionHandler(RoleNotFoundException exception) {
        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(ApiResponseDto.<Void>builder()
                        .isSuccess(false)
                        .message(exception.getMessage())
                        .build());
    }

}
