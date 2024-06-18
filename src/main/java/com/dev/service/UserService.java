package com.dev.service;

import com.dev.models.User;
import org.springframework.stereotype.Service;

@Service
public interface UserService {

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    void save(User user);
}
