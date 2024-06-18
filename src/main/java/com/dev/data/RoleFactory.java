package com.dev.data;

import com.dev.exceptions.RoleNotFoundException;
import com.dev.models.ERole;
import com.dev.models.Role;
import com.dev.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class RoleFactory {
    private final RoleRepository roleRepository;

    public Role getInstance(String role) throws RoleNotFoundException {
        switch (role) {
            case "admin" -> {
                return roleRepository.findByName(ERole.ROLE_ADMIN);
            }
            case "user" -> {
                return roleRepository.findByName(ERole.ROLE_USER);
            }
            case "super_admin" -> {
                return roleRepository.findByName(ERole.ROLE_SUPER_ADMIN);
            }
            case "chef" -> {
                return roleRepository.findByName(ERole.ROLE_CHEF);
            }
            case "courier" -> {
                return roleRepository.findByName(ERole.ROLE_COURIER);
            }
            default -> throw new RoleNotFoundException("No role found for " +  role);
        }
    }

}
