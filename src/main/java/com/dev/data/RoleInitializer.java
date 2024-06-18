package com.dev.data;

import com.dev.models.ERole;
import com.dev.models.Role;
import com.dev.repository.RoleRepository;
import java.util.Arrays;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
public class RoleInitializer implements CommandLineRunner {
    private final RoleRepository roleRepository;

    @Override
    @Transactional
    public void run(String... args) {
        List<ERole> roles = Arrays.stream(ERole.values()).toList();

        for (ERole erole : roles) {
            if (roleRepository.findByName(erole) == null) {
                roleRepository.save(new Role(erole));
            }
        }
    }
}