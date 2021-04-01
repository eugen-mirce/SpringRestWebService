package com.project.app.ws;

import com.project.app.ws.io.entity.AuthorityEntity;
import com.project.app.ws.io.entity.RoleEntity;
import com.project.app.ws.io.entity.UserEntity;
import com.project.app.ws.io.repositories.AuthorityRepository;
import com.project.app.ws.io.repositories.RoleRepository;
import com.project.app.ws.io.repositories.UserRepository;
import com.project.app.ws.shared.Roles;
import com.project.app.ws.shared.Utils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.Collection;

@Component
public class InitialUsersSetup {
    @Autowired
    AuthorityRepository authorityRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    Utils utils;

    @Autowired
    UserRepository userRepository;

    @EventListener
    @Transactional
    public void onApplicationEvent(ApplicationReadyEvent event) {
        System.out.println("From Application ready event...");

        AuthorityEntity readAuthority = createAuthority("READ_AUTHORITY");
        AuthorityEntity writeAuthority = createAuthority("WRITE_AUTHORITY");
        AuthorityEntity deleteAuthority = createAuthority("DELETE_AUTHORITY");

        createRole(Roles.ROLE_USER.name(), Arrays.asList(readAuthority,writeAuthority));
        RoleEntity roleAdmin = createRole(Roles.ROLE_ADMIN.name(), Arrays.asList(readAuthority,writeAuthority, deleteAuthority));

        if(roleAdmin == null) return;

        UserEntity adminUser = new UserEntity();
        adminUser.setFirstName("Eugen");
        adminUser.setLastName("Mirce");
        adminUser.setEmail("eugen.el92@hotmail.com");
        adminUser.setEmailVerificationStatus(true);
        adminUser.setUserId(utils.generateUserId(30));
        adminUser.setEncryptedPassword(bCryptPasswordEncoder.encode("12345678"));
        adminUser.setRoles(Arrays.asList(roleAdmin));

        UserEntity storedUserDetails = userRepository.findByEmail("eugen.el92@hotmail.com");
        if (storedUserDetails == null) {
            userRepository.save(adminUser);
        }

    }

    @Transactional
    private AuthorityEntity createAuthority(String name) {

        AuthorityEntity authority = authorityRepository.findByName(name);
        if (authority == null) {
            authority = new AuthorityEntity(name);
            authorityRepository.save(authority);
        }
        return authority;
    }

    @Transactional
    private RoleEntity createRole(
            String name, Collection<AuthorityEntity> authorities) {

        RoleEntity role = roleRepository.findByName(name);
        if (role == null) {
            role = new RoleEntity(name);
            role.setAuthorities(authorities);
            roleRepository.save(role);
        }
        return role;
    }
}
