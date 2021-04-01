package com.project.app.ws.service.Impl;

import com.project.app.ws.io.entity.RoleEntity;
import com.project.app.ws.io.repositories.RoleRepository;
import com.project.app.ws.security.UserPrincipal;
import com.project.app.ws.shared.EmailSender;
import com.project.app.ws.shared.Utils;
import com.project.app.ws.shared.dto.AddressDTO;
import com.project.app.ws.shared.dto.UserDto;
import com.project.app.ws.ui.model.response.ErrorMessages;
import com.project.app.ws.exceptions.UserServiceException;
import com.project.app.ws.io.entity.PasswordResetTokenEntity;
import com.project.app.ws.io.repositories.PasswordResetTokenRepository;
import com.project.app.ws.io.repositories.UserRepository;
import com.project.app.ws.io.entity.UserEntity;
import com.project.app.ws.service.UserService;
import org.modelmapper.ModelMapper;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    UserRepository userRepository;

    @Autowired
    Utils utils;

    @Autowired
    PasswordResetTokenRepository passwordResetTokenRepository;

    @Autowired
    BCryptPasswordEncoder bCryptPasswordEncoder;

    @Autowired
    EmailSender emailSender;

    @Autowired
    RoleRepository roleRepository;

    @Override
    public UserDto createUser(UserDto user, boolean skipVerification) {

        if(userRepository.findByEmail(user.getEmail()) != null)
            throw new UserServiceException("Record already exists");

        for(int i=0; i < user.getAddresses().size(); i++) {
            AddressDTO address = user.getAddresses().get(i);
            address.setUserDetails(user);
            address.setAddressId(utils.generateAddressId(30));
            user.getAddresses().set(i,address);
        }

        ModelMapper modelMapper = new ModelMapper();
        UserEntity userEntity = modelMapper.map(user,UserEntity.class);

        String publicUserId = utils.generateUserId(30);
        userEntity.setUserId(publicUserId);
        userEntity.setEncryptedPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        if (skipVerification) {
            userEntity.setEmailVerificationToken(null);
            userEntity.setEmailVerificationStatus(true);
        } else {
            userEntity.setEmailVerificationToken(utils.generateEmailVerificationToken(publicUserId));
            userEntity.setEmailVerificationStatus(false);
        }


        Collection<RoleEntity> roleEntities = new HashSet<>();
        for(String role: user.getRoles()) {
            RoleEntity roleEntity = roleRepository.findByName(role);
            if(roleEntity !=null) { roleEntities.add(roleEntity); }
        }
        userEntity.setRoles(roleEntities);

        UserEntity storedUserDetails = userRepository.save(userEntity);

        UserDto returnValue = modelMapper.map(storedUserDetails,UserDto.class);
        if(!skipVerification) {
            try {
                emailSender.verifyEmail(returnValue);
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        }
        return returnValue;
    }

    @Override
    public UserDto getUser(String email) {
        UserDto returnValue = new UserDto();
        UserEntity userEntity = userRepository.findByEmail(email);
        if(userEntity == null) throw new UsernameNotFoundException(email);

        BeanUtils.copyProperties(userEntity,returnValue);
        return returnValue;
    }

    @Override
    public UserDto getUserByUserId(String userId) {
        UserEntity userEntity = userRepository.findByUserId(userId);
        if(userEntity == null) throw new UserServiceException(ErrorMessages.NO_RECORD_FOUND.getErrorMessage());
        ModelMapper modelMapper = new ModelMapper();
        return modelMapper.map(userEntity,UserDto.class);
    }

    @Override
    public UserDto updateUser(String userId,UserDto user) {
        ModelMapper modelMapper = new ModelMapper();

        UserEntity userEntity = userRepository.findByUserId(userId);
        if(userEntity == null) throw new UserServiceException(ErrorMessages.NO_RECORD_FOUND.getErrorMessage());

        userEntity.setFirstName(user.getFirstName());
        userEntity.setLastName(user.getLastName());

        UserEntity updatedUserDetails = userRepository.save(userEntity);
        return modelMapper.map(updatedUserDetails,UserDto.class);

    }

    @Override
    public void deleteUser(String userId) {
        UserEntity userEntity = userRepository.findByUserId(userId);
        if(userEntity == null) throw new UserServiceException(ErrorMessages.NO_RECORD_FOUND.getErrorMessage());

        userRepository.delete(userEntity);
    }

    @Override
    public List<UserDto> getUsers(int page, int limit) {

        if(page > 0) page++;

        ModelMapper modelMapper = new ModelMapper();

        List<UserDto> returnValue = new ArrayList<>();
        PageRequest pageableRequest = PageRequest.of(page,limit);
        Page<UserEntity> usersPage = userRepository.findAll(pageableRequest);
        List<UserEntity> users = usersPage.getContent();
        for(UserEntity userEntity: users) {
            UserDto userDto = modelMapper.map(userEntity,UserDto.class);

            returnValue.add(userDto);
        }
        return returnValue;
    }

    @Override
    public boolean verifyEmailToken(String token) {
        boolean returnValue = false;

        //Find user by token
        UserEntity userEntity = userRepository.findByEmailVerificationToken(token);

        if(userEntity != null) {
            boolean hasTokenExpired = Utils.hasTokenExpired(token);
            if(!hasTokenExpired) {
                userEntity.setEmailVerificationToken(null);
                userEntity.setEmailVerificationStatus(Boolean.TRUE);
                userRepository.save(userEntity);
                returnValue = true;
            }
        }

        return returnValue;
    }

    @Override
    public boolean requestPasswordReset(String email) {

        UserEntity userEntity = userRepository.findByEmail(email);

        if(userEntity == null) {
            return false;
        }

        String token = utils.generatePasswordResetToken(userEntity.getUserId());

        PasswordResetTokenEntity passwordResetEntity = new PasswordResetTokenEntity();
        passwordResetEntity.setToken(token);
        passwordResetEntity.setUserDetails(userEntity);
        passwordResetTokenRepository.save(passwordResetEntity);

        try {
            return emailSender.sendPasswordResetRequest(
                    userEntity.getFirstName(),
                    userEntity.getEmail(),
                    token
            );
        } catch (Exception ex) {
            throw new RuntimeException(ex);
        }
    }

    @Override
    public boolean resetPassword(String token, String password) {
        boolean returnValue = false;

        // Check if token has expired
        if(Utils.hasTokenExpired(token)) {
            return false;
        }

        PasswordResetTokenEntity passwordResetTokenEntity = passwordResetTokenRepository.findByToken(token);
        if(passwordResetTokenEntity == null) {
            return false;
        }

        // Create the new encrypted password
        String encodedPassword = bCryptPasswordEncoder.encode(password);

        // Save the new user details
        UserEntity userEntity = passwordResetTokenEntity.getUserDetails();
        userEntity.setEncryptedPassword(encodedPassword);
        UserEntity savedUserEntity = userRepository.save(userEntity);

        // Check if password was changed successfully
        if(savedUserEntity.getEncryptedPassword().equalsIgnoreCase(encodedPassword)) {
            returnValue = true;
        }

        //Remove reset token from database
        passwordResetTokenRepository.delete(passwordResetTokenEntity);

        return returnValue;
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        UserEntity userEntity = userRepository.findByEmail(email);
        if(userEntity == null) throw new UsernameNotFoundException(email);

//        return new User(
//                userEntity.getEmail(),
//                userEntity.getEncryptedPassword(),
//                userEntity.getEmailVerificationStatus(),
//                true,
//                true,
//                true,
//                new ArrayList<>()
//                );
        return new UserPrincipal(userEntity);
    }
}
