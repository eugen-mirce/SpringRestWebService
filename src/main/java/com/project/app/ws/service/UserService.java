package com.project.app.ws.service;

import com.project.app.ws.shared.dto.UserDto;
import org.springframework.security.core.userdetails.UserDetailsService;

import java.util.List;

public interface UserService extends UserDetailsService {
    UserDto createUser(UserDto user,boolean skipVerification);
    UserDto getUser(String email);
    UserDto getUserByUserId(String userId);
    UserDto updateUser(String userId,UserDto userDto);
    void deleteUser(String userId);
    List<UserDto> getUsers(int page, int limit);
    boolean verifyEmailToken(String token);
    boolean requestPasswordReset(String email);
    boolean resetPassword(String token, String password);
}
