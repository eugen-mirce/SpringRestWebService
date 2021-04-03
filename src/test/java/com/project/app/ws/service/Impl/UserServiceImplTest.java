package com.project.app.ws.service.Impl;

import com.project.app.ws.shared.EmailSender;
import com.project.app.ws.shared.Utils;
import com.project.app.ws.shared.dto.AddressDTO;
import com.project.app.ws.shared.dto.UserDto;
import com.project.app.ws.exceptions.UserServiceException;
import com.project.app.ws.io.entity.AddressEntity;
import com.project.app.ws.io.entity.UserEntity;
import com.project.app.ws.io.repositories.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.modelmapper.ModelMapper;
import org.modelmapper.TypeToken;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeMessage;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

public class UserServiceImplTest {
    @InjectMocks
    UserServiceImpl userService;

    @Mock
    UserRepository userRepository;

    @Mock
    Utils utils;

    @Mock
    BCryptPasswordEncoder bCryptPasswordEncoder;

    @Mock
    JavaMailSender javaMailSender;

    @Mock
    EmailSender emailSender;

    String userId = "asdfdsfsd";
    String encryptedPassword = "12345678";
    UserEntity userEntity;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);

        userEntity = new UserEntity();
        userEntity.setId(1L);
        userEntity.setUserId(userId);
        userEntity.setEmail("username@domain.tld");
        userEntity.setFirstName("FirstName");
        userEntity.setLastName("LastName");
        userEntity.setEncryptedPassword(encryptedPassword);
        userEntity.setEmailVerificationToken("fdgdfgdfgdfg");
        userEntity.setAddresses(getAddressEntity());
    }
    @Test
    final void testGetUser() {
        when(userRepository.findByEmail(anyString())).thenReturn(userEntity);

        UserDto userDto = userService.getUser("test@test.com");
        assertNotNull(userDto);
        assertEquals("FirstName",userDto.getFirstName());
    }

    @Test
    final void testGetUser_UsernameNotFoundException() {
        when(userRepository.findByEmail(anyString())).thenReturn(null);
        assertThrows(UsernameNotFoundException.class,
                () -> {
                    userService.getUser("test@test.com");
                });
    }

    @Test
    final void createUser_CreateUserServiceException() {
        when(userRepository.findByEmail(anyString())).thenReturn(userEntity);

        UserDto userDto = new UserDto();
        userDto.setFirstName("FirstName");
        userDto.setLastName("LastName");
        userDto.setEmail("username@domain.tld");
        userDto.setPassword("12345678");
        userDto.setAddresses(getAddresses());

        assertThrows(UserServiceException.class,
                () -> {
                    userService.createUser(userDto,true);
                });
    }

    @Test
    final void testCreateUser() throws UnsupportedEncodingException, MessagingException {

        when(userRepository.findByEmail(anyString())).thenReturn(null);
        when(utils.generateAddressId(anyInt())).thenReturn("affdgfdgaafdgfd");
        when(utils.generateUserId(anyInt())).thenReturn(userId);
        when(bCryptPasswordEncoder.encode(anyString())).thenReturn(encryptedPassword);
        when(userRepository.save(any(UserEntity.class))).thenReturn(userEntity);
        when(javaMailSender.createMimeMessage()).thenReturn(new MimeMessage((Session) null));
        Mockito.doNothing().when(emailSender).verifyEmail(any(UserDto.class));

        UserDto userDto = new UserDto();
        userDto.setFirstName("FirstName");
        userDto.setLastName("LastName");
        userDto.setEmail("username@domain.tld");
        userDto.setPassword("12345678");
        userDto.setAddresses(getAddresses());

        UserDto storedUserDetails = userService.createUser(userDto,true);

        assertNotNull(storedUserDetails);
        assertEquals(userEntity.getFirstName(),storedUserDetails.getFirstName());
        assertEquals(userEntity.getLastName(),storedUserDetails.getLastName());
        assertEquals(userEntity.getEmail(),storedUserDetails.getEmail());
        assertEquals(userEntity.getEncryptedPassword(),storedUserDetails.getEncryptedPassword());
        assertEquals(userEntity.getAddresses().size(),storedUserDetails.getAddresses().size());
        assertEquals(userEntity.getUserId(),storedUserDetails.getUserId());
        assertEquals(userEntity.getEmailVerificationToken(),storedUserDetails.getEmailVerificationToken());
        verify(utils,times(2)).generateAddressId(30);
        verify(bCryptPasswordEncoder,times(1)).encode("12345678");
        verify(userRepository,times(1)).save(any(UserEntity.class));
    }

    private List<AddressDTO> getAddresses() {
        AddressDTO shippingAddressDTO = new AddressDTO();
        shippingAddressDTO.setCity("Tirana");
        shippingAddressDTO.setCountry("Albania");
        shippingAddressDTO.setStreetName("Ali Demi");
        shippingAddressDTO.setPostalCode("1001");
        shippingAddressDTO.setType("shipping");

        AddressDTO billingAddressDTO = new AddressDTO();
        billingAddressDTO.setCity("Tirana");
        billingAddressDTO.setCountry("Albania");
        billingAddressDTO.setStreetName("Ali Demi");
        billingAddressDTO.setPostalCode("1001");
        billingAddressDTO.setType("billing");

        List<AddressDTO> addressesList= new ArrayList<>();
        addressesList.add(shippingAddressDTO);
        addressesList.add(billingAddressDTO);
        return addressesList;
    }

    private List<AddressEntity> getAddressEntity() {
        List<AddressDTO> addressesList = getAddresses();

        Type listType = new TypeToken<List<AddressEntity>>() {}.getType();

        return new ModelMapper().map(addressesList,listType);

    }
}
