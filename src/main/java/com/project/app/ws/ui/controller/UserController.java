package com.project.app.ws.ui.controller;

import com.project.app.ws.shared.Roles;
import com.project.app.ws.shared.dto.AddressDTO;
import com.project.app.ws.shared.dto.UserDto;
import com.project.app.ws.ui.model.request.PasswordResetModel;
import com.project.app.ws.ui.model.request.PasswordResetRequestModel;
import com.project.app.ws.ui.model.request.UserDetailsRequestModel;
import com.project.app.ws.ui.model.response.*;
import com.project.app.ws.exceptions.UserServiceException;
import com.project.app.ws.service.AddressService;
import com.project.app.ws.service.UserService;
import org.modelmapper.ModelMapper;
import org.modelmapper.TypeToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.hateoas.CollectionModel;
import org.springframework.hateoas.EntityModel;
import org.springframework.hateoas.Link;
import org.springframework.http.MediaType;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.linkTo;
import static org.springframework.hateoas.server.mvc.WebMvcLinkBuilder.methodOn;

@RestController
@RequestMapping("users")        //http://localhost:8080/users
public class UserController {
    private boolean skipVerification = true;

    @Autowired
    UserService userService;

    @Autowired
    AddressService addressService;

    @PostAuthorize("hasRole('ROLE_ADMIN') or returnObject.userId == principal.userId")
    @GetMapping(
            path = "/{userId}",
            produces = {MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE}
            )
    public UserRest getUser(@PathVariable String userId) {

        UserDto userDto = userService.getUserByUserId(userId);
        ModelMapper modelMapper = new ModelMapper();

        return modelMapper.map(userDto,UserRest.class);
    }

    @PostMapping(
            consumes = {MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE},
            produces = {MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE}
            )
    public UserRest createUser(@RequestBody UserDetailsRequestModel userDetails) throws UserServiceException {

        if(userDetails.getFirstName().isEmpty()) throw new UserServiceException(ErrorMessages.MISSING_REQUIRED_FIELD.getErrorMessage());

        ModelMapper modelMapper = new ModelMapper();
        UserDto userDto = modelMapper.map(userDetails,UserDto.class);
        userDto.setRoles(new HashSet<>(Arrays.asList(Roles.ROLE_USER.name())));

        UserDto createdUser = userService.createUser(userDto,skipVerification);

        return modelMapper.map(createdUser,UserRest.class);

    }
    @PutMapping(
            path = "/{userId}",
            consumes = {MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE},
            produces = {MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE}
            )
    public UserRest updateUser(@PathVariable String userId, @RequestBody UserDetailsRequestModel userDetails) {
        ModelMapper modelMapper = new ModelMapper();

        UserDto userDto = modelMapper.map(userDetails, UserDto.class);

        UserDto createdUser = userService.updateUser(userId,userDto);
        return modelMapper.map(createdUser, UserRest.class);
    }
    @PreAuthorize("hasRole('ROLE_ADMIN') or #id == principal.userId")
    @DeleteMapping(
            path = "/{userId}",
            produces = {MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE}
            )
    public OperationStatusModel deleteUser(@PathVariable String userId) {
        OperationStatusModel returnValue = new OperationStatusModel();
        returnValue.setOperationName(RequestOperationName.DELETE.name());
        userService.deleteUser(userId);
        returnValue.setOperationResult(RequestOperationStatus.SUCCESS.name());

        return returnValue;
    }

    @GetMapping(produces = {MediaType.APPLICATION_XML_VALUE, MediaType.APPLICATION_JSON_VALUE })
    public List<UserRest> getUsers(@RequestParam(value="page", defaultValue = "1") int page, @RequestParam(value = "limit", defaultValue = "10") int limit) {
        List<UserRest> returnValue = new ArrayList<>();
        List<UserDto> users = userService.getUsers(page,limit);
        ModelMapper modelMapper = new ModelMapper();
        for(UserDto userDto : users) {
            UserRest userModel = modelMapper.map(userDto,UserRest.class);
            returnValue.add(userModel);
        }
        return returnValue;
    }

    //http://localhost:8080/users/{id}/addresses
    @GetMapping(
            path = "/{userId}/addresses",
            produces = {MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE, "application/hal+json" }
    )
    public CollectionModel<AddressesRest> getUserAddresses(@PathVariable String userId) {
        List<AddressesRest> addressesListRestModel = new ArrayList<>();
        List<AddressDTO> addressDTO = addressService.getAddresses(userId);

        if(addressDTO != null && !addressDTO.isEmpty()) {
            Type listType = new TypeToken<List<AddressesRest>>() {}.getType();
            addressesListRestModel = new ModelMapper().map(addressDTO,listType);

            for(AddressesRest addressesRest: addressesListRestModel) {
                Link addressLink = linkTo(methodOn(UserController.class).getUserAddress(userId,addressesRest.getAddressId())).withSelfRel();
                Link userLink = linkTo(methodOn(UserController.class).getUser(userId)).withRel("user");

                addressesRest.add(addressLink);
                addressesRest.add(userLink);
            }
        }
        return new CollectionModel<>(addressesListRestModel);
    }

    //http://localhost:8080/users/{id}/addresses/{aid}
    @GetMapping(
            path = "/{userId}/addresses/{addressId}",
            produces = {MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE, "application/hal+json" }
    )
    public EntityModel<AddressesRest> getUserAddress(@PathVariable String userId,
                                                    @PathVariable String addressId) {
        AddressDTO addressDTO = addressService.getAddress(addressId);
        AddressesRest addressesRestModel = new ModelMapper().map(addressDTO,AddressesRest.class);

        Link addressLink = linkTo(methodOn(UserController.class).getUserAddress(userId,addressId)).withSelfRel();
        Link userLink = linkTo(methodOn(UserController.class).getUser(userId)).withRel("user");
        Link addressesLink = linkTo(methodOn(UserController.class).getUserAddresses(userId)).withRel("addresses");

        addressesRestModel.add(addressLink);
        addressesRestModel.add(userLink);
        addressesRestModel.add(addressesLink);

        return new EntityModel<>(addressesRestModel);
    }
    @GetMapping(
            path = "/email-verification",
            produces = {MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE}
    )
    public OperationStatusModel verifyEmailToken(@RequestParam(value = "token") String token) {
        OperationStatusModel returnValue = new OperationStatusModel();
        returnValue.setOperationName(RequestOperationName.VERIFY_EMAIL.name());

        boolean isVerified = userService.verifyEmailToken(token);

        if(isVerified) {
            returnValue.setOperationResult(RequestOperationStatus.SUCCESS.name());
        } else {
            returnValue.setOperationResult(RequestOperationStatus.ERROR.name());
        }

        return returnValue;
    }

    /*
     * http://localhost:8080/app/users/password-reset
     */
    @PostMapping(
            path = "/password-reset-request",
            produces = {MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE},
            consumes = {MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE}
    )
    public OperationStatusModel requestReset(@RequestBody PasswordResetRequestModel passwordResetRequestModel) {
        OperationStatusModel returnValue = new OperationStatusModel();

        boolean operationResult = userService.requestPasswordReset(passwordResetRequestModel.getEmail());

        returnValue.setOperationName(RequestOperationName.REQUEST_PASSWORD_RESET.name());
        returnValue.setOperationResult(RequestOperationStatus.ERROR.name());

        if(operationResult == true) {
            returnValue.setOperationResult(RequestOperationStatus.SUCCESS.name());
        }
        return returnValue;
    }
    @PostMapping(
            path = "/password-reset",
            consumes = {MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_XML_VALUE}
    )
    public OperationStatusModel resetPassword(@RequestBody PasswordResetModel passwordResetModel) {
        OperationStatusModel returnValue = new OperationStatusModel();

        boolean operationResult = userService.resetPassword(
                passwordResetModel.getToken(),
                passwordResetModel.getPassword());

        returnValue.setOperationName(RequestOperationName.PASSWORD_RESET.name());
        returnValue.setOperationResult(RequestOperationStatus.ERROR.name());

        if(operationResult == true) {
            returnValue.setOperationResult(RequestOperationStatus.SUCCESS.name());
        }
        return returnValue;
    }
}
