package com.project.app.ws;

import com.project.app.ws.shared.Utils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
@SpringBootTest
public class UtilsTest {

    @Autowired
    Utils utils;

    @BeforeEach
    void setUp() throws Exception {

    }

    @Test
    final void testGenerateUserId() {
        String userId = utils.generateUserId(30);
        String userId2 = utils.generateUserId(30);
        assertNotNull(userId);
        assertTrue(userId.length() == 30);
        assertTrue(!userId.equalsIgnoreCase(userId2));
    }
    @Test
    final void testHasTokenNotExpired() {
        String token = utils.generateEmailVerificationToken("gdfgasd335");
        assertNotNull(token);

        boolean hasTokenExpired = Utils.hasTokenExpired(token);
        assertFalse(hasTokenExpired);
    }
    @Test
    @Disabled //TODO Remove after a few days to check if token is expired
    final void testHasTokenExpired() {
        String expiredToken = "eyJhbGciOiJIUzUxMiJ9.eyJzdWIiOiIzZXVnZW4uZWw5MkBob3RtYWlsLmNvbSIsImV4cCI6MTYxNzYyNDkzMH0.hWxuk5RwSRJV8xS2lCc3fFvH-AxtveZsxIqBurXqaWwIEXSStfjS5QOGU-RCDg9FZRtGVkw26eqYKtndXjDgAA";
        boolean hasTokenExpired = Utils.hasTokenExpired(expiredToken);

        assertTrue(hasTokenExpired);
    }
}
