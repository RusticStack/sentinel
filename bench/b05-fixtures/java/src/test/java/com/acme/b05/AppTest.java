package com.acme.b05;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class AppTest {
    @Test
    void hello() {
        assertEquals("b05", new App().hello());
    }
}
