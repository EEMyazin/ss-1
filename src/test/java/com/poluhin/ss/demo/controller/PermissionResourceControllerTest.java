package com.poluhin.ss.demo.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class PermissionResourceControllerTest {
    @Autowired
    private MockMvc mockMvc;

    @Test
    void shouldUserGetReturnOk() throws Exception {
        mockMvc.perform(get("/resource/1")
                    .with(httpBasic("user", "password")))
                .andExpect(status().isOk());
    }

    @Test
    void shouldUserPostReturnForbidden() throws Exception {
        mockMvc.perform(post("/resource")
                    .with(httpBasic("user", "password")))
                .andExpect(status().isForbidden());
    }

    @Test
    void shouldAdminGetReturnOk() throws Exception {
        mockMvc.perform(get("/resource/1")
                    .with(httpBasic("admin", "root")))
                .andExpect(status().isOk());
    }

    @Test
    void shouldAdminPostReturnOk() throws Exception {
        mockMvc.perform(post("/resource")
                    .with(httpBasic("admin", "root")))
                .andExpect(status().isForbidden());
    }

    @Test
    void shouldFakeGetReturnUnauthorized() throws Exception {
        mockMvc.perform(get("/resource/1")
                    .with(httpBasic("fake", "fake")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldFakePostReturnUnauthorized() throws Exception {
        mockMvc.perform(post("/resource")
                    .with(httpBasic("fake", "fake")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldAnonymousGetReturnUnauthorized() throws Exception {
        mockMvc.perform(get("/resource"))
                .andExpect(status().isUnauthorized());
    }
}
