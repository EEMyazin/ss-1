package com.poluhin.ss.demo.controller;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultHandlers;

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
    void shouldReturnJwtTokenForUser() throws Exception {
        mockMvc.perform(post("/authenticate")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {
                            "login": "user",
                            "password": "password"
                        }
                        """))
                .andExpect(status().isOk());
    }

    @Test
    void shouldReturnJwtTokenForAdmin() throws Exception {
        mockMvc.perform(post("/authenticate")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {
                            "login": "admin",
                            "password": "root"
                        }
                        """))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(status().isOk());
    }

    @Test
    void shouldNotReturnJwtTokenForFake() throws Exception {
        mockMvc.perform(post("/authenticate")
                .contentType(MediaType.APPLICATION_JSON)
                .content("""
                        {
                            "login": "fake",
                            "password": "fake"
                        }
                        """))
                .andDo(MockMvcResultHandlers.print())
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldUserJwtGetReturnOk() throws Exception {
        mockMvc.perform(get("/resource/1")
                .header("authorization", "Bearer " + getAccessToken("""
                    {
                        "login": "user",
                        "password": "password"
                    }
                    """)))
                .andExpect(status().isOk());
    }

    @Test
    void shouldUserJwtPostReturnForbidden() throws Exception {
        mockMvc.perform(post("/resource")
                        .header("authorization", "Bearer " + getAccessToken("""
                            {
                                "login": "user",
                                "password": "password"
                            }
                            """)))
                .andExpect(status().isForbidden());
    }

    @Test
    void shouldAdminGetReturnOk() throws Exception {
        mockMvc.perform(
                        get("/resource/1")
                                .header("authorization", "Bearer " + getAccessToken("""
                                    {
                                        "login": "user",
                                        "password": "password"
                                    }
                                    """)))
                .andExpect(status().isOk());
    }

    @Test
    void shouldAdminPostReturnOk() throws Exception {
        mockMvc.perform(
                        post("/resource")
                                .header("authorization", "Bearer " + getAccessToken("""
                                    {
                                        "login": "user",
                                        "password": "password"
                                    }
                                    """)))
                .andExpect(status().isForbidden());
    }

    private String getAccessToken(String content) throws Exception{
        MvcResult mvcResult = mockMvc.perform(post("/authenticate")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(content))
                .andReturn();

        return new JSONObject(mvcResult.getResponse().getContentAsString()).optString("accessToken");
    }
}
