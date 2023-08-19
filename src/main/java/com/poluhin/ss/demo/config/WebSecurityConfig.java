package com.poluhin.ss.demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.*;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

import static org.springframework.http.HttpMethod.GET;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {
    @Autowired
    private DataSource dataSource;

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.jdbcAuthentication().dataSource(dataSource).withDefaultSchema()
                .withUser(User.builder()
                        .username("user")
                        .password(passwordEncoder().encode("password"))
                        .roles("USER")
                        .build())
                .withUser(User.builder()
                        .username("admin")
                        .password(passwordEncoder().encode("root"))
                        .roles("USER")
                        .build())
                ;
    }

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http, DefaultAuthentificationEntryPoint entryPoint) throws Exception {
        return http.authorizeHttpRequests(customizer ->
                customizer
                        .requestMatchers(GET, "/resource/**").hasAnyRole("USER", "ADMIN")
                        .requestMatchers("/resource").hasAnyRole("ADMIN")
                        .anyRequest().authenticated())
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(configurer ->
                        configurer.authenticationEntryPoint(entryPoint))
                .build();
    }

    @Bean
    public static PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
