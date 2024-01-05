package tn.firas.jwtsecurity.config;

import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;
import static tn.firas.jwtsecurity.user.Permission.*;
import static tn.firas.jwtsecurity.user.Role.ADMIN;
import static tn.firas.jwtsecurity.user.Role.MANAGER;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfiguration {
    public static final String STRING = "/api/v1/management/**";
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    private final LogoutHandler logoutHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        //start configuring our HTTP security
        http
                .csrf(AbstractHttpConfigurer::disable)
                //choose and decide what are URLs and the pathways that we want to secure
            // but of course within every application we have always a whiteList(some endpoints they do not require
        //any authentication oir any tokens
                .authorizeHttpRequests(req ->
                //after authorizeHttpRequest we can call request matcher
                req.requestMatchers("/api/v1/auth/**")
                .permitAll()
                //after permitAll we add
//Secure Hole Managment endpoints
                .requestMatchers(STRING)
                .hasAnyRole(ADMIN.name(),MANAGER.name())//to be accessible by any user having the following roles


//Secure Management One By One
                .requestMatchers(HttpMethod.GET,"/api/v1/management/**")
                .hasAnyAuthority(ADMIN_READ.name(),MANAGER_READ.name())//te secure different endpoints
                .requestMatchers(HttpMethod.POST,"/api/v1/management/**")
                .hasAnyAuthority(ADMIN_WRITE.name(),MANAGER_WRITE.name())
//assigning Permission

//Secure Hole admin endpoints
                .requestMatchers("/api/v1/admin/**")
                .hasRole(ADMIN.name())

//Secure Admin endpoint
                .requestMatchers(HttpMethod.GET,"/api/v1/admin/**")
                .hasAuthority(ADMIN_READ.name()))
                //configure our sessionManagment
                .sessionManagement(session -> session.sessionCreationPolicy(STATELESS))

                //tell spring which authentication provider that i want to use
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)//i want to use the jwtFilter
                .logout(logout ->


                logout.logoutUrl("/api/v1/auth/logout")
                        .addLogoutHandler(logoutHandler)
                .logoutSuccessHandler(
                        (request, response, authentication) -> SecurityContextHolder.clearContext()
                )
                        );
        return http.build();

    }
}
