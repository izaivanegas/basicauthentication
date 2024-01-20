package com.example.basicauthentication.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;


@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {


    @Bean
    public PasswordEncoder getPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public UserDetailsService userDetailsService(PasswordEncoder encoder){
        UserDetails admin = User.withUsername("izai").password(encoder.encode("vanegas"))
                .roles("ADMIN","USER").build();
        UserDetails user = User.withUsername("alejandra")
                .password(encoder.encode("barragan"))
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(admin,user);
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity  http  )throws Exception{

        return http.csrf().disable()
                .authorizeHttpRequests().requestMatchers("/auth/welcome").permitAll()
                .and().authorizeHttpRequests().requestMatchers("/auth/user/**").authenticated()
                .and().authorizeHttpRequests().requestMatchers("/auth/admin/**").authenticated()
                .and().formLogin()
                .and().build();


    }



}
