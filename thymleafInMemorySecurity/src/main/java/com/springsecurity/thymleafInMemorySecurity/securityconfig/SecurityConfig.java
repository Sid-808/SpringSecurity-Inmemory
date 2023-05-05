package com.springsecurity.thymleafInMemorySecurity.securityconfig;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    //{noop} is used before password if we dont want to encode password else: it will throw
    @Bean
    protected InMemoryUserDetailsManager configAuthentication(){
        List<UserDetails> users = new ArrayList<>();
        List<GrantedAuthority> adminAuthority = new ArrayList<>();
        adminAuthority.add(new SimpleGrantedAuthority("ADMIN"));
        UserDetails admin = new User("Ram","{noop}ram123",adminAuthority);
        users.add(admin);

        List<GrantedAuthority> employeeAuthority = new ArrayList<>();
        employeeAuthority.add(new SimpleGrantedAuthority("EMPLOYEE"));
        UserDetails employee = new User("Shyam","{noop}shyam123",employeeAuthority);
        users.add(employee);

        List<GrantedAuthority> managerAuthority = new ArrayList<>();
        managerAuthority.add(new SimpleGrantedAuthority("MANAGER"));
        UserDetails manager = new User("Mohan","{noop}mohan123",managerAuthority);
        users.add(manager);

        return new InMemoryUserDetailsManager(users);
    }

    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
       http.authorizeRequests()
               .requestMatchers("/home").permitAll()
               .requestMatchers("/welcome").authenticated()
               .requestMatchers("/admin").hasAuthority("ADMIN")
               .requestMatchers("/emp").hasAuthority("EMPLOYEE")
               .requestMatchers("/mgr").hasAuthority("MANAGER")
               .requestMatchers("/common").hasAnyAuthority("EMPLOYEE","MANAGER","ADMIN")

               //anyother request than metioned above
               .anyRequest().authenticated()

               //LogIN and LogOut settings
               .and()
               .formLogin()
               .defaultSuccessUrl("/welcome",true)

               .and()
               .logout()
               .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))

               //Exception details
               .and()
               .exceptionHandling()
               .accessDeniedPage("/accessDenied");

                return http.build();
    }
}
