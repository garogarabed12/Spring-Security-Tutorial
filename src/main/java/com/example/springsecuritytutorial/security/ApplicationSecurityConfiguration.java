package com.example.springsecuritytutorial.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.util.Set;

import static com.example.springsecuritytutorial.security.ApplicationUserPermission.COURSE_WRITE;
import static com.example.springsecuritytutorial.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true
        /*securedEnabled = true,
        jsr250Enabled = true
        */ )
public class ApplicationSecurityConfiguration extends WebSecurityConfigurerAdapter {

  @Override
  protected void configure(HttpSecurity http) throws Exception {

    http.csrf().disable()
        .authorizeRequests()
        .antMatchers("/", "index", "/css/*", "/js/*")
        .permitAll()
        .antMatchers("/api/**")
        .hasRole(STUDENT.name())
        // See StudentManagementController.
        /*
        .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
        .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
        .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
        .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
        */
        .anyRequest()
        .authenticated()
        .and()
        .httpBasic();
  }

  @Bean
  protected PasswordEncoder encoder() {
    return new BCryptPasswordEncoder(10);
  }

  @Bean
  @Override
  protected UserDetailsService userDetailsService() {
    UserDetails garo = User.builder()
            .username("garo")
            .password(encoder().encode("round"))
            //.roles(ADMIN.name())
            .authorities(ADMIN.getGrantedAuthorities())
            .build();

    UserDetails haigaz = User.builder()
            .username("haigaz")
            .password(encoder().encode("round"))
            // .roles(STUDENT.name())
            .authorities(STUDENT.getGrantedAuthorities())
            .build();

    UserDetails alice = User.builder()
            .username("alice")
            .password(encoder().encode("round"))
            // .roles(ADMINTRAINEE.name())
            .authorities(ADMINTRAINEE.getGrantedAuthorities())
            .build();

    return new InMemoryUserDetailsManager(garo, haigaz, alice);
  }
}
