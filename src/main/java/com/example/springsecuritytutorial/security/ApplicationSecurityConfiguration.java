package com.example.springsecuritytutorial.security;

import com.example.springsecuritytutorial.auth.ApplicationUserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import static com.example.springsecuritytutorial.security.ApplicationUserRole.STUDENT;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true/*securedEnabled = true,
        jsr250Enabled = true
        */ )
public class ApplicationSecurityConfiguration extends WebSecurityConfigurerAdapter {

  private final ApplicationUserService applicationUserService;

  public ApplicationSecurityConfiguration(ApplicationUserService applicationUserService) {
    this.applicationUserService = applicationUserService;
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {

    http.csrf()
        .disable()
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

  //From a DB
  @Bean
  public DaoAuthenticationProvider daoAuthenticationProvider() {
    DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
    provider.setPasswordEncoder(encoder());
    provider.setUserDetailsService(applicationUserService);
    return provider;
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth.authenticationProvider(daoAuthenticationProvider());
  }

  // In Memory
  /*@Bean
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
  }*/
}
