package com.example.springsecuritytutorial.auth;

import com.google.common.collect.Lists;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.example.springsecuritytutorial.security.ApplicationUserRole.*;

@Repository("Fake repo")
public class FakeApplicationUserDaoService implements ApplicationUserDao {

  PasswordEncoder passwordEncoder = new BCryptPasswordEncoder(10);

  @Override
  public Optional<ApplicationUser> selectApplicationUserByUserName(String username) {
    return getApplicationUsers().stream()
            .filter(applicationUser -> username.equals(applicationUser.getUsername()))
            .findFirst();
  }

  private List<ApplicationUser> getApplicationUsers() {
    List<ApplicationUser> applicationUsers =
        Lists.newArrayList(
            new ApplicationUser(
                "haigaz",
                passwordEncoder.encode("round"),
                STUDENT.getGrantedAuthorities(),
                true,
                true,
                true,
                true),

            new ApplicationUser(
                "alice",
                passwordEncoder.encode("round"),
                ADMINTRAINEE.getGrantedAuthorities(),
                true,
                true,
                true,
                true),

                new ApplicationUser(
                "garo",
                passwordEncoder.encode("round"),
                ADMIN.getGrantedAuthorities(),
                true,
                true,
                true,
                true));

    return applicationUsers;
  }
}
