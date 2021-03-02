package com.example.springsecuritytutorial.Controllers;

import com.example.springsecuritytutorial.student.Student;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students/")
public class StudentManagementController {

  private static final List<Student> STUDENTS =
      Arrays.asList(
          new Student(1, "James Bond"),
          new Student(2, "LeBron James"),
          new Student(3, "Rafael Nadal"));

  // Options: hasRole('ROLE_'), hasAnyRole('ROLE_'), hasAuthority('permission'),
  // hasAnyAuthority('permission')
  // Also works: @Secured("ROLE_")

  @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
  @GetMapping
  public List<Student> getAllStudents() {
    return STUDENTS;
  }

  @PreAuthorize("hasAnyAuthority('student:write')")
  @PostMapping
  public void registerNewStudent(@RequestBody Student student) {
    System.out.println(student);
  }

  @PreAuthorize("hasAnyAuthority('student:write')")
  @DeleteMapping(path = "{studentId}")
  public void deleteStudent(@PathVariable Integer studentId) {
    System.out.println("Deleted:" + studentId);
  }

  @PreAuthorize("hasAnyAuthority('student:write')")
  @PutMapping(path = "{studentId}")
  public void updateStudent(@PathVariable Integer studentId, @RequestBody Student student) {
    System.out.println("studentId = " + studentId);
    System.out.println("student = " + student);
  }
}
