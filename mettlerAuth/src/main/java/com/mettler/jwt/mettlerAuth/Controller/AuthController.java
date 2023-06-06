package com.mettler.jwt.mettlerAuth.Controller;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.mettler.jwt.mettlerAuth.Models.ERole;
import com.mettler.jwt.mettlerAuth.Models.Role;
import com.mettler.jwt.mettlerAuth.Models.Session;
import com.mettler.jwt.mettlerAuth.Models.User;
import com.mettler.jwt.mettlerAuth.Security.jwt.JwtUtils;
import com.mettler.jwt.mettlerAuth.Security.services.UserDetailsImpl;
import com.mettler.jwt.mettlerAuth.repository.RoleRepository;
import com.mettler.jwt.mettlerAuth.repository.SessionRepository;
import com.mettler.jwt.mettlerAuth.repository.UserRepository;
import com.mettler.jwt.mettlerAuth.request.ForgotPasswordRequest;
import com.mettler.jwt.mettlerAuth.request.LoginRequest;
import com.mettler.jwt.mettlerAuth.request.ResetPasswordRequest;
import com.mettler.jwt.mettlerAuth.request.SignupRequest;
import com.mettler.jwt.mettlerAuth.response.MessageResponse;
import com.mettler.jwt.mettlerAuth.response.UserResponse;

import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
  @Autowired
  AuthenticationManager authenticationManager;
  
  @Autowired
  private SessionRepository sessionRepository;
  
  @Autowired
  UserRepository userRepository;

  @Autowired
  RoleRepository roleRepository;

  @Autowired
  PasswordEncoder encoder;

  @Autowired
  JwtUtils jwtUtils;
  
  @PostMapping("/createNewRole")
  public ResponseEntity<String> createNewRole(@RequestBody Role role) {
      if (roleRepository.findByName(role.getName()).isPresent()) {
          return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Role already exists: " + role.getName());
      }

      Role createdRole = roleRepository.save(role);
      if (createdRole != null) {
          return ResponseEntity.ok("Role created successfully");
      } else {
          return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to create role");
      }
  }
  

  @PostMapping("/signup")
  public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
    if (userRepository.existsByUsername(signUpRequest.getUsername())) {
      return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
    }

    if (userRepository.existsByEmail(signUpRequest.getEmail())) {
      return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
    }

    // Create new user's account
    User user = new User(signUpRequest.getUsername(),
                         signUpRequest.getEmail(),
                         encoder.encode(signUpRequest.getPassword()));

    Set<String> strRoles = signUpRequest.getRole();
    Set<Role> roles = new HashSet<>();

    if (strRoles == null) {
      Role userRole = roleRepository.findByName(ERole.user)
          .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
      roles.add(userRole);
    } else {
      strRoles.forEach(role -> {
        switch (role) {
        case "admin":
          Role adminRole = roleRepository.findByName(ERole.admin)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
          roles.add(adminRole);

          break;
        case "mod":
          Role modRole = roleRepository.findByName(ERole.moderator)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
          roles.add(modRole);

          break;
        default:
          Role userRole = roleRepository.findByName(ERole.user)
              .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
          roles.add(userRole);
        }
      });
    }

    user.setRoles(roles);
    userRepository.save(user);

    return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
  }

  @PostMapping("/signin")
  public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

    Authentication authentication = authenticationManager
        .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
    
    Session session = new Session();
    session.setUsername(loginRequest.getUsername());
    session.setSessionId(UUID.randomUUID().toString());
    session.setCreatedDate(LocalDateTime.now());
    Date jwtExpiration = new Date(System.currentTimeMillis() + jwtUtils.getJwtExpirationMs());
    LocalDateTime expireTime = LocalDateTime.ofInstant(jwtExpiration.toInstant(), ZoneId.systemDefault());
    session.setExpireTime(expireTime);
    sessionRepository.save(session);

    SecurityContextHolder.getContext().setAuthentication(authentication);

    UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();

    ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);

    List<String> roles = userDetails.getAuthorities().stream()
        .map(item -> item.getAuthority())
        .collect(Collectors.toList());

    return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
        .body(new UserResponse(userDetails.getId(),
                                   userDetails.getUsername(),
                                   userDetails.getEmail(),
                                   roles));
  }

  @PostMapping("/signout")
  public ResponseEntity<?> logoutUser(HttpServletRequest request, HttpServletResponse response) {
      String jwtToken = jwtUtils.getJwtFromRequest(request);
      if (jwtToken != null && jwtUtils.validateJwtToken(jwtToken)) {
          jwtUtils.invalidateJwtToken(jwtToken); // Invalidate the JWT token
          ResponseCookie cookie = jwtUtils.getCleanJwtCookie();
          response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
          return ResponseEntity.ok().body(new MessageResponse("You've been signed out!"));
      } else {
          return ResponseEntity.badRequest().body(new MessageResponse("Invalid or expired token!"));
      }
  }
  
  @Autowired
  private JavaMailSender mailSender;

  private void sendOTPEmail(String email, String otp) {
      SimpleMailMessage message = new SimpleMailMessage();
      message.setTo(email);
      message.setSubject("Reset Password OTP");
      message.setText("Your OTP is: " + otp);
      mailSender.send(message);
  }
  
  private String generateOTP() {
	    int otpLength = 6;
	    int min = (int) Math.pow(10, otpLength - 1);
	    int max = (int) Math.pow(10, otpLength) - 1;
	    return String.valueOf((int) (Math.random() * (max - min + 1) + min));
	}
  
  @PostMapping("/forgot-password")
  public ResponseEntity<?> forgotPassword(@Valid @RequestBody ForgotPasswordRequest forgotPasswordRequest) {
      // Check if the email exists in the database
      User user = userRepository.findByEmail(forgotPasswordRequest.getEmail());
      if (user == null) {
          return ResponseEntity.badRequest().body(new MessageResponse("Error: Email not found!"));
      }
      

      // Generate OTP
      String otp = generateOTP();
      user.setResetOtp(otp);
      user.setResetOtpExpiration(LocalDateTime.now().plusMinutes(15)); // Set OTP expiration to 15 minutes from now
      userRepository.save(user);

      // Send OTP to the user's email
      

      sendOTPEmail(forgotPasswordRequest.getEmail(), otp);

      return ResponseEntity.ok(new MessageResponse("OTP sent to your email. Please check your inbox."));
  }

  
  @PostMapping("/reset-password")
  public ResponseEntity<?> resetPassword(@Valid @RequestBody ResetPasswordRequest resetPasswordRequest) {
      // Check if the email exists in the database
      User user = userRepository.findByEmail(resetPasswordRequest.getEmail());
      if (user == null) {
          return ResponseEntity.badRequest().body(new MessageResponse("Error: Email not found!"));
      }

      // Check if the OTP is valid and has not expired
      if (!resetPasswordRequest.getOtp().equals(user.getResetOtp())
              || LocalDateTime.now().isAfter(user.getResetOtpExpiration())) {
          return ResponseEntity.badRequest().body(new MessageResponse("Error: Invalid or expired OTP!"));
      }

      // Update the user's password
      user.setPassword(encoder.encode(resetPasswordRequest.getNewPassword()));
      user.setResetOtp(null);
      user.setResetOtpExpiration(null);
      userRepository.save(user);

      return ResponseEntity.ok(new MessageResponse("Password reset successful!"));
  }

}
