package com.mettler.jwt.mettlerAuth.Security.jwt;

import java.time.Duration;
import java.util.Date;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.util.WebUtils;

import com.mettler.jwt.mettlerAuth.Security.services.UserDetailsImpl;

import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.Transport;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;
import java.util.Properties;
import io.jsonwebtoken.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

@Component
public class JwtUtils {
  private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

  @Value("${mettler.app.jwtSecret}")
  private String jwtSecret;

  @Value("${mettler.app.jwtExpirationMs}")
  private long jwtExpirationMs;

  @Value("${mettler.app.jwtCookieName}")
  private String jwtCookie;
  
  private Set<String> invalidatedTokenCache;
  @Autowired
  private JavaMailSender mailSender;
  
  public JwtUtils(JavaMailSender mailSender) {
	  this.mailSender= mailSender;
	  this.invalidatedTokenCache= ConcurrentHashMap.newKeySet();
  }

  public JwtUtils() {
      this.invalidatedTokenCache = ConcurrentHashMap.newKeySet();
  }

  public boolean isJwtTokenInvalidated(String token) {
      return invalidatedTokenCache.contains(token);
  }

  public void invalidateJwtToken(String token) {
      invalidatedTokenCache.add(token);
  }

  public String getJwtFromCookies(HttpServletRequest request) {
    Cookie cookie = WebUtils.getCookie(request, jwtCookie);
    if (cookie != null) {
      return cookie.getValue();
    } else {
      return null;
    }
  }

  public ResponseCookie generateJwtCookie(UserDetailsImpl userPrincipal) {
    String jwt = generateTokenFromUsername(userPrincipal.getUsername());
    ResponseCookie cookie = ResponseCookie.from(jwtCookie, jwt)
        .path("/")
        .maxAge(Duration.ofSeconds(1 * 60 * 60))
        .httpOnly(true)
        .secure(false)
        .sameSite("None")
        .build();
    return cookie;
  }

  public ResponseCookie getCleanJwtCookie() {
    ResponseCookie cookie = ResponseCookie.from(jwtCookie, null)
        .path("/")
        .maxAge(Duration.ofSeconds(0))
        .httpOnly(true)
        .secure(false)
        .sameSite("None")
        .build();
    return cookie;
  }

  public String getUserNameFromJwtToken(String token) {
    return Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody().getSubject();
  }

  public boolean validateJwtToken(String authToken) {
    try {
      Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
      return true;
    } catch (SignatureException e) {
      logger.error("Invalid JWT signature: {}", e.getMessage());
    } catch (MalformedJwtException e) {
      logger.error("Invalid JWT token: {}", e.getMessage());
    } catch (ExpiredJwtException e) {
      logger.error("JWT token is expired: {}", e.getMessage());
    } catch (UnsupportedJwtException e) {
      logger.error("JWT token is unsupported: {}", e.getMessage());
    } catch (IllegalArgumentException e) {
      logger.error("JWT claims string is empty: {}", e.getMessage());
    }

    return false;
  }
  
  public String generateTokenFromUsername(String username) {   
    return Jwts.builder()
        .setSubject(username)
        .setIssuedAt(new Date())
        .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
        .signWith(SignatureAlgorithm.HS512, jwtSecret)
        .compact();
  }
  
  private void sendOTPEmail(String email, String otp) {
	    // Get the session properties
	    Properties properties = new Properties();
//	    properties.put("mail.smtp.auth", "true");
//	    properties.put("mail.smtp.starttls.enable", "true");
	    properties.put("mail.smtp.host", "${spring.mail.host}");
	    properties.put("mail.smtp.port", "${spring.mail.port}");
	    properties.put("mail.smtp.username", "${spring.mail.username}");
	    properties.put("mail.smtp.password", "${spring.mail.password}");

	    // Create the session
	    Session session = Session.getInstance(properties, null);

	    try {
	        // Create a new message
	        Message message = new MimeMessage(session);
	        message.setFrom(new InternetAddress("govindharaj@elonnativesystem.com"));
	        message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(email));
	        message.setSubject("Reset Password OTP");
	        message.setText("Your OTP is: " + otp);

	        // Send the message
	        Transport.send(message);
	    } catch (MessagingException e) {
	        // Handle the exception
	        e.printStackTrace();
	    }
	}

  
  public String getJwtFromRequest(HttpServletRequest request) {
	    String header = request.getHeader(HttpHeaders.AUTHORIZATION);
	    if (StringUtils.hasText(header) && header.startsWith("Bearer ")) {
	        return header.substring(7); // Extract the JWT token from the "Authorization" header
	    }
	    return null;
	}


public long getJwtExpirationMs() {
	
	return jwtExpirationMs;
}
}
