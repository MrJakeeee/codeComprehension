package com.example.codecomprehension.auth;
import org.junit.jupiter.api.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.mail.javamail.JavaMailSender;
import java.util.*;
class AuthServiceTests {
 JdbcTemplate db=mock(JdbcTemplate.class);
 PasswordEncoder passwords=mock(PasswordEncoder.class);
 JavaMailSender mail=mock(JavaMailSender.class);
 AuthService service;
 @BeforeEach void setup(){when(passwords.encode(anyString())).thenReturn("hash");service=new AuthService(db,passwords,mail,"http://localhost:8080","test@example.org");}
 @Test void normalizesEmail(){assertEquals("user@example.org",AuthService.normalize(" USER@Example.org "));}
 @Test void hashesOpaqueToken(){assertEquals(64,AuthService.hash("secret").length());assertNotEquals("secret",AuthService.hash("secret"));assertEquals(AuthService.hash("secret"),AuthService.hash("secret"));}
 @Test void wrongPasswordDoesNotIssueSession(){
  when(db.queryForList(anyString(),any(Object[].class))).thenReturn(List.of());
  ApiException error=assertThrows(ApiException.class,()->service.login("user@example.org","wrongpass"));assertEquals(401,error.status);verify(db,never()).update(anyString(),any(Object[].class));
 }
 @Test void blockedAccountCannotLogin(){
  var user=new HashMap<String,Object>();user.put("password_hash","hash");user.put("blocked",true);user.put("verified",true);
  when(db.queryForList(anyString(),any(Object[].class))).thenReturn(List.of(user));when(passwords.matches("password","hash")).thenReturn(true);
  assertEquals(403,assertThrows(ApiException.class,()->service.login("u@example.org","password")).status);verify(db,never()).update(anyString(),any(Object[].class));
 }
 @Test void unverifiedAccountCannotLogin(){
  var user=new HashMap<String,Object>();user.put("password_hash","hash");user.put("blocked",false);user.put("verified",false);
  when(db.queryForList(anyString(),any(Object[].class))).thenReturn(List.of(user));when(passwords.matches("password","hash")).thenReturn(true);
  assertEquals(403,assertThrows(ApiException.class,()->service.login("u@example.org","password")).status);
 }
}
