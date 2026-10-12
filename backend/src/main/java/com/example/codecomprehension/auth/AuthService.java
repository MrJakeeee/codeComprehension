package com.example.codecomprehension.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.Duration;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.MailException;

@Service
public class AuthService {
 private final JdbcTemplate db;
 private final PasswordEncoder passwords;
 private final JavaMailSender mail;
 private final String publicUrl, from;
 private final SecureRandom random = new SecureRandom();
 private final String dummyHash;
 public AuthService(JdbcTemplate db, PasswordEncoder passwords, JavaMailSender mail,
  @Value("${app.auth.public-url}") String publicUrl, @Value("${app.auth.mail-from}") String from) {
  this.db=db; this.passwords=passwords; this.mail=mail; this.publicUrl=publicUrl; this.from=from;
  dummyHash=passwords.encode(UUID.randomUUID().toString());
 }
 public static String normalize(String email) { return email.trim().toLowerCase(Locale.ROOT); }
 public static String hash(String raw) {
  try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(raw.getBytes(StandardCharsets.UTF_8))); }
  catch (Exception ex) { throw new IllegalStateException(ex); }
 }
 private String issue(UUID user, String purpose, Duration ttl) {
  byte[] bytes=new byte[32]; random.nextBytes(bytes);
  String raw=Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  db.update("INSERT INTO auth_tokens(token_hash,user_id,purpose,expires_at) VALUES(?,?,?,?)",hash(raw),user,purpose,Timestamp.from(Instant.now().plus(ttl)));
  return raw;
 }
 private void send(String email,String path,String token,String subject) {
  SimpleMailMessage msg=new SimpleMailMessage(); msg.setFrom(from);msg.setTo(email);msg.setSubject(subject);
  msg.setText(subject+"\n"+publicUrl+path+token);
  try { mail.send(msg); } catch(MailException ex) { throw new ApiException(503,"Не удалось отправить письмо"); }
 }
 @Transactional
 public void register(String email,String password) {
  UUID id=UUID.randomUUID();
  try { db.update("INSERT INTO app_users(id,email,password_hash,role) VALUES(?,?,?,'USER')",id,normalize(email),passwords.encode(password)); }
  catch(DuplicateKeyException ex) { throw new ApiException(409,"Эта почта уже используется"); }
  send(normalize(email),"/api/auth/verify-email?token=",issue(id,"VERIFY",Duration.ofHours(24)),"Подтвердите почту");
 }
 private UUID consume(String token,String purpose) {
  var rows=db.query("DELETE FROM auth_tokens WHERE token_hash=? AND purpose=? AND expires_at>CURRENT_TIMESTAMP RETURNING user_id",(rs,n)->rs.getObject(1,UUID.class),hash(token),purpose);
  if(rows.isEmpty()) throw new ApiException(400,"Ссылка недействительна или срок её действия истёк");
  return rows.getFirst();
 }
 @Transactional
 public void verify(String token) { db.update("UPDATE app_users SET verified=TRUE WHERE id=?",consume(token,"VERIFY")); }
 @Transactional
 public Map<String,Object> login(String email,String password) {
  var rows=db.queryForList("SELECT * FROM app_users WHERE email=? FOR UPDATE",normalize(email));
  Map<String,Object> u=rows.isEmpty()?null:rows.getFirst();
  boolean valid=passwords.matches(password,u==null?dummyHash:(String)u.get("password_hash"));
  if(u==null || !valid) throw new ApiException(401,"Неверная почта или пароль");
  if((Boolean)u.get("blocked")) throw new ApiException(403,"Аккаунт заблокирован");
  if(!(Boolean)u.get("verified")) throw new ApiException(403,"Подтвердите почту");
  String token=issue((UUID)u.get("id"),"SESSION",Duration.ofHours(12));
  return Map.of("accessToken",token,"tokenType","Bearer","expiresIn",43200,"user",new UserView((UUID)u.get("id"),(String)u.get("email"),(String)u.get("role")));
 }
 public Optional<UserView> authenticate(String token) {
  return db.query("SELECT u.id,u.email,u.role FROM app_users u JOIN auth_tokens t ON u.id=t.user_id WHERE t.token_hash=? AND t.purpose='SESSION' AND t.expires_at>CURRENT_TIMESTAMP AND u.verified=TRUE AND u.blocked=FALSE",(rs,n)->new UserView(rs.getObject(1,UUID.class),rs.getString(2),rs.getString(3)),hash(token)).stream().findFirst();
 }
 public void logout(String raw) { db.update("DELETE FROM auth_tokens WHERE token_hash=? AND purpose='SESSION'",hash(raw)); }
 @Transactional
 public void forgot(String email) {
  var ids=db.query("SELECT id FROM app_users WHERE email=? AND verified=TRUE AND blocked=FALSE FOR UPDATE",(rs,n)->rs.getObject(1,UUID.class),normalize(email));
  if(ids.isEmpty())return;
  UUID id=ids.getFirst(); db.update("DELETE FROM auth_tokens WHERE user_id=? AND purpose='RESET'",id);
  send(normalize(email),"/api/auth/reset-password?token=",issue(id,"RESET",Duration.ofMinutes(30)),"Восстановление пароля: отправьте token и новый password через POST /api/auth/reset-password");
 }
 @Transactional
 public void reset(String token,String password) {
  // Lock the account before consuming the token: login and reset cannot race.
  var ids=db.query("SELECT u.id FROM app_users u JOIN auth_tokens t ON u.id=t.user_id WHERE t.token_hash=? AND t.purpose='RESET' FOR UPDATE OF u",(rs,n)->rs.getObject(1,UUID.class),hash(token));
  if(ids.isEmpty())throw new ApiException(400,"Ссылка недействительна или срок её действия истёк");
  UUID id=consume(token,"RESET");
  db.update("UPDATE app_users SET password_hash=? WHERE id=?",passwords.encode(password),id);
  db.update("DELETE FROM auth_tokens WHERE user_id=? AND purpose IN ('SESSION','RESET')",id);
 }
 @Transactional
 public void bootstrap(String email,String password) {
  if(db.queryForObject("SELECT count(*) FROM app_users WHERE email=?",Long.class,normalize(email))>0)return;
  db.update("INSERT INTO app_users(id,email,password_hash,role,verified) VALUES(?,?,?,'ADMIN',TRUE)",UUID.randomUUID(),normalize(email),passwords.encode(password));
 }
}
