package com.example.codecomprehension.auth;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import java.nio.charset.StandardCharsets;
import java.util.Map;
@RestController
@RequestMapping("/api/auth")
public class AuthController {
 private final AuthService service;
 public AuthController(AuthService service){this.service=service;}
 public record Credentials(@NotBlank @Email @Size(max=254) String email,@NotBlank @Size(min=8,max=72) String password) {}
 public record EmailRequest(@NotBlank @Email @Size(max=254) String email) {}
 public record ResetRequest(@NotBlank @Size(max=128) String token,@NotBlank @Size(min=8,max=72) String password) {}
 private void checkPassword(String password){if(password.getBytes(StandardCharsets.UTF_8).length>72)throw new ApiException(400,"Пароль должен занимать не больше 72 байт UTF-8");}
 @PostMapping("/register") @ResponseStatus(org.springframework.http.HttpStatus.CREATED)
 public Map<String,String> register(@Valid @RequestBody Credentials body){checkPassword(body.password());service.register(body.email(),body.password());return Map.of("message","Проверьте почту для подтверждения аккаунта");}
 @GetMapping("/verify-email")
 public Map<String,String> verify(@RequestParam @NotBlank @Size(max=128) String token){service.verify(token);return Map.of("message","Почта подтверждена");}
 @PostMapping("/login")
 public Map<String,Object> login(@Valid @RequestBody Credentials body){checkPassword(body.password());return service.login(body.email(),body.password());}
 @PostMapping("/logout") @ResponseStatus(org.springframework.http.HttpStatus.NO_CONTENT)
 public void logout(@RequestHeader("Authorization") String header){service.logout(header.substring(7));}
 @GetMapping("/me") public UserView me(@AuthenticationPrincipal UserView user){return user;}
 @PostMapping("/forgot-password") public Map<String,String> forgot(@Valid @RequestBody EmailRequest body){service.forgot(body.email());return Map.of("message","Если аккаунт доступен, письмо с инструкцией отправлено");}
 @GetMapping("/reset-password") public Map<String,String> resetInstructions(@RequestParam @NotBlank @Size(max=128) String token){return Map.of("message","Передайте token из ссылки и новый password в JSON через POST /api/auth/reset-password");}
 @PostMapping("/reset-password") public Map<String,String> reset(@Valid @RequestBody ResetRequest body){checkPassword(body.password());service.reset(body.token(),body.password());return Map.of("message","Пароль изменён. Войдите заново");}
}
