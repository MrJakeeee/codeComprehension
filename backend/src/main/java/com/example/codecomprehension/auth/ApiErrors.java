package com.example.codecomprehension.auth;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import java.util.Map;
@RestControllerAdvice
public class ApiErrors {
 @ExceptionHandler(ApiException.class) ResponseEntity<?> api(ApiException e){return ResponseEntity.status(e.status).body(Map.of("message",e.getMessage()));}
 @ExceptionHandler({MethodArgumentNotValidException.class,HttpMessageNotReadableException.class,HandlerMethodValidationException.class,MissingServletRequestParameterException.class}) ResponseEntity<?> validation(Exception e){return ResponseEntity.badRequest().body(Map.of("message","Проверьте данные: корректная почта, пароль от 8 до 72 символов, непустой токен"));}
}
