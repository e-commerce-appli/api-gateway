package com.blue.api_gateway.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class CustomExceptionController {
    @ExceptionHandler(CustomException.class)
    public ResponseEntity<String> exceptionhandler(CustomException customException){
        return new ResponseEntity<>(customException.getMessage(), HttpStatus.OK);
    }
}
