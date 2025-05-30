package io.security_JWT.backend.admin.unit;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

@Getter
@AllArgsConstructor
public class BaseResponse<T> {
    private int status;
    private String message;
    private T data;

    //성공을 반환할 메시지만
    public static ResponseEntity<BaseResponse<?>> ok(String message,HttpStatus status) {
        return ResponseEntity.status(status)
                .body(new BaseResponse<>(status.value(), message, null));
    }

    //성공 메시지와 데이터 반환
    public static <T> ResponseEntity<BaseResponse<T>> ok(String message, T data, HttpStatus status) {
        return ResponseEntity.status(status)
                .body(new BaseResponse<>(status.value(), message, data));
    }

    //에러 메시지를 반환
    public static ResponseEntity<BaseResponse<?>> error(String message, HttpStatus status) {
        return ResponseEntity.status(status)
                .body(new BaseResponse<>(status.value(), message, null));
    }
    //에러 메시지와 데이터를 반환
    public static <T> ResponseEntity<BaseResponse<T>> error(String message, T data, HttpStatus status) {
        return ResponseEntity.status(status)
                .body(new BaseResponse<>(status.value(), message, data));
    }
}
