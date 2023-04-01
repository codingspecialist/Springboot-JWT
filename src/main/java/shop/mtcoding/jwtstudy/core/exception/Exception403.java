package shop.mtcoding.jwtstudy.core.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;
import shop.mtcoding.jwtstudy.dto.ResponseDto;

// 권한 없음
@Getter
public class Exception403 extends RuntimeException {
    public Exception403(String message) {
        super(message);
    }

    public ResponseDto<?> body(){
        ResponseDto<String> responseDto = new ResponseDto<>();
        responseDto.fail(HttpStatus.FORBIDDEN, "forbidden", getMessage());
        return responseDto;
    }

    public HttpStatus status(){
        return HttpStatus.FORBIDDEN;
    }
}