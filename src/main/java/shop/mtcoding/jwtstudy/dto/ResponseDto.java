package shop.mtcoding.jwtstudy.dto;

import lombok.*;
import org.springframework.http.HttpStatus;

@Getter
public class ResponseDto<T> {
    private Integer status; // 에러시에 의미 있음.
    private String msg; // 에러시에 의미 있음. ex) badRequest
    private T data; // 에러시에는 구체적인 에러 내용 ex) username이 입력되지 않았습니다

    public ResponseDto(){
        this.status = HttpStatus.OK.value();
        this.msg = "성공";
        this.data = null;
    }

    public ResponseDto<?> data(T data){
        this.data = data;
        return this;
    }

    public ResponseDto<?> fail(HttpStatus httpStatus, String errorTitle, T errorDetail){
        this.status = httpStatus.value();
        this.msg = errorTitle;
        this.data = errorDetail;
        return this;
    }
}
