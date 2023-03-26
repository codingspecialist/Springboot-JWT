package shop.mtcoding.jwtstudy.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import shop.mtcoding.jwtstudy.config.auth.JwtProvider;
import shop.mtcoding.jwtstudy.config.auth.LoginUser;
import shop.mtcoding.jwtstudy.dto.UserRequest;
import shop.mtcoding.jwtstudy.model.User;
import shop.mtcoding.jwtstudy.model.UserRepository;

import javax.servlet.http.HttpSession;
import java.util.Optional;

@RequiredArgsConstructor
@RestController
public class UserController {

    private final UserRepository userRepository;
    private final HttpSession session;

    @GetMapping("/user/{id}/v1") // 인증, 권한 필요
    public ResponseEntity<?> userV1(@PathVariable Integer id){
        // 권한처리 이 사람이 이 정보의 주인
        LoginUser loginUser = (LoginUser) session.getAttribute("loginUser");
        if(loginUser.getId() == id) {
            return ResponseEntity.ok().body("접근 성공");
        }else{
            return new ResponseEntity<>("접근 실패", HttpStatus.FORBIDDEN);
        }
    }

    @GetMapping("/user/{id}/v2") // 인증, 권한 필요 and 관리자 접근 가능
    public ResponseEntity<?> userV2(@PathVariable Integer id){
        // 권한처리 이 사람이 이 정보의 주인
        LoginUser loginUser = (LoginUser) session.getAttribute("loginUser");
        if(loginUser.getId() == id || loginUser.getRole().equals("ADMIN")) {
            return ResponseEntity.ok().body("접근 성공");
        }else{
            return new ResponseEntity<>("접근 실패", HttpStatus.FORBIDDEN);
        }
    }

    @GetMapping("/") // 인증 불필요
    public ResponseEntity<?> main(){
        return ResponseEntity.ok().body("접근 성공");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody UserRequest.LoginDto loginDto){
        Optional<User> userOP = userRepository.findByUsernameAndPassword(loginDto.getUsername(), loginDto.getPassword());
        if(userOP.isPresent()){
            String jwt = JwtProvider.create(userOP.get());
            return ResponseEntity.ok().header(JwtProvider.HEADER, jwt).body("로그인 성공");
        }else{
            return ResponseEntity.badRequest().build();
        }
    }
}
