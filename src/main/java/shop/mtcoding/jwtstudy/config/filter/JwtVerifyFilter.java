package shop.mtcoding.jwtstudy.config.filter;

import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import shop.mtcoding.jwtstudy.config.auth.JwtProvider;
import shop.mtcoding.jwtstudy.config.auth.LoginUser;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

public class JwtVerifyFilter implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        System.out.println("디버그 : JwtVerifyFilter 동작함");
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;
        String prefixJwt = req.getHeader(JwtProvider.HEADER);
        if(prefixJwt == null){
            resp.setStatus(401);
            resp.setContentType("text/plain; charset=utf-8");
            resp.getWriter().println("로그인 다시해");
            return;
        }
        String jwt = prefixJwt.replace(JwtProvider.TOKEN_PREFIX, "");
        try {
            DecodedJWT decodedJWT = JwtProvider.verify(jwt);
            int id = decodedJWT.getClaim("id").asInt();
            String role = decodedJWT.getClaim("role").asString();

            // 내부적으로 권한처리 (인터셉터와 함께 사용하면 좋지만, 추후 스프링 시큐리티로 다룰 예정)
            HttpSession session =  req.getSession();
            LoginUser loginUser = LoginUser.builder().id(id).role(role).build();
            session.setAttribute("loginUser", loginUser);
            chain.doFilter(req, resp);
        }catch (SignatureVerificationException sve){
            resp.setStatus(401);
            resp.setContentType("text/plain; charset=utf-8");
            resp.getWriter().println("로그인 다시해");
        }catch (TokenExpiredException tee){
            resp.setStatus(401);
            resp.setContentType("text/plain; charset=utf-8");
            resp.getWriter().println("로그인 다시해");
        }
    }

}
