package me.chandlersong.jwt.utils;

import lombok.extern.slf4j.Slf4j;

import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Slf4j
public class AuthUtils {
    private static final String BASIC_ = "Basic ";

    private AuthUtils() {
        throw new IllegalStateException("Utility class" );
    }

    /**
     * *从header 请求中的clientId:clientSecret
     */
    public static String[] extractClient(HttpServletRequest request) {
        String header = request.getHeader("Authorization" );
        if (header == null || !header.startsWith(BASIC_)) {
            throw new IllegalArgumentException("请求头中client信息为空" );
        }
        return extractHeaderClient(header);
    }

    /**
     * 从header 请求中的clientId:clientSecret
     *
     * @param header header中的参数
     */
    public static String[] extractHeaderClient(String header) {
        byte[] base64Client = header.substring(BASIC_.length()).getBytes(StandardCharsets.UTF_8);
        byte[] decoded = Base64.getDecoder().decode(base64Client);
        String clientStr = new String(decoded, StandardCharsets.UTF_8);
        String[] clientArr = clientStr.split(":" );
        if (clientArr.length != 2) {
            throw new RuntimeException("Invalid basic authentication token" );
        }
        return clientArr;
    }


}
