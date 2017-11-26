package com.svlada.security.auth.ajax;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.web.bind.annotation.RequestParam;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.svlada.common.WebUtil;
/*import com.svlada.common.WebUtil;
import com.svlada.security.exceptions.AuthMethodNotSupportedException;*/
import com.svlada.security.exceptions.AuthMethodNotSupportedException;

/**
 * AjaxLoginProcessingFilter
 * 
 * @author vladimir.stankovic
 *
 * Aug 3, 2016
 */
public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {
    private static Logger logger = LoggerFactory.getLogger(AjaxLoginProcessingFilter.class);

    private final AuthenticationSuccessHandler successHandler;
    private final AuthenticationFailureHandler failureHandler;

    private final ObjectMapper objectMapper;
    
    public AjaxLoginProcessingFilter(String defaultProcessUrl, AuthenticationSuccessHandler successHandler, 
            AuthenticationFailureHandler failureHandler, ObjectMapper mapper) {
        super(defaultProcessUrl);
        this.successHandler = successHandler;
        this.failureHandler = failureHandler;
        this.objectMapper = mapper;
    }

    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
    	
    	//String payloadRequest = getBody(request);
    //	String payloadRequest=null;
    	String payloadRequest=null;
    	//if ("POST".equalsIgnoreCase(request.getMethod())) 
    	{
    		payloadRequest = request.getReader().lines().collect(Collectors.joining(System.lineSeparator()));
    	   
    	   System.out.println("TTTTTTTTTTTTTtt" + payloadRequest);
    	}
    	
    	
    //	System.out.println("TTTTTTTTtt" +test);
    	//System.out.println("asdasdas" + payloadRequest);
      /*  if (!HttpMethod.POST.name().equals(request.getMethod()) || !WebUtil.isAjax(request)) {
            if(logger.isDebugEnabled()) {
                logger.debug("Authentication method not supported. Request method: " + request.getMethod());
            }
            throw new AuthMethodNotSupportedException("Authentication method not supported");
        }*/

        LoginRequest loginRequest = objectMapper.readValue(payloadRequest, LoginRequest.class);
        
        if (StringUtils.isBlank(loginRequest.getUsername()) || StringUtils.isBlank(loginRequest.getPassword())) {
            throw new AuthenticationServiceException("Username or Password not provided");
        }

    	//String tt=request.getParameter("username");
    	//System.out.println("asasf" +tt);
    	
    	String username="svlada@gmail.com";
        String password ="test1234";

    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);

      // UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword());

        return this.getAuthenticationManager().authenticate(token);
    }
    
    
    public static String getBody(HttpServletRequest request) throws IOException {

        String body = null;
        StringBuilder stringBuilder = new StringBuilder();
        BufferedReader bufferedReader = null;

        try {
            InputStream inputStream = request.getInputStream();
            if (inputStream != null) {
                bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                char[] charBuffer = new char[128];
                int bytesRead = -1;
                while ((bytesRead = bufferedReader.read(charBuffer)) > 0) {
                    stringBuilder.append(charBuffer, 0, bytesRead);
                }
            } else {
                stringBuilder.append("");
            }
        } catch (IOException ex) {
            throw ex;
        } finally {
            if (bufferedReader != null) {
                try {
                    bufferedReader.close();
                } catch (IOException ex) {
                    throw ex;
                }
            }
        }

        body = stringBuilder.toString();
        return body;
    }


    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
            Authentication authResult) throws IOException, ServletException {
        successHandler.onAuthenticationSuccess(request, response, authResult);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            AuthenticationException failed) throws IOException, ServletException {
        SecurityContextHolder.clearContext();
        failureHandler.onAuthenticationFailure(request, response, failed);
    }
}
