package com.enjoybt.framework.security.util;

import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.text.SimpleDateFormat;

public class JBUtil {
	 public static String getDate() {
		 SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-dd");
		 return format.format(System.currentTimeMillis());
	 }
	
	 public static String getIpAddr(){
		 HttpServletRequest request = ((ServletRequestAttributes)RequestContextHolder.currentRequestAttributes()).getRequest();
		
         String ip = request.getHeader("X-FORWARDED-FOR"); 
        
         if (ip == null || ip.length() == 0) {
             ip = request.getHeader("Proxy-Client-IP");
         }
        
         if (ip == null || ip.length() == 0) {
             ip = request.getHeader("WL-Proxy-Client-IP");
         }

         if (ip == null || ip.length() == 0) {
             ip = request.getRemoteAddr() ;
         }
        
         return ip;
    }
}
