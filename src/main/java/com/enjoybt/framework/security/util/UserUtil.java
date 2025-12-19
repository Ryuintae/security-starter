package com.enjoybt.framework.security.util;

import com.enjoybt.framework.config.Constants;
import com.enjoybt.framework.security.vo.UserVO;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;


/**
 *  Description : 사용자 정보를 관리하는 클래스
 */
public class UserUtil {
	/**
	* 세션 사용자 객체 가져오는 메서드
	* @return 사용자 정보 객체
	*/
	public static UserVO getUserVO() {
		try{
			return (UserVO)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		}catch(NullPointerException e) {
			return null;
		}catch(ClassCastException e) {
			return null;
		}
		
	}
	
	/**
	* 세션 사용자 권한 가져오는 메서드
	* @return 사용자 권한
	*/
	public static String getRole() {
		if(UserUtil.getUserVO() != null) {
			return UserUtil.getUserVO().getAuthorities().iterator().next().getAuthority();
		}else{
			return null;
		}
	}
	
	/**
	* 세션 사용자 관리자 권한인지 체크하는 메서드
	* @return 관리자 권한 여부
	*/
	public static boolean isAdmin() {
		String role = UserUtil.getRole();
		return role.equals(Constants.ROLE_ADMIN);
	}
	
	/**
	* 세션 사용자 접속 권한 없는 지 여부 확인
	* @return 접속 권한 여부
	*/
	public static boolean isFail() {
		String role = UserUtil.getRole();
		return role.equals(Constants.ROLE_FAILURE);
	}
	
	/**
	* 세션 사용자 아이디 가져오는 메서드
	* @return 사용자 아이디
	*/
	public static String getUserId() {
		if(UserUtil.getUserVO() != null) {
			return UserUtil.getUserVO().getUsername();
		}else{
			return null;
		}
	}
	
	public static String getUserName() {
		if(UserUtil.getUserVO() != null) {
			return UserUtil.getUserVO().getName();
		}else{
			return null;
		}
	}
	
	public static String getGroupName() {
		if(UserUtil.getUserVO() != null) {
			return UserUtil.getUserVO().getGroupName();
		}else{
			return null;
		}
	}
	
	/**
	* 세션 사용자 아이디 체크
	* @param check - 체크할 사용자 아이디
	* @return 동일 여부
	*/
	public static boolean checkUserId(String check) {
		String userId = UserUtil.getUserId();
		
		return userId.equals(check);
	}
	
	public static void setFailRole() {
		GrantedAuthority authorityFail = new SimpleGrantedAuthority(Constants.ROLE_FAILURE);
		UserUtil.getUserVO().setAuthorities(authorityFail);
	}
	
	public static void setRole(String role) {
		GrantedAuthority authorityFail = new SimpleGrantedAuthority(role);
		UserUtil.getUserVO().setAuthorities(authorityFail);
	}
}
