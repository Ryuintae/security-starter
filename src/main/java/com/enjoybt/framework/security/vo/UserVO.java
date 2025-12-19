package com.enjoybt.framework.security.vo;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 *  Description : 사용자 정보를 담는 객체
 */
public class UserVO implements UserDetails {
	
	private static final long serialVersionUID = -6286395747969948191L;
	
	/**
	 * 	사용자 계정
	 */
	private String userID;
	
	/**
	 *  사용자 패스워드 
	 */
	private String password;
	
	private String name;
	
	private String groupName;
	
	private Integer loginCnt;
	
	/**
	 *  계정 권한 목록 
	 */
	private List<GrantedAuthority> authorities;
	
	public UserVO(String userID, String password, List<GrantedAuthority> authorities) {
		this.userID = userID;
		this.password = password;
		this.authorities = new ArrayList<GrantedAuthority>();
		for(GrantedAuthority authority : authorities)
			this.authorities.add(authority);
	}
	
	public UserVO(String userID, String password, List<GrantedAuthority> authorities, boolean isAccountNonExpired, boolean isAccountNonLocked, boolean isCredentialsNonExpired, boolean isEnabled) {
		this.userID = userID;
		this.password = password;
		this.authorities = new ArrayList<GrantedAuthority>();
		for(GrantedAuthority authority : authorities)
			this.authorities.add(authority);
	}
	
	public void setAuthorities(GrantedAuthority authority){
		authorities.clear();
		authorities.add(authority);
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		ArrayList<GrantedAuthority> copyAuthorities = new ArrayList<GrantedAuthority>();
		copyAuthorities.addAll(authorities);
		return copyAuthorities;
	}

	@Override
	public String getPassword() {
		return password;
	}

	@Override
	public String getUsername() {
		return userID;
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return (getLoginCnt() < 5) ? true : false;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getGroupName() {
		return groupName;
	}

	public void setGroupName(String groupName) {
		this.groupName = groupName;
	}
	
	public Integer getLoginCnt() {
		return loginCnt;
	}

	public void setLoginCnt(Integer loginCnt) {
		this.loginCnt = loginCnt;
	}
	
	public void setUserInfo(Map<String, Object> map) {
		this.name = (String) map.get("user_name");
		this.groupName = (String) map.get("group_name");
		this.userID = (String) map.get("user_id");
		this.loginCnt = 0;
		
	}
}
