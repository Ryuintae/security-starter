<%@ page contentType="text/html; charset=utf-8" pageEncoding="utf-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/functions" prefix="fn" %>
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>오류 페이지</title>
<script language="javascript">
function fncGoAfterErrorPage(){
    history.back(-2);
}
</script>
<style>
body {
	background-color: #dee8ed;
}
* {
	color:#082c3d;
	font-weight: bold;
	font-size:20px;
}
</style>
</head>
<body>
<div style="width:450px; height: 100%; margin: 300px auto 0;">
	<img src="<c:url value='/resources/images/common/warning.png' />" width="116" height="106" />
	<p style="font-size: 30px; margin: 46px 0 28px 0">405 Error</p>
	<p class="title" style="margin: 0 0 60px 0">HTTP 405 Error / Method not allowed</p>
	<span class="btn_style1 blue" style="width:148px; height:50px; background: #1395d3; border-radius: 4px; padding: 8px 24px; "><a href="javascript:fncGoAfterErrorPage();" style="text-decoration:none;color : #FFFFFF;	">이전 페이지</a></span>
</div>
</body>
</html>
