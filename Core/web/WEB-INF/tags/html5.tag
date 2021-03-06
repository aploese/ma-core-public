<%--
    Copyright (C) 2015 Infinite Automation Systems, Inc. All rights reserved.
    http://infiniteautomation.com/
    @author Jared Wiltshire
--%><!doctype html>
<%@tag import="com.serotonin.m2m2.Common"%>
<%@include file="/WEB-INF/tags/decl.tagf"%>
<%@attribute name="styles" fragment="true" %>
<%@attribute name="scripts" fragment="true" %>
<%@attribute name="showHeader" %>
<%@attribute name="showToolbar" %>
<%@attribute name="showFooter" %>
<%@attribute name="replaceStyles" %>
<%@attribute name="replaceScripts" %>
<c:choose>
    <c:when test="${empty showHeader}"><c:set var="showHeader">${param.showHeader}</c:set></c:when>
</c:choose>
<c:choose>
    <c:when test="${empty showToolbar}"><c:set var="showToolbar">${param.showToolbar}</c:set></c:when>
</c:choose>
<c:choose>
    <c:when test="${empty showFooter}"><c:set var="showFooter">${param.showFooter}</c:set></c:when>
</c:choose>
<html class="no-js" lang="">
    <head>
        <meta charset="utf-8">
        <meta http-equiv="x-ua-compatible" content="ie=edge">
        <title><c:choose><c:when test="${!empty instanceDescription}">${instanceDescription}</c:when>
        <c:otherwise><fmt:message key="header.title"/></c:otherwise></c:choose></title>
        <meta name="description" content="Mango Automation from Infinite Automation Systems">
        <meta name="copyright" content="&copy;2015 Infinite Automation Systems, Inc.">
        <meta name="viewport" content="width=device-width, initial-scale=1">

        <link rel="apple-touch-icon" href="apple-touch-icon.png">

        <link rel="icon" href="<%= Common.applicationFavicon %>"/>
        <link rel="shortcut icon" href="<%= Common.applicationFavicon %>"/>
        
        <c:choose>
          <c:when test="${replaceStyles == true}">
            <!-- JSP styles fragment -->
            <jsp:invoke fragment="styles"/>
            <!-- / JSP styles fragment -->
          </c:when>
          <c:otherwise>
            <%-- included with bootstrap?
            <link rel="stylesheet" href="/resources/normalize.css">--%>
            <link rel="stylesheet" type="text/css" href="/resources/bootstrap/css/bootstrap.min.css"/>
            <%--<link rel="stylesheet" href="/resources/fonts/Roboto/Roboto.css">
            <link rel="stylesheet" href="/resources/fonts/OpenSans/OpenSans.css">--%>
            <link rel="stylesheet" type="text/css" href="/resources/main.css"/>
            <%-- For now we need to include the floating pane CSS to use the help popup --%>
            <link rel="stylesheet" type="text/css" href="/resources/dojox/layout/resources/FloatingPane.css"/>
            <link rel="stylesheet" type="text/css" href="/resources/dojox/layout/resources/ResizeHandle.css"/>
            <!-- JSP styles fragment -->
            <jsp:invoke fragment="styles"/>
            <!-- / JSP styles fragment -->
          </c:otherwise>
        </c:choose>
        
        <script type="text/javascript" src="/resources/modernizr-2.8.3.min.js"></script>
      <c:choose>
        <c:when test="${!empty siteAnalyticsHead}">${siteAnalyticsHead}</c:when>
      </c:choose>
    </head>
    <body class="mango">
        <!--[if lt IE 8]>
            <p class="browserupgrade">You are using an <strong>outdated</strong> browser. Please <a href="http://browsehappy.com/">upgrade your browser</a> to improve your experience.</p>
        <![endif]-->
        
        <!-- Header -->
        <c:if test="${empty showHeader || showHeader == true}">
        <html5:header />
        </c:if>
        
        <!-- Toolbar -->
        <c:if test="${empty showToolbar || showToolbar == true}">
        <html5:toolbar />
        </c:if>
        
        <!-- JSP body fragment -->
        <div class="content container-fluid">
        <jsp:doBody/>
        </div>
        
        <!-- Footer -->
        <c:if test="${empty showFooter || showFooter == true}">
        <html5:footer />
        </c:if>
        
        <!-- Scripts -->
        <c:choose>
          <c:when test="${replaceScripts == true}">
            <!-- JSP scripts fragment -->
            <jsp:invoke fragment="scripts"/>
            <!-- / JSP scripts fragment -->
          </c:when>
          <c:otherwise>
            <%-- Template scripts TODO work out how the loader can use the  versioned java script URL--%>
            <script type="text/javascript" src="/resources/loaderConfig.js"></script>
            <script type="text/javascript"  src="/resources/require.js"></script>
            <script type="text/javascript"  src="/resources/main.js"></script>
            <!-- JSP scripts fragment -->
            <jsp:invoke fragment="scripts"/>
            <!-- / JSP scripts fragment -->
          </c:otherwise>
        </c:choose>
      <c:choose>
        <c:when test="${!empty siteAnalyticsBody}">${siteAnalyticsBody}</c:when>
      </c:choose>
    </body>
</html>
