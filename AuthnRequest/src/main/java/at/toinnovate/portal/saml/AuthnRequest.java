/*
 * Creates the SAML authentication request to allow SP initiated SAML Flow.
 * 
 * System Properties:
 * - at.toinnovate.saml.spi.encodeAuthnRequestXML: Encode the XML. Default: true
 * - at.toinnovate.saml.spi.includeRequestAuthnContext: Encode the XML. Default: true
 * - at.toinnovate.saml.spi.useAzureFormat: Follow Azure rules. Default: true
 * - at.toinnovate.saml.nameIdFormat: The nameID attribute of the SAML request being generated. Default: emailAddress
 */

package at.toinnovate.portal.saml;

import java.rmi.server.UID;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.http.HttpServletRequest;

import com.ibm.websphere.security.NotImplementedException;
// import com.ibm.ws.wssecurity.saml.common.util.Base64;
import java.util.Base64;

import com.ibm.websphere.runtime.ServerName;
//
// https://www.ibm.com/support/knowledgecenter/en/SSEQTP_9.0.0/com.ibm.websphere.javadoc.doc/web/spidocs/com/ibm/wsspi/security/web/saml/AuthnRequestProvider.html
public class AuthnRequest implements com.ibm.wsspi.security.web.saml.AuthnRequestProvider {
	
		private static final String LOGGER_CLASS = AuthnRequest.class.getName();
		private static final Logger LOGGER = Logger.getLogger(LOGGER_CLASS);
		private static final String DEFAULT_NAME_ID_FORMAT = "emailAddress";
		private static final String ENCODE_AUTHN_REQUEST_XML_PROPERTY_NAME= "at.toinnovate.saml.spi.encodeAuthnRequestXML";
		private static final String INCLUDE_AUTHN_CONTEXT_PROPERTY_NAME= "at.toinnovate.saml.spi.includeRequestAuthnContext";
		private static final String USE_AZURE_FORMAT_PROPERTY_NAME= "at.toinnovate.saml.spi.useAzureFormat";
		private static final String NAME_ID_FORMAT_PROPERTY_NAME = "at.toinnovate.saml.nameIdFormat";

		private String issueInstant = "1979-06-27T10:11:12";
		private String requestId = "";
		private String providerName = "";
		// destination: A URI reference indicating the address to which this request has been sent.
		private String destination = "https://tfim02.rtp.raleigh.ibm.com:9443/sps/IBMIDtest/saml20/login"; // sso_1.idp_1.SingleSignOnUrl
		//AssertionConsumerServiceURL: Specifies by value the location to which the <Response> message MUST be returned to the requester.
		private String assertionConsumerServiceURL = "https://20150214sascha.rtp.raleigh.ibm.com:10041/samlsps/wasibmidtest"; // sso_1.sp.acsUrl
		//issuer: Identifies the entity that generated the request message.
		private String issuer = "https://20150214sascha.rtp.raleigh.ibm.com:10041/samlsps/wasibmidtest"; //sso_1.sp.acsUrl
		//ssoUrl: is SAML IdP SingleSignOn URL (so SAML TAI can post authnRequest to this URL)
		private String ssoUrl = "https://tfim02.rtp.raleigh.ibm.com:9443/sps/IBMIDtest/saml20/login"; // samlSsoUrl.get(0); sso_1.idp_1.SingleSignOnUrl
		private String requestedUrl = "";
		private String nameIdFormat = "";
		private Boolean doIncludeRequestAuthnContext = null; 
		private Boolean doEncodeAuthnRequestXML = null;
		private Boolean doUseAzureFormat = null;

	/**
	1.  The returned Hashmap contains 4 entries (https://www.ibm.com/support/knowledgecenter/SSEQTP_9.0.0/com.ibm.websphere.base.doc/ae/tsec_enable_saml_sp_sso.html)
	key    "authnRequest"  return base64 encoded SAMLRequest
	key    "requestId" returns the requestID inside AuthnRequest
	key    "relayState" returns relayState that will be passed to IdP
	key    "ssoUrl" is SAML IdP SingleSignOn URL (so SAML TAI can post authnRequest to this URL)

	2. You package your classes in a jar, and place the jar in lib/ext directory, then in SAML TAI custom property, you define
	login.error.page = <class name>
	The runtime will detect if it is a class or not. If it is class, it will loaded as class.

	 * If signature required, it need sign it before base64 encoded.
	 */
		@Override
		public HashMap<String, String> getAuthnRequest(HttpServletRequest samlServletRequest, String samlErrorMsg, String samlAcsUrl, ArrayList<String> samlSsoUrl) throws NotImplementedException {
		LOGGER.entering(LOGGER_CLASS, "getAuthnRequest-1");

		HashMap<String, String> myHashMap = new HashMap<String, String>();
		String myAuthnRequest = "";
		// SSO URL is taken from the parameters
		ssoUrl = samlSsoUrl.get(0);
		//
		// Set Variables which are retrieven from the SystemProperties
		setVarsFromSystemProperties();
		//
		// Set the provider name at first invocation
		if (providerName.equals("")) {
			providerName = getProviderName();
		}
		//
		// Get the nameIdFormat. We use the eMail as default if no property is specified
		if (nameIdFormat.equals("")) {
			nameIdFormat = getNameIdFormat();
		}
		requestedUrl = getServletRequest(samlServletRequest);
		assertionConsumerServiceURL = samlAcsUrl;
		issuer = samlAcsUrl;
		destination = ssoUrl;
		// 
		// Azure required an ID to start with a non-numeric character
		requestId = "id" + getRequestId();
		if (LOGGER.isLoggable(Level.FINE)) {
			LOGGER.fine("providerName: " + providerName);
			LOGGER.fine("requestedUrl: " + requestedUrl);
			LOGGER.fine("assertionConsumerServiceURL: " + assertionConsumerServiceURL);
			LOGGER.fine("issuer: " + issuer);
			LOGGER.fine("destination: " + destination);
			LOGGER.fine("requestId: " + requestId);

			LOGGER.fine("samlSsoUrl size:" + samlSsoUrl.size());
			for (int i = 0; i < samlSsoUrl.size(); i++) {
				LOGGER.fine("samlSsoUrl Element: " + i + " = " + samlSsoUrl.get(i));
			}
		}

		
		Date myDate = new Date();
		SimpleDateFormat issueFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
		// issueFormat.setTimeZone(TimeZone.getDefault());
		// must be UTC
		issueFormat.setTimeZone(TimeZone.getTimeZone("UTC"));
		issueInstant = issueFormat.format(myDate);

		//key    "authnRequest"  return base64 encoded SAMLRequest
		myAuthnRequest = new String(getAuthnRequest());
		//If signature required, it need sign it before base64 encoded.
		myAuthnRequest = signAuthRequest(myAuthnRequest);
		if (doEncodeAuthnRequestXML.booleanValue()) {
			LOGGER.fine("Encoding AuthnRequest ..." );
			myAuthnRequest = base64Encode(myAuthnRequest);
		} else {
			LOGGER.fine("Not encoding AuthnRequest as system property \"at.toinnovate.saml.spi.encodeAuthnRequestXML\" is false" );
		}
		myHashMap.put("authnRequest", myAuthnRequest);
		//key    "requestId" returns the requestID inside AuthnRequest
		myHashMap.put("requestId", requestId);
		//key    "relayState" returns relayState that will be passed to IdP
		myHashMap.put("relayState", getRelayState());
		//key    "ssoUrl" is SAML IdP SingleSignOn URL (so SAML TAI can post authnRequest to this URL)
		myHashMap.put("ssoUrl", getSsoUrl());

		if (LOGGER.isLoggable(Level.FINEST)) {
			LOGGER.finest("getAuthnRequest-1: myHashMap = " + myHashMap.toString());
		}
		LOGGER.exiting(LOGGER_CLASS, "getAuthnRequest-1");
		return myHashMap;
	}

	private String base64Encode(String myAuthnRequest) {
		return Base64.getEncoder().encodeToString(myAuthnRequest.getBytes());
	}

	private String signAuthRequest(String myAuthnRequest) {
		// if require sign message before encoding
		return myAuthnRequest;
	}

	private String getSsoUrl() {
		return ssoUrl;
	}

	private String getRelayState() {
		return requestedUrl;
//		return "relayStateId_1";
	}

	private String getAuthnRequest() {
		/**
		 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
		 * https://www.samltool.com/generic_sso_req.php
		 * https://rnd.feide.no/2007/12/10/example_saml_2_0_request_and_response/
		 * 
		 * <samlp:AuthnRequest 
		 * 		xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" 
		 * 		xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" 
		 * 		ID="ONELOGIN_809707f0030a5d00620c9d9df97f627afe9dcc24" 
		 * 		Version="2.0" 
		 * 		ProviderName="SP test" 
		 * 		IssueInstant="2014-07-16T23:52:45Z" 
		 * 		Destination="http://idp.example.com/SSOService.php" 
		 * 		ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" 
		 * 		AssertionConsumerServiceURL="http://sp.example.com/demo1/index.php?acs">
		 * <saml:Issuer>http://sp.example.com/demo1/metadata.php</saml:Issuer>
		 * <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:emailAddress" AllowCreate="true"/>
		 * <samlp:RequestedAuthnContext Comparison="exact">
		 * 		<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
		 * </samlp:RequestedAuthnContext>
		 * </samlp:AuthnRequest>
		 */
		
		LOGGER.entering(LOGGER_CLASS, "getAuthnRequest-2");
		//
		// Using new String to ensure that the string can be cleaned up
		String xmlString = new String("<samlp:AuthnRequest "
				+ "xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \n"
				+ "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" \n"
				+ "ID=\""+ requestId + "\" \n"
				+ "Version=\"2.0\" \n"
				+ "ProviderName=\""+ providerName + "\" \n"
				+ "IssueInstant=\""+ issueInstant + "\" \n"
				+ "Destination=\""+ destination + "\" \n"
				+ "ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" \n"
				+ "AssertionConsumerServiceURL=\"" + assertionConsumerServiceURL + "\"> \n"
				+ "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + issuer + "</saml:Issuer> \n"
				+ "<samlp:NameIDPolicy Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:" + nameIdFormat + "\" AllowCreate=\"true\" /> \n");
		if (doIncludeRequestAuthnContext.booleanValue()) {
			xmlString = xmlString + "<samlp:RequestedAuthnContext Comparison=\"exact\"> \n" 
			+ "<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef> \n"
			+ "</samlp:RequestedAuthnContext> \n";
		} else {
			LOGGER.fine("Not adding saml:AuthnContextClassRef as system property \"at.toinnovate.saml.spi.includeRequestAuthnContext\" is false" );
		}
		xmlString = xmlString + "</samlp:AuthnRequest>";
		
		if (LOGGER.isLoggable(Level.FINEST)) {
			LOGGER.finest(xmlString);
		}
		LOGGER.exiting(LOGGER_CLASS, "getAuthnRequest-2");
		return xmlString;
	}

/**
	private String getAzureAuthnRequest() {
		/**
		 * https://docs.microsoft.com/en-us/azure/active-directory/develop/single-sign-on-saml-protocol
		 * 
		 * <samlp:AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:metadata"
		 * 		ID="F84D888AA3B44C1B844375A4E8210D9E"
		 * 		Version="2.0"
		 * 		IssueInstant="2018-09-21T09:09:45.354Z"
		 * 		IsPassive="false"
		 * 		AssertionConsumerServiceURL="https://151.136.217.93/samlsps/samlsnoop"
		 * 		xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
		 * >
		 *	<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">https://151.136.217.93/samlsps/samlsnoop</Issuer>
		 *	<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" />
		 *</samlp:AuthnRequest>

		// Execution starts here!! insert an END-COMMENT in the line above!
		LOGGER.entering(LOGGER_CLASS, "getAzureAuthnRequest");
		//
		// Using new String to ensure that the string can be cleaned up
		String xmlString = new String("<samlp:AuthnRequest xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" \n"
				+ "ID=\""+ requestId + "\" \n"
				+ "Version=\"2.0\" \n"
				+ "IssueInstant=\""+ issueInstant + "\" \n"
				+ "Destination=\""+ destination + "\" \n"
				+ "IsPassive=\"false\" \n"
				+ "AssertionConsumerServiceURL=\"" + assertionConsumerServiceURL + "\" \n"
				+ "ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" \n"
				+ "xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \n"
				+ "ProviderName=\""+ providerName + "\" \n"
				+ "> \n"
				+ "<Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\">" + issuer + "</Issuer> \n"
				+ "<samlp:NameIDPolicy Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\" /> \n"
				);
		xmlString = xmlString + "</samlp:AuthnRequest>";
		
		if (LOGGER.isLoggable(Level.FINEST)) {
			LOGGER.finest(xmlString);
		}
		LOGGER.exiting(LOGGER_CLASS, "getAzureAuthnRequest");
		return xmlString;
	}
**/

	@Override
	public String getIdentityProviderOrErrorURL(HttpServletRequest arg0, String arg1, String arg2, ArrayList<String> arg3) throws NotImplementedException {
		return null;
	}

	private String getRequestId() {
		return new UID().toString().replaceAll(":", "-");
	}
	
	private String getProviderName() {
		LOGGER.entering(LOGGER_CLASS, "getProviderName");
		String rtnString = "";
		
		try {
			InitialContext ic = new javax.naming.InitialContext();
			String serverName = ic.lookup("servername").toString();
			String cellName = ic.lookup("thisNode/cell/cellname").toString();
			String nodeName = ic.lookup("thisNode/nodename").toString();
			rtnString = cellName + "-" + nodeName + "-" + serverName;
		} catch (NamingException e) {
			if (LOGGER.isLoggable(Level.FINE)) {
				String ex = e.toString();
				LOGGER.fine("Received exception while retrieving values fron initial context: " + ex);
			}
			rtnString = ServerName.getFullName().replaceAll("\\", "-");
			LOGGER.warning("Retrieved provider name via deprecated API getFullName");
		}
		
		if (LOGGER.isLoggable(Level.FINE)) {
			LOGGER.fine("Calculated provider name: " + rtnString);
		}
		LOGGER.exiting(LOGGER_CLASS, "getProviderName");
		return rtnString;
	} // getProviderName

	private String getSystemProperty(String propName, String defaultValue) {
		LOGGER.entering(LOGGER_CLASS, "getSystemProperty-2: " + propName);

		String rtnString = defaultValue;
		
		String propValue = System.getProperty(propName);
		LOGGER.fine("propValue for property " + propName + " is: " + propValue);
		if (propValue != null) {
			rtnString = propValue;
		} else {
			LOGGER.fine("System property " + propName + " is null!");
		}
		
		LOGGER.exiting(LOGGER_CLASS, "getSystemProperty-2: " + propName + ". Returning: " + rtnString);
		return rtnString;
	} // getSystemProperty

	private String getSystemProperty(String propName) {
		LOGGER.entering(LOGGER_CLASS, "getSystemProperty-1: " + propName);

		String rtnString = getSystemProperty(propName, null);
		
		LOGGER.exiting(LOGGER_CLASS, "getSystemProperty-1: " + propName + ". Returning: " + rtnString);
		return rtnString;
	} // getSystemProperty

	private Boolean getBooleanSystemProperty(String propName, Boolean defaultValue) {
		LOGGER.entering(LOGGER_CLASS, "getBooleanSystemProperty: " + propName);

		Boolean rtnBoolean = defaultValue;
		
		String propValue = getSystemProperty(propName);
		LOGGER.fine("propValue for property " + propName + " is: " + propValue);
		if (propValue != null) {
			rtnBoolean = Boolean.valueOf(propValue);
		} else {
			LOGGER.fine("System property " + propName + " is null!");
		}
		
		LOGGER.exiting(LOGGER_CLASS, "getBooleanSystemProperty: " + propName + ". Returning: " + rtnBoolean.toString());
		return rtnBoolean;
	} // getSystemProperty

	private String getNameIdFormat() {
		LOGGER.entering(LOGGER_CLASS, "getNameIdFormat");

		String tmpValue = "";
		String propValue = System.getProperty(NAME_ID_FORMAT_PROPERTY_NAME);

		if (propValue != null) {
			tmpValue = propValue;
			LOGGER.fine( String.format("nameIdFormat being used taken from property \"%s\" is: \"%s\"", NAME_ID_FORMAT_PROPERTY_NAME, tmpValue) );
		} else {
			tmpValue = DEFAULT_NAME_ID_FORMAT;
			LOGGER.fine( String.format("System property \"%s\" not found. Using default nameIdFormat \"%s\"", NAME_ID_FORMAT_PROPERTY_NAME, tmpValue) );
		}

		LOGGER.exiting(LOGGER_CLASS, "getNameIdFormat. Returning: " + tmpValue);
		return tmpValue;
	} // getNameIdFormat

	private void setVarsFromSystemProperties() {
		LOGGER.entering(LOGGER_CLASS, "setVarsFromSystemProperties");
		// Check if the AuthnRequest XML should be BASE64 encoded 
		if (doEncodeAuthnRequestXML == null) {
			doEncodeAuthnRequestXML = getBooleanSystemProperty(ENCODE_AUTHN_REQUEST_XML_PROPERTY_NAME, true);
			LOGGER.fine("doEncodeAuthnRequestXML is: " + doEncodeAuthnRequestXML.booleanValue());
		}
		// Check if the RequestedAuthnContext attribute should included 
		if (doIncludeRequestAuthnContext == null) {
			doIncludeRequestAuthnContext = getBooleanSystemProperty(INCLUDE_AUTHN_CONTEXT_PROPERTY_NAME, true);
			LOGGER.fine("doIncludeRequestAuthnContext is: " + doIncludeRequestAuthnContext.booleanValue());
		}
		// Check if we should use Azure format 
		if (doUseAzureFormat == null) {
			doUseAzureFormat = getBooleanSystemProperty(USE_AZURE_FORMAT_PROPERTY_NAME, true);
			LOGGER.fine("doUseAzureFormat is: " + doUseAzureFormat.booleanValue());
		}
		LOGGER.exiting(LOGGER_CLASS, "setVarsFromSystemProperties");
	} // setSystemProperties

	private String getServletRequest(HttpServletRequest samlServletRequest) {
		LOGGER.entering(LOGGER_CLASS, "getServletRequest");
		
		String rtnString;
		Map<String, String[]> paramMap = null;
		
		rtnString = samlServletRequest.getRequestURL().toString();
		if (LOGGER.isLoggable(Level.FINEST)) {
			String paramValue = "";
			String requestMethod = samlServletRequest.getMethod();

			paramMap = samlServletRequest.getParameterMap();
			LOGGER.finest("Size of parameter map is: " + paramMap.size());
			LOGGER.finest("samlServletRequest request method is: " + requestMethod);
			for (String key : paramMap.keySet()){
				paramValue = "";
				for (String arrayItem : paramMap.get(key)) {
					paramValue += paramValue + arrayItem + "\n";
				}
				LOGGER.finest("Parameter Name: " + key +"; Value: " + paramValue);
			}
		}
		LOGGER.exiting(LOGGER_CLASS, "getServletRequest. Returning: " + rtnString);
		return rtnString;
	}
}
