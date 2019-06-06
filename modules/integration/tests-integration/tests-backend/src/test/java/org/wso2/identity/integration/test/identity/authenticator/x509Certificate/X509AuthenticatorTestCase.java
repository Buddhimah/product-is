package org.wso2.identity.integration.test.identity.authenticator.x509Certificate;


import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.http.Header;
import org.apache.http.HttpResponse;
import org.apache.http.client.CookieStore;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;
import org.wso2.carbon.automation.engine.context.TestUserMode;
import org.wso2.carbon.automation.engine.frameworkutils.FrameworkPathUtil;
import org.wso2.carbon.identity.application.common.model.script.xsd.AuthenticationScriptConfig;
import org.wso2.carbon.identity.application.common.model.xsd.AuthenticationStep;
import org.wso2.carbon.identity.application.common.model.xsd.InboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.xsd.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.xsd.LocalAndOutboundAuthenticationConfig;
import org.wso2.carbon.identity.application.common.model.xsd.LocalAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.xsd.ServiceProvider;
import org.wso2.carbon.identity.authenticator.x509Certificate.X509CertificateAuthenticator;
import org.wso2.carbon.identity.sso.saml.stub.types.SAMLSSOServiceProviderDTO;
import org.wso2.carbon.integration.common.admin.client.UserManagementClient;
import org.wso2.carbon.integration.common.utils.LoginLogoutClient;
import org.wso2.carbon.integration.common.utils.mgt.ServerConfigurationManager;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.mgt.stub.UserAdminUserAdminException;
import org.wso2.identity.integration.common.clients.application.mgt.ApplicationManagementServiceClient;
import org.wso2.identity.integration.common.clients.sso.saml.SAMLSSOConfigServiceClient;
import org.wso2.identity.integration.common.clients.usermgt.remote.RemoteUserStoreManagerServiceClient;
import org.wso2.identity.integration.common.utils.ISIntegrationTest;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Factory;
import org.testng.annotations.Test;
import org.wso2.identity.integration.test.util.Utils;
import org.wso2.identity.integration.test.utils.CommonConstants;
import org.wso2.carbon.security.ui.ServiceHolder;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.rmi.RemoteException;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;
import javax.net.ssl.SSLContext;

import static org.wso2.identity.integration.test.util.Utils.extractDataFromResponse;

public class X509AuthenticatorTestCase extends ISIntegrationTest {

    private ServerConfigurationManager serverConfigurationManager;
    private UserManagementClient userManagementClient;
    private X509CertificateAuthenticator x509CertificateAuthenticator;
    private SPConfig config;
    private static final String APPLICATION_NAME = "travelocity.com";
    private static final String INBOUND_AUTH_TYPE = "samlsso";
    private ApplicationManagementServiceClient applicationManagementServiceClient;
    private RemoteUserStoreManagerServiceClient remoteUSMServiceClient;
    private static final String ACCOUNT_LOCK_CLAIM_URI = "http://wso2.org/claims/identity/accountLocked";
    private static final String profileName = "default";
    private SAMLSSOConfigServiceClient ssoConfigServiceClient;
    private CloseableHttpClient httpClient;
    private CookieStore cookieStore = new BasicCookieStore();
    private static final String SAML_SSO_LOGIN_URL = "http://localhost:8490/%s/samlsso?SAML2.HTTPBinding=%s";
    private static final String USER_AGENT = "Apache-HttpClient/4.2.5 (java 1.5)";
    private static final String SAML_SSO_URL = "https://localhost:" + CommonConstants.IS_DEFAULT_HTTPS_PORT +
            "/samlsso";
    private static final String X509_SSO_URL = "https://localhost:" + CommonConstants.IS_DEFAULT_HTTPS_PORT +
            "/x509Certificate-certificate-servlet?commonAuthCallerPath=%2Fsamlsso";

    public static final String TENANT_DOMAIN_PARAM = "tenantDomain";
    private String SAML_ISSUER = "travelocity.com";
    private static final String ACS_URL = "http://localhost:8490/%s/home.jsp";
    private static final String NAMEID_FORMAT =
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
    private static final String ATTRIBUTE_CS_INDEX_VALUE = "1239245949";
    private static final String LOGIN_URL = "/carbon/admin/login.jsp";




    private enum SPApplication {
        SUPER_TENANT_APP(APPLICATION_NAME);
        private String artifact;

        SPApplication(String artifact) {
            this.artifact = artifact;
        }

        public String getArtifact() {
            return artifact;
        }
    }

    private void createLocalAndOutBoundAuthenticator() throws Exception {
        switch (config.getAuthenticator()) {
        case DEFAULT_AUTHENTICATOR:
            createDefaultAuthenticator();
            break;
        case ADVANCED_AUTHENTICATOR:
            createAdvanceAuthenticatorWithMultiOptions();
            break;
        case FEDERATED_AUTHENTICATOR:
            createFederatedAuthenticator();
            break;
        case LOCAL_AUTHENTICATOR:
            createLocalAuthenticator();
            break;
        default:
            createDefaultAuthenticator();
            break;
        }

    }

    private void createApplication() throws Exception {

        ServiceProvider serviceProvider = new ServiceProvider();
        serviceProvider.setApplicationName(APPLICATION_NAME);
        serviceProvider.setDescription("This is a test Service Provider");
        applicationManagementServiceClient.createApplication(serviceProvider);
        serviceProvider = applicationManagementServiceClient.getApplication(APPLICATION_NAME);

        InboundAuthenticationRequestConfig requestConfig = new InboundAuthenticationRequestConfig();
        requestConfig.setInboundAuthType(INBOUND_AUTH_TYPE);
        requestConfig.setInboundAuthKey(config.getApplication().getArtifact());

        InboundAuthenticationConfig inboundAuthenticationConfig = new InboundAuthenticationConfig();
        inboundAuthenticationConfig.setInboundAuthenticationRequestConfigs(
                new InboundAuthenticationRequestConfig[]{requestConfig});

        serviceProvider.setInboundAuthenticationConfig(inboundAuthenticationConfig);
        serviceProvider.setLocalAndOutBoundAuthenticationConfig(config.getAuthenticator()
                .getLocalAndOutboundAuthenticationConfig());
        applicationManagementServiceClient.updateApplicationData(serviceProvider);
    }

    private void deleteApplication() throws Exception {
        applicationManagementServiceClient.deleteApplication(APPLICATION_NAME);
    }

    private enum User {
        SUPER_TENANT_USER("admin", "admin", "carbon.super", "samluser1@wso2.com", "samlnickuser1",
                "admin", "");

        private String username;
        private String password;
        private String tenantDomain;
        private String email;
        private String nickname;
        private String tenantAwareUsername;
        private String expectedErrorcode;

        User(String username, String password, String tenantDomain, String email, String nickname, String
                tenantAwareUsername, String expectedErrorcode) {
            this.username = username;
            this.password = password;
            this.tenantDomain = tenantDomain;
            this.email = email;
            this.nickname = nickname;
            this.tenantAwareUsername = tenantAwareUsername;
            this.expectedErrorcode = expectedErrorcode;
        }


        public String getNickname() {
            return nickname;
        }

        public String getEmail() {
            return email;
        }

        public String getTenantDomain() {
            return tenantDomain;
        }

        public String getPassword() {
            return password;
        }

        public String getUsername() {
            return username;
        }

        public String getTenantAwareUsername() {
            return tenantAwareUsername;
        }

        public String getExpectedErrorcode() {
            return expectedErrorcode;
        }

        public void setExpectedErrorcode(String expectedErrorcode) {
            this.expectedErrorcode = expectedErrorcode;
        }
    }

    private static class SPConfig {
        private Authenticator authenticator;
        private User user;
        private SPApplication application;
        private TestUserMode userMode;
        private HttpBinding httpBinding;

        private SPConfig(Authenticator authenticator, User user, SPApplication application, TestUserMode userMode,
                HttpBinding httpBinding) {
            this.authenticator = authenticator;
            this.user = user;
            this.application = application;
            this.userMode = userMode;
            this.httpBinding = httpBinding;
        }

        public SPApplication getApplication() {
            return application;
        }

        public User getUser() {
            return user;
        }

        public Authenticator getAuthenticator() {
            return authenticator;
        }

        public TestUserMode getUserMode() {
            return userMode;
        }

        public HttpBinding getHttpBinding() {
            return httpBinding;
        }
    }

    private enum Authenticator {
        DEFAULT_AUTHENTICATOR, LOCAL_AUTHENTICATOR, FEDERATED_AUTHENTICATOR, ADVANCED_AUTHENTICATOR;
        private LocalAndOutboundAuthenticationConfig localAndOutboundAuthenticationConfig;

        public LocalAndOutboundAuthenticationConfig getLocalAndOutboundAuthenticationConfig() {
            return localAndOutboundAuthenticationConfig;
        }

        public void setLocalAndOutboundAuthenticationConfig(LocalAndOutboundAuthenticationConfig
                localAndOutboundAuthenticationConfig) {
            this.localAndOutboundAuthenticationConfig = localAndOutboundAuthenticationConfig;
        }
    }

    private enum HttpBinding {
        HTTP_REDIRECT("HTTP-Redirect"),
        HTTP_POST("HTTP-POST");

        String binding;

        HttpBinding(String binding) {
            this.binding = binding;
        }
    }

    @Factory(dataProvider = "spConfigProvider")
    public X509AuthenticatorTestCase(SPConfig config) {
        if (log.isDebugEnabled()) {
            log.info("SAML LocalAndOutboundAuthenticators Test initialized for " + config);
        }
        this.config = config;
    }

    @DataProvider(name = "spConfigProvider")
    public static SPConfig[][] spConfigProvider() {
        return new SPConfig[][]{
                {new SPConfig(
                        Authenticator.LOCAL_AUTHENTICATOR, User.SUPER_TENANT_USER, SPApplication
                        .SUPER_TENANT_APP, TestUserMode.SUPER_TENANT_USER, HttpBinding.HTTP_POST)},
                };
    }

    /**
     * Create the Default Authenticator.
     * Use this method to assign properties to the default authenticator.
     */
    private void createDefaultAuthenticator() {
        config.getAuthenticator().setLocalAndOutboundAuthenticationConfig(new LocalAndOutboundAuthenticationConfig());
    }

    /**
     * Create the AdvancedAuthenticator with Multi options.
     * Use any attributes needed if needed to do multiple tests with different advanced authenticators.
     * @throws Exception
     */
    private void createAdvanceAuthenticatorWithMultiOptions() throws Exception {
        // This method needed to be implemented as expected for the testcase
    }

    /**
     * Create the federated authenticator as needed for the test
     */
    private void createFederatedAuthenticator() {
        // This method needed to be implemented as expected for the testcase
    }

    /**
     * Create the local authenticator as needed for the test
     */
    private void createLocalAuthenticator() throws Exception {
        LocalAndOutboundAuthenticationConfig localAndOutboundAuthenticationConfig =
                new LocalAndOutboundAuthenticationConfig();

        ServiceProvider serviceProvider;
        serviceProvider = applicationManagementServiceClient.getApplication(APPLICATION_NAME);
        localAndOutboundAuthenticationConfig.setUseTenantDomainInLocalSubjectIdentifier(true);
        localAndOutboundAuthenticationConfig.setUseUserstoreDomainInLocalSubjectIdentifier(true);
        localAndOutboundAuthenticationConfig.setUseUserstoreDomainInRoles(true);
        localAndOutboundAuthenticationConfig.setAuthenticationType("local");
        serviceProvider.setLocalAndOutBoundAuthenticationConfig(localAndOutboundAuthenticationConfig);
        AuthenticationStep authStep = new AuthenticationStep();
        authStep.setStepOrder(1);
        authStep.setAttributeStep(true);
        authStep.setSubjectStep(true);
        LocalAuthenticatorConfig localAuthenticatorConfig = new LocalAuthenticatorConfig();
        localAuthenticatorConfig.setName("x509CertificateAuthenticator");
        localAuthenticatorConfig.setDisplayName("X509Certificate");
        localAuthenticatorConfig.setEnabled(true);
        authStep.setLocalAuthenticatorConfigs(new LocalAuthenticatorConfig[]{localAuthenticatorConfig});
        serviceProvider.getLocalAndOutBoundAuthenticationConfig().setAuthenticationSteps(
                new AuthenticationStep[]{authStep});

        AuthenticationScriptConfig scriptConfig = new AuthenticationScriptConfig();
        scriptConfig.setLanguage("application/javascript");
        scriptConfig.setContent("function onLoginRequest(context) {\r\n  executeStep(1);\r\n}\r\n");
        serviceProvider.getLocalAndOutBoundAuthenticationConfig().setAuthenticationScriptConfig(scriptConfig);

        applicationManagementServiceClient.updateApplicationData(serviceProvider);
        config.getAuthenticator().setLocalAndOutboundAuthenticationConfig(localAndOutboundAuthenticationConfig);
    }

    @BeforeClass(alwaysRun = true)
    public void testInit() throws Exception {

        super.init(TestUserMode.SUPER_TENANT_ADMIN);

        String pathToApplicationAuthenticationXML =
                FrameworkPathUtil.getSystemResourceLocation() + "artifacts" + File.separator + "IS" + File.separator
                        + "authenticator" + File.separator + "x509Certificate" + File.separator
                        + "application-authentication.xml";

        String pathToCatalinaServerXML =
                FrameworkPathUtil.getSystemResourceLocation() + "artifacts" + File.separator + "IS" + File.separator
                        + "authenticator" + File.separator + "x509Certificate" + File.separator
                        + "catalina-server.xml";


        String targetApplicationAuthenticationXML =
                Utils.getResidentCarbonHome() + File.separator + "repository" + File.separator + "conf" + File.separator
                        + "identity" + File.separator + "application-authentication.xml";

        String pathToCertificateValidationXML =
                FrameworkPathUtil.getSystemResourceLocation() + "artifacts" + File.separator + "IS" + File.separator
                        + "authenticator" + File.separator + "x509Certificate" + File.separator
                        + "certificate-validation.xml";


        String targetCertificateValidationXML =
                Utils.getResidentCarbonHome() + File.separator + "repository" + File.separator + "conf" + File.separator
                        + "security" + File.separator + "certificate-validation.xml";

        String targetCatalinaServerXML =
                Utils.getResidentCarbonHome() + File.separator + "repository" + File.separator + "conf" + File.separator
                        + "tomcat" + File.separator + "catalina-server.xml";

        String pathToKeyStore =
                FrameworkPathUtil.getSystemResourceLocation() + "artifacts" + File.separator + "IS" + File.separator
                        + "authenticator" + File.separator + "x509Certificate" + File.separator
                        + "client-truststore.jks";

        String targetKeyStore =
                Utils.getResidentCarbonHome() + File.separator + "repository" + File.separator + "resources" + File.separator
                        + "security" + File.separator + "client-truststore.jks";

        String pathToLog4jProperties =
                FrameworkPathUtil.getSystemResourceLocation() + "artifacts" + File.separator + "IS" + File.separator
                        + "authenticator" + File.separator + "x509Certificate" + File.separator
                        + "log4j.properties";

        String targetLog4jProperties =
                Utils.getResidentCarbonHome() + File.separator + "repository" + File.separator + "conf" + File.separator
                        + "log4j.properties";


        serverConfigurationManager = new ServerConfigurationManager(isServer);

        serverConfigurationManager.applyConfigurationWithoutRestart(new File(pathToApplicationAuthenticationXML),
                new File(targetApplicationAuthenticationXML), true);
        serverConfigurationManager.applyConfigurationWithoutRestart(new File(pathToCatalinaServerXML),
                new File(targetCatalinaServerXML), true);
        serverConfigurationManager.applyConfigurationWithoutRestart(new File(pathToKeyStore),
                new File(targetKeyStore), true);
        serverConfigurationManager.applyConfigurationWithoutRestart(new File(pathToLog4jProperties),
                new File(targetLog4jProperties), true);
        serverConfigurationManager.restartGracefully();
        super.init(TestUserMode.SUPER_TENANT_ADMIN);
        remoteUSMServiceClient = new RemoteUserStoreManagerServiceClient(backendURL, sessionCookie);
        ConfigurationContext configContext = ConfigurationContextFactory
                .createConfigurationContextFromFileSystem(null, null);
        httpClient = (CloseableHttpClient) getHttpClient();
        applicationManagementServiceClient = new ApplicationManagementServiceClient(sessionCookie, backendURL,
                configContext);
        ssoConfigServiceClient = new SAMLSSOConfigServiceClient(backendURL, sessionCookie);

        loginLogoutClient = new LoginLogoutClient(isServer);
        ServiceHolder serviceHoldler = ServiceHolder.getInstance();
        RegistryService regService = serviceHoldler.getRegistryService();
        org.wso2.carbon.registry.core.Registry systemRegistry = regService.getConfigSystemRegistry();
        Resource ocspvalidator = systemRegistry.get("/_system/governance/repository/security/certificate/validator/ocspvalidator");

        Resource crlvalidator = systemRegistry.get("/_system/governance/repository/security/certificate/validator/crlvalidator");

        ocspvalidator.setProperty("enable","false");
        crlvalidator.setProperty("enable","false");


        ssoConfigServiceClient = new SAMLSSOConfigServiceClient(backendURL, sessionCookie);
        ssoConfigServiceClient.addServiceProvider(createSsoServiceProviderDTO());
        createApplication();
        createLocalAndOutBoundAuthenticator();

        userManagementClient = new UserManagementClient(backendURL, getSessionCookie());
        userManagementClient.addUser("rashmi", "admin", new String[]{"Internal/everyone"}, null);


    }

    private SAMLSSOServiceProviderDTO createSsoServiceProviderDTO() {
        SAMLSSOServiceProviderDTO samlssoServiceProviderDTO = new SAMLSSOServiceProviderDTO();
        samlssoServiceProviderDTO.setIssuer(SAML_ISSUER);
        samlssoServiceProviderDTO.setAssertionConsumerUrls(new String[] {String.format(ACS_URL,
                SAML_ISSUER)});
        samlssoServiceProviderDTO.setDefaultAssertionConsumerUrl(String.format(ACS_URL, SAML_ISSUER));
        samlssoServiceProviderDTO.setAttributeConsumingServiceIndex(ATTRIBUTE_CS_INDEX_VALUE);
        samlssoServiceProviderDTO.setNameIDFormat(NAMEID_FORMAT);
        samlssoServiceProviderDTO.setDoSignAssertions(false);
        samlssoServiceProviderDTO.setDoSignResponse(false);
        samlssoServiceProviderDTO.setDoSingleLogout(true);
        samlssoServiceProviderDTO.setLoginPageURL(LOGIN_URL);
        return samlssoServiceProviderDTO;
    }


    @AfterClass(alwaysRun = true)
    public void endTest() throws Exception {

        serverConfigurationManager.restoreToLastConfiguration(false);
        deleteApplication();
        deleteUser();

        ssoConfigServiceClient = null;
        applicationManagementServiceClient = null;

    }
    private void deleteUser() throws RemoteException, UserAdminUserAdminException {
        log.info("Deleting User " + config.getUser().getUsername());
        userManagementClient.deleteUser("buddhima");
    }

    @Test(groups = "wso2.is", description = "Trying to authenticate a user using x509Certificate certificate")
    public void testLoginWithX509Certificate() throws Exception {
        HttpResponse response;
        response = Utils.sendGetRequest(String.format(SAML_SSO_LOGIN_URL, config.getApplication().getArtifact(),
                config.getHttpBinding().binding), USER_AGENT, httpClient);
        if (config.getHttpBinding() == HttpBinding.HTTP_POST) {
            String samlRequest = extractDataFromResponse(response, CommonConstants.SAML_REQUEST_PARAM, 5);
            Map<String, String> paramters = new HashMap<>();
            paramters.put(CommonConstants.SAML_REQUEST_PARAM, samlRequest);
            response = Utils.sendSAMLMessage(SAML_SSO_URL, paramters, USER_AGENT, config.getUserMode(),
                    TENANT_DOMAIN_PARAM, config.getUser().getTenantDomain(), httpClient);
            String sessionKey = extractDataFromResponse(response, "name=\"sessionDataKey\"", 1);
            response = sendRedirectRequest(response);

        }
    }

    private HttpResponse sendRedirectRequest(HttpResponse response) throws IOException {

        Header[] headers = response.getAllHeaders();
        String url = "";
        for (Header header : headers) {
            if ("Location".equals(header.getName())) {
                url = header.getValue();
            }
        }

        HttpGet request = new HttpGet(url);
        request.addHeader("User-Agent", USER_AGENT);
        request.addHeader("Referer", String.format(ACS_URL, config.getApplication().getArtifact()));
        return httpClient.execute(request);
    }


    public HttpClient getHttpClient() throws Exception{

        String CERT_PASSWORD = "wso2carbon";

        String pathToClientCert =
                FrameworkPathUtil.getSystemResourceLocation() + "artifacts" + File.separator + "IS" + File.separator
                        + "authenticator" + File.separator + "x509Certificate" + File.separator
                        + "client.p12";
        KeyStore identityKeyStore = KeyStore.getInstance("PKCS12");
        FileInputStream identityKeyStoreFile = new FileInputStream(new File(pathToClientCert));
        identityKeyStore.load(identityKeyStoreFile, CERT_PASSWORD.toCharArray());

        SSLContext sslContext = SSLContexts.custom()
                .loadKeyMaterial(identityKeyStore, CERT_PASSWORD.toCharArray())
                .loadTrustMaterial(null, new TrustSelfSignedStrategy())
                .build();
        SSLConnectionSocketFactory sslConnectionFactory =
                new SSLConnectionSocketFactory(sslContext, SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
        Registry<ConnectionSocketFactory> registry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register("https", sslConnectionFactory)
                .register("http", new PlainConnectionSocketFactory())
                .build();
        BasicHttpClientConnectionManager connManager = new BasicHttpClientConnectionManager(registry);

        return HttpClients.custom()
                .setConnectionManager(connManager)
                .setSSLSocketFactory(sslConnectionFactory)
                .setHostnameVerifier(SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER)
                .build();


    }


}
