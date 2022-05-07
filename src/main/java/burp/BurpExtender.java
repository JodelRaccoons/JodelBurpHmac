package burp;

import com.google.common.base.Joiner;
import com.google.common.escape.Escaper;
import com.google.common.net.UrlEscapers;
import okio.Buffer;
import okio.ByteString;
import parser.Request;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/*
 * Signing copied from https://github.com/Jupiops/JodelAPI
 * */

public class BurpExtender implements IBurpExtender, ISessionHandlingAction, ITab, IHttpListener {

    private static final Escaper ESCAPER = UrlEscapers.urlFormParameterEscaper();
    static String extensionName = "HmacInterceptor";
    // some default values
    public final static String DEFAULT_HMAC_KEY_ANDROID = "swbBCdBLdtvSqgflkjyrvVwiVHMZSQDQzQWsPiMg";
    public final static String DEFAULT_HMAC_KEY_IOS = "ITphnJSfuGskaTENCxRIPbiiaMScFRhycyZvFNaT";
    public final static String DEFAULT_VERSION_ANDROID = "7.25.8";
    public final static String DEFAULT_VERSION_IOS = "7.26";
    final String DEFAULT_API_VERSION = "0.2";
    final String DEFAULT_LOCATION = "52.504062;13.386062";
    IExtensionHelpers helpers = null;
    Pattern accessTokenPattern = Pattern.compile("access_token\":\"(.*?)\"");
    Pattern refreshTokenPattern = Pattern.compile("refresh_token\":\"(.*?)\"");
    IBurpExtenderCallbacks callbacks = null;
    private BurpTab tab;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName(extensionName);
        this.helpers = callbacks.getHelpers();
        callbacks.registerSessionHandlingAction(this);
        callbacks.registerHttpListener(this);

        // create our UI
        SwingUtilities.invokeLater(() -> {
            tab = new BurpTab();

            // set some default values
            tab.setApiVersion(DEFAULT_API_VERSION);
            tab.setHmacKey(DEFAULT_HMAC_KEY_ANDROID);
            tab.setVersion(DEFAULT_VERSION_ANDROID);
            tab.setLocationText(DEFAULT_LOCATION);

            tab.setCustomUATextFieldEnabled(false);

            // customize our UI components
            callbacks.customizeUiComponent(tab);
            callbacks.addSuiteTab(BurpExtender.this);

            tab.appendLog("[+] HMAC signing extension loaded");
        });

        callbacks.printOutput("[+] HMAC signing extension loaded");
    }

    // methods below from ISessionHandlingAction
    @Override
    public String getActionName() {
        return extensionName;
    }

    public byte[] signRequest(byte[] currentRequest, String signingKey, String jodelVersion, String userAgent, String xClientType, String xApiVersion) {
        Request mRequest = Request.parse(currentRequest);

        logVerbose("[+] Signing request to " + mRequest.getUrl());

        // get all url parameters, stream an entry set, escape one by one, collect them to map
        logVerbose("\t[+] URL parameters: ");
        SortedMap<String, String> parameters = new TreeMap<>(mRequest.getUrlParameters().entrySet().stream().map(entry -> new AbstractMap.SimpleEntry<>(ESCAPER.escape(entry.getKey()),ESCAPER.escape(entry.getValue()))).collect(Collectors.toMap(AbstractMap.SimpleEntry::getKey, AbstractMap.SimpleEntry::getValue)));
        parameters.forEach((s1, s2) -> logVerbose("\t" + s1 + "=" + s2));

        String timestamp = Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
        logVerbose("\t[+] Timestamp: " + timestamp);

        // get access token from previous headers if existend (not existend on login)
        // should already be updated if neccessary from previous method
        String accessToken = mRequest.getHttpHeader("Authorization");
        logVerbose("\t[+] Access token: " + accessToken);

        // get location from previous headers if existent. If not existent, location will be taken from options and header will be appended
        // if location should be updated forcefully, do so
        String location = tab.getUpdateLocation() ? tab.getLocationText() : (mRequest.getHttpHeader("X-Location").isEmpty() ? tab.getLocationText() : mRequest.getHttpHeader("X-Location"));
        logVerbose("\t[+] Location: " + location);

        // create base buffer to create HMACable string
        Buffer base = new Buffer();
        base.writeUtf8(mRequest.getHttpMethod())
                .writeByte('%')
                .writeUtf8(ESCAPER.escape(mRequest.getHost()))
                .writeByte('%')
                .writeUtf8(String.valueOf(443))
                .writeByte('%')
                .writeUtf8(mRequest.getUriPath())
                .writeByte('%')
                .writeUtf8(!accessToken.isEmpty() ? accessToken.substring(7).trim() + "%" : "%");

        if (!mRequest.getUriPath().equals("v2/users/") || !mRequest.getUriPath().equals("v2/users"))
            base.writeUtf8(location.trim()).writeByte('%');

        base.writeUtf8(timestamp)
                .writeByte('%')
                .writeUtf8(Joiner.on("%").withKeyValueSeparator("%").join(parameters)).writeByte('%')
                .writeUtf8(Objects.requireNonNullElse(mRequest.getBody(), ""));

        logVerbose("\t[+] Constructed HMAC String: " + base.clone().readUtf8());

        // do the signing
        String signature = calculateHMAC(signingKey, base.readByteArray());

        // create new headers, overwrite old ones if neccessary
        mRequest.setHttpHeader("User-Agent", userAgent.contains("%s") ? String.format(userAgent, jodelVersion) : userAgent); //"Jodel/%s (iPhone; iOS 12.5.2; Scale/2.00)") if UA string contains placeholder, add version else not
        mRequest.setHttpHeader("X-Timestamp", timestamp);
        mRequest.setHttpHeader("X-Client-Type", String.format(xClientType, jodelVersion)); // "ios_%s"
        mRequest.setHttpHeader("X-Api-Version", xApiVersion); //"0.2"
        mRequest.setHttpHeader("X-Authorization", "HMAC " + signature);
        mRequest.setHttpHeader("X-Location", location.trim());

        // create list of all headers
        logVerbose("\t[+] New header:");
        mRequest.getHttpHeaders().forEach((s, s2) -> logVerbose("\t    " + s + ": " + s2));

        tab.appendLog("[+] Generated signature " + signature + " for request " + mRequest.getUrl());

        // build new request with adjusted headers
        return mRequest.build();
    }

    private String calculateHMAC(String signingKey, byte[] value) {
        SecretKeySpec keySpec = new SecretKeySpec(signingKey.getBytes(), "HmacSHA1");
        Mac mac;
        try {
            mac = Mac.getInstance("HmacSHA1");
            mac.init(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new IllegalStateException(e);
        }
        byte[] result = mac.doFinal(value);
        return ByteString.of(result).hex().toUpperCase();
    }

    private void logVerbose(String log) {
        if (tab.verboseLogging()) {
            tab.appendLog(log);
        }
    }

    @Override
    public void performAction(IHttpRequestResponse currentRequest, IHttpRequestResponse[] macroItems) {
        IRequestInfo rqInfo = helpers.analyzeRequest(currentRequest);
        if (tab.enabled() && (rqInfo.getUrl().toString().contains("api.jodelapis.com") || rqInfo.getUrl().toString().contains("api.go-tellm.com"))) {
            byte[] updatedRequest = tab.getToggleReplaceAccessToken() ? updateAccessTokenIfPresent(rqInfo, currentRequest.getRequest()) : currentRequest.getRequest();
            byte[] signedRequest = this.signRequest(updatedRequest, tab.getHmacKey(), tab.getVersion(), tab.getUserAgent(), tab.getClientType(), tab.getApiVersion());
            currentRequest.setRequest(signedRequest);
        }
    }
    // end ISessionHandlingAction methods

    // ITab methods
    @Override
    public String getTabCaption() {
        return extensionName;
    }

    @Override
    public Component getUiComponent() {
        return tab;
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse currentRequestResponse) {
        IRequestInfo rqInfo = helpers.analyzeRequest(currentRequestResponse.getHttpService(), currentRequestResponse.getRequest());
        if (rqInfo.getUrl().toString().contains("api.jodelapis.com") || rqInfo.getUrl().toString().contains("api.go-tellm.com")) {
            if (!messageIsRequest) {
                IResponseInfo rsInfo = helpers.analyzeResponse(currentRequestResponse.getResponse());
                if (rsInfo.getStatusCode() == 401) {
                    // token could be expired, lets try to get a new one using the refresh token
                } else if (rsInfo.getStatusCode() == 200 && tab.scrapeTokensFromResponses()) {
                    extractTokensFromResponse(currentRequestResponse, rsInfo, rqInfo);
                }
            }
        }

    }

    private void extractTokensFromResponse(IHttpRequestResponse currentRequestResponse, IResponseInfo rsInfo, IRequestInfo rqInfo) {
        String responseBody = new String(Arrays.copyOfRange(currentRequestResponse.getResponse(), rsInfo.getBodyOffset(), currentRequestResponse.getResponse().length));
        if (responseBody.contains("\"access_token\":")) {
            tab.appendLog("[+] Caught response from request to " + rqInfo.getUrl());
            Matcher accessTokenMatcher = accessTokenPattern.matcher(responseBody);
            if (accessTokenMatcher.find()) {
                tab.appendLog("\t[+] Got access token: " + accessTokenMatcher.group(1));
                tab.setTextFieldAccessToken(accessTokenMatcher.group(1));
            } else {
                logVerbose(responseBody);
            }
        }
        if (responseBody.contains("\"refresh_token\":")) {
            Matcher refreshTokenMatcher = refreshTokenPattern.matcher(responseBody);
            if (refreshTokenMatcher.find()) {
                tab.appendLog("\t[+] Got refresh token: " + refreshTokenMatcher.group(1));
                tab.setTextFieldRefreshToken(refreshTokenMatcher.group(1));
            } else {
                logVerbose(responseBody);
            }
        }
    }

    private byte[] updateAccessTokenIfPresent(IRequestInfo rqInfo, byte[] request) {
        if (!tab.getTextFieldAccessToken().isEmpty() && !rqInfo.getHeaders().get(0).contains("POST /api/v2/users/ HTTP")) {
            logVerbose("[+] Updating authorization header");
            Map<String, String> headerMap = rqInfo.getHeaders().stream().filter(s -> s.contains(":")).collect(Collectors.toMap(s -> s.substring(0, s.indexOf(":")), s -> s.substring(s.indexOf(":") + 2)));

            logVerbose("\t[+] " + headerMap.get("Authorization") + " -> " + tab.getTextFieldAccessToken().trim());
            headerMap.put("Authorization", "Bearer " + tab.getTextFieldAccessToken().trim());
            List<String> headerList = headerMap.keySet().stream().map(s -> s + ": " + headerMap.get(s).trim()).collect(Collectors.toList());
            headerList.add(0, rqInfo.getHeaders().get(0));
            return helpers.buildHttpMessage(new ArrayList<>(headerList), Arrays.copyOfRange(request, rqInfo.getBodyOffset(), request.length));
        }
        logVerbose("[-] No access_token present, please enter one or issue an user creation request (with enabled response scraping)");
        return request;
    }
    // end ITab methods

}
