package parser;

import java.util.Comparator;
import java.util.Objects;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.function.Function;

@SuppressWarnings("unused")
public class Request {

    enum HttpVersion {

        HTTP_1_0,
        HTTP_1_1,
        HTTP_2;

        public static HttpVersion parse(String line) {
            String input = line.split(" ")[2];
            if (input.contains("1.0"))
                return HTTP_1_0;
            else if (input.contains("1.1"))
                return HTTP_1_1;
            else if (input.contains("/2"))
                return HTTP_2;
            throw new RuntimeException("Unsupported HTTP version:" + input);
        }

        @Override
        public String toString() {
            return switch (this) {
                case HTTP_2 -> "HTTP/2";
                case HTTP_1_0 -> "HTTP/1.0";
                case HTTP_1_1 -> "HTTP/1.1";
            };
        }
    }

    private final String httpMethod;
    private final String uriPath;
    private final HttpVersion httpVersion;
    private final SortedMap<String, String> httpHeaders;
    private final SortedMap<String, String> urlParameters;
    private final String body;
    private static final String SEPERATOR = System.lineSeparator();

    public static Request parse(byte[] request) {
        String[] mRequestLines = new String(request).split(SEPERATOR);
        String httpMethod = getHttpMethod(mRequestLines[0]);
        SortedMap<String, String> urlParameters = getUrlParameters(mRequestLines[0]);
        HttpVersion httpVersion = HttpVersion.parse(mRequestLines[0]);
        SortedMap<String, String> httpHeaders = parseHeaders(mRequestLines);
        String body = getBody(mRequestLines);
        String uri = getUri(mRequestLines[0]);
        return new Request(httpMethod, uri, httpVersion, httpHeaders, urlParameters, body);
    }

    public byte[] build() {
        StringBuilder mRequest = new StringBuilder(buildStatusLine());
        for (String headerName : httpHeaders.keySet()) {
            mRequest.append(headerName).append(": ").append(httpHeaders.get(headerName)).append(SEPERATOR);
        }
        mRequest.append(SEPERATOR).append(body);
        return mRequest.toString().getBytes();
    }

    private String buildStatusLine() {
        StringBuilder mRequest = new StringBuilder(httpMethod);
        mRequest.append(" ");
        mRequest.append(uriPath);
        if (!urlParameters.isEmpty()) {
            mRequest.append("?");
            for (String key : urlParameters.keySet()) {
                mRequest.append(key).append("=").append(urlParameters.get(key));
                if (!key.equals(urlParameters.lastKey())) {
                    mRequest.append("&");
                }
            }
        }
        mRequest.append(" ").append(httpVersion.toString()).append(SEPERATOR);
        return mRequest.toString();
    }

    public String getUrl() {
        return "https://" + getHost() + ":443" + getUriPath();
    }

    public String getHost() {
        return getHttpHeader("Host");
    }

    public String getHttpMethod() {
        return httpMethod;
    }

    public String getUriPath() {
        return uriPath;
    }

    public HttpVersion getHttpVersion() {
        return httpVersion;
    }

    public SortedMap<String, String> getHttpHeaders() {
        return httpHeaders;
    }

    public SortedMap<String, String> getUrlParameters() {
        return urlParameters;
    }

    public String getBody() {
        return body;
    }

    public String getHttpHeader(String name) {
        return httpHeaders.getOrDefault(name, "");
    }

    public String getUrlParameter(String name) {
        return urlParameters.getOrDefault(name, "");
    }

    public void setHttpHeader(String name, String value) {
        httpHeaders.put(name, value);
    }

    public void setUrlParameter(String name, String value) {
        urlParameters.put(name, value);
    }

    public Request(String httpMethod, String uriPath, HttpVersion httpVersion, SortedMap<String, String> httpHeaders, SortedMap<String, String> urlParameters, String body) {
        this.httpMethod = httpMethod;
        this.uriPath = uriPath;
        this.httpVersion = httpVersion;
        this.httpHeaders = httpHeaders;
        this.urlParameters = urlParameters;
        this.body = body;
    }

    private static String getUri(String firstLine) {
        String uriPart = firstLine.split(" ")[1];
        if (uriPart.contains("?")) {
            uriPart = uriPart.split("\\?")[0];
        }
        return uriPart;
    }

    private static String getBody(String... lines) {
        StringBuilder bodyString = new StringBuilder();
        boolean reachedBody = false;
        for (String line : lines) {
            if (!reachedBody) {
                if (line.isEmpty())
                    reachedBody = true;
            } else {
                bodyString.append(line);
            }
        }
        return bodyString.toString().trim();
    }

    private static SortedMap<String, String> parseHeaders(String... lines) {
        SortedMap<String, String> mHeaders = new TreeMap<>(Comparator.comparingInt(String::length).thenComparing(Function.identity()));
        for (String line : lines) {
            if (line.isEmpty())
                break;
            if (line.contains(":")) {
                String[] mHeader = line.split(":");
                mHeaders.put(mHeader[0].trim(), mHeader[1].trim());
            }
        }
        return mHeaders;
    }

    private static SortedMap<String, String> getUrlParameters(String firstLine) {
        String requestUrl = firstLine.split(" ")[1];
        SortedMap<String, String> urlParameters = new TreeMap<>();
        if (requestUrl.contains("?")) {
            String paramsString = requestUrl.split("\\?")[1];
            String[] mParams = paramsString.split("&");
            for (String mmParam : mParams) {
                String[] keyValueParams = mmParam.split("=");
                urlParameters.put(keyValueParams[0], Objects.requireNonNullElse(keyValueParams[1], ""));
            }
        }
        return urlParameters;
    }

    private static String getHttpMethod(String firstLine) {
        try {
            return firstLine.split(" ")[0];
        } catch (Exception e) {
            throw new RuntimeException("Invalid http method: " + firstLine);
        }
    }

    public boolean hasHeader(String key) {
        return httpHeaders.containsKey(key);
    }
}
