package io.aiven.kafka.connect.opensearch;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.auth.BasicSessionCredentials;
import com.amazonaws.auth.STSAssumeRoleSessionCredentialsProvider;
import com.amazonaws.services.securitytoken.AWSSecurityTokenService;
import com.amazonaws.services.securitytoken.AWSSecurityTokenServiceClientBuilder;
import org.apache.http.HttpRequestInterceptor;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.opensearch.client.RestClientBuilder;
import com.amazonaws.auth.AWS4Signer;
import com.amazonaws.Request;
import com.amazonaws.DefaultRequest;
import com.amazonaws.http.HttpMethodName;
import org.apache.http.HttpRequest;
import org.apache.http.protocol.HttpContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.TreeMap;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;
import java.util.Map;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.net.URLEncoder;
import java.lang.reflect.Field;
import org.apache.http.message.BasicRequestLine;

public class AwsAuthenticationHelper {
    private static final Logger LOGGER = LoggerFactory.getLogger(AwsAuthenticationHelper.class);
    private static final String CONTENT_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    
    private final OpensearchSinkConnectorConfig config;
    
    public AwsAuthenticationHelper(OpensearchSinkConnectorConfig config) {
        this.config = config;
        LOGGER.info("AwsAuthenticationHelper initialized");
    }
    
    public void configureAwsAuthentication(RestClientBuilder builder) {
        LOGGER.info("Starting AWS authentication configuration");
        
        if (!config.isAwsIamAuthEnabled()) {
            LOGGER.warn("AWS IAM authentication is not enabled");
            return;
        }

        final AWS4Signer signer = new AWS4Signer(false);
        String endpoint = config.httpHosts()[0].toURI();
        
        signer.setServiceName("aoss");
        signer.setRegionName(config.awsRegion());

        final AWSCredentialsProvider credentialsProvider = createCredentialsProvider();

        // List of parameters to exclude
        final Set<String> excludedParams = new HashSet<>(Arrays.asList(
            "master_timeout",
            "timeout"
        ));

        HttpRequestInterceptor interceptor = new HttpRequestInterceptor() {
            @Override
            public void process(HttpRequest request, HttpContext context) throws IOException {
                try {
                    String originalUri = request.getRequestLine().getUri();
                    String method = request.getRequestLine().getMethod();
                    LOGGER.info("Processing {} request for URI: {}", method, originalUri);

                    Request<?> awsRequest = new DefaultRequest<>("aoss");
                    URI endpointUri = new URI(endpoint);
                    String path = originalUri.split("\\?")[0];
                    String query = originalUri.contains("?") ? originalUri.split("\\?")[1] : null;
                    
                    // Set the endpoint first
                    awsRequest.setEndpoint(endpointUri);
                    awsRequest.setResourcePath(path);
                    awsRequest.setHttpMethod(HttpMethodName.valueOf(method));
                    
                    // Add canonical headers
                    awsRequest.addHeader("host", endpointUri.getHost());
                    awsRequest.addHeader("x-amz-content-sha256", 
                        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

                    // Handle query parameters
                    StringBuilder finalQueryString = new StringBuilder();
                    TreeMap<String, List<String>> filteredParams = new TreeMap<>();
                    
                    if (query != null) {
                        LOGGER.info("Processing query parameters: {}", query);
                        boolean isFirst = true;
                        
                        for (String param : query.split("&")) {
                            String[] keyValue = param.split("=", 2);
                            if (keyValue.length == 2) {
                                String key = URLDecoder.decode(keyValue[0], StandardCharsets.UTF_8);
                                
                                // Skip excluded parameters
                                if (excludedParams.contains(key)) {
                                    LOGGER.debug("Skipping excluded parameter: {}", key);
                                    continue;
                                }
                                
                                String value = URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8);
                                
                                // Add to AWS request
                                awsRequest.addParameter(key, value);
                                LOGGER.info("Added query param: {} = {}", key, value);
                                
                                // Build query string for final URI
                                if (!isFirst) {
                                    finalQueryString.append("&");
                                }
                                finalQueryString.append(URLEncoder.encode(key, StandardCharsets.UTF_8))
                                              .append("=")
                                              .append(URLEncoder.encode(value, StandardCharsets.UTF_8));
                                isFirst = false;
                            }
                        }
                    }

                    // Sign the request
                    signer.sign(awsRequest, credentialsProvider.getCredentials());

                    // Clear existing headers
                    for (org.apache.http.Header header : request.getAllHeaders()) {
                        request.removeHeader(header);
                    }
                    
                    // Add signed headers
                    for (Map.Entry<String, String> header : awsRequest.getHeaders().entrySet()) {
                        request.addHeader(header.getKey(), header.getValue());
                        if (header.getKey().equalsIgnoreCase("Authorization")) {
                            LOGGER.info("Authorization header: {}", header.getValue());
                        } else {
                            LOGGER.info("Added header: {} = {}", header.getKey(), header.getValue());
                        }
                    }

                    // Create the final URI
                    String finalUri = path;
                    if (finalQueryString.length() > 0) {
                        finalUri += "?" + finalQueryString.toString();
                    }
                    
                    // Set the final URI using reflection since HttpRequest doesn't have setRequestLine
                    try {
                        Field uriField = request.getRequestLine().getClass().getDeclaredField("uri");
                        uriField.setAccessible(true);
                        uriField.set(request.getRequestLine(), finalUri);
                    } catch (Exception e) {
                        LOGGER.warn("Could not modify request URI: {}", e.getMessage());
                    }
                    
                    LOGGER.info("Final request URI: {}", request.getRequestLine().getUri());
                } catch (Exception e) {
                    LOGGER.error("Error during request signing", e);
                    throw new IOException("Error during request signing: " + e.getMessage(), e);
                }
            }
        };

        builder.setHttpClientConfigCallback(httpClientBuilder -> {
            LOGGER.info("Adding AWS interceptor to HTTP client");
            return httpClientBuilder.addInterceptorLast(interceptor);
        });
        
        LOGGER.info("AWS authentication configuration completed");
    }

    private AWSCredentialsProvider createCredentialsProvider() {
        try {
            LOGGER.info("Creating AWS credentials provider");
            
            if (config.awsRoleArn().isPresent()) {
                LOGGER.info("Using AWS IAM Role authentication");
                final AWSSecurityTokenService stsClient = AWSSecurityTokenServiceClientBuilder.standard()
                    .withRegion(config.awsRegion())
                    .build();

                return new STSAssumeRoleSessionCredentialsProvider.Builder(
                    config.awsRoleArn().get(),
                    "OpenSearchConnectorSession"
                )
                .withStsClient(stsClient)
                .build();
            }

            if (config.awsSessionToken().isPresent()) {
                LOGGER.info("Using AWS temporary credentials with session token");
                return new AWSStaticCredentialsProvider(
                    new BasicSessionCredentials(
                        config.awsAccessKeyId().get(),
                        config.awsSecretKey().get(),
                        config.awsSessionToken().get()
                    )
                );
            }

            LOGGER.info("Using AWS static credentials with access key ID: {}", 
                config.awsAccessKeyId().get().substring(0, 5) + "...");
            return new AWSStaticCredentialsProvider(
                new BasicAWSCredentials(
                    config.awsAccessKeyId().get(),
                    config.awsSecretKey().get()
                )
            );
        } catch (Exception e) {
            LOGGER.error("Failed to create AWS credentials provider", e);
            throw e;
        }
    }
}