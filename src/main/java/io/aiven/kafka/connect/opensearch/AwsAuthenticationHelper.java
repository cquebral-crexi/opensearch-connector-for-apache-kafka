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

        final AWS4Signer signer = new AWS4Signer(false);  // false = don't double-url-encode
        String endpoint = config.httpHosts()[0].toURI();
        
        signer.setServiceName("aoss");
        signer.setRegionName(config.awsRegion());

        final AWSCredentialsProvider credentialsProvider = createCredentialsProvider();

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
                    
                    // Set the resource path (must start with /)
                    awsRequest.setResourcePath(path);
                    
                    // Set HTTP method
                    awsRequest.setHttpMethod(HttpMethodName.valueOf(method));
                    
                    // Add canonical headers in specific order
                    TreeMap<String, String> headers = new TreeMap<>();
                    headers.put("host", endpointUri.getHost());
                    headers.put("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
                    
                    // Add headers to request
                    for (Map.Entry<String, String> header : headers.entrySet()) {
                        awsRequest.addHeader(header.getKey(), header.getValue());
                    }

                    // Handle query parameters
                    if (query != null) {
                        LOGGER.info("Processing query parameters: {}", query);
                        TreeMap<String, List<String>> queryParams = new TreeMap<>();
                        
                        for (String param : query.split("&")) {
                            String[] keyValue = param.split("=", 2);
                            if (keyValue.length == 2) {
                                String key = URLDecoder.decode(keyValue[0], StandardCharsets.UTF_8);
                                String value = URLDecoder.decode(keyValue[1], StandardCharsets.UTF_8);
                                
                                queryParams.computeIfAbsent(key, k -> new ArrayList<>()).add(value);
                            }
                        }
                        
                        // Add sorted parameters to request
                        for (Map.Entry<String, List<String>> entry : queryParams.entrySet()) {
                            String key = entry.getKey();
                            for (String value : entry.getValue()) {
                                awsRequest.addParameter(key, value);
                                LOGGER.info("Added query param: {} = {}", key, value);
                            }
                        }
                    }

                    // Sign the request
                    signer.sign(awsRequest, credentialsProvider.getCredentials());

                    // Clear existing headers
                    for (org.apache.http.Header header : request.getAllHeaders()) {
                        request.removeHeader(header);
                    }
                    
                    // Add all headers from signed request, maintaining their case
                    for (Map.Entry<String, String> header : awsRequest.getHeaders().entrySet()) {
                        request.addHeader(header.getKey(), header.getValue());
                        if (header.getKey().equalsIgnoreCase("Authorization")) {
                            LOGGER.info("Authorization header: {}", header.getValue());
                        } else {
                            LOGGER.info("Added header: {} = {}", header.getKey(), header.getValue());
                        }
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