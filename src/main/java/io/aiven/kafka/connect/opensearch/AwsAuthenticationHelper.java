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

        final AWS4Signer signer = new AWS4Signer();
        String endpoint = config.httpHosts()[0].toURI();
        boolean isServerless = endpoint.contains(".aoss.");
        String serviceName = isServerless ? "aoss" : "es";
        
        LOGGER.info("AWS authentication details - Endpoint: {}, Service: {}, Region: {}", 
            endpoint, serviceName, config.awsRegion());
        
        signer.setServiceName("aoss");
        signer.setRegionName(config.awsRegion());

        final AWSCredentialsProvider credentialsProvider = createCredentialsProvider();

        HttpRequestInterceptor interceptor = new HttpRequestInterceptor() {
            @Override
            public void process(HttpRequest request, HttpContext context) throws IOException {
                try {
                    String originalUri = request.getRequestLine().getUri();
                    LOGGER.info("Processing request for URI: {}", originalUri);

                    // Create AWS Request
                    Request<?> awsRequest = new DefaultRequest<>("aoss");
                    
                    // Parse and build the URI, keeping original encoding
                    URI endpointUri = new URI(endpoint);
                    String path = originalUri.split("\\?")[0];
                    String query = originalUri.contains("?") ? originalUri.split("\\?")[1] : null;
                    
                    // Build the full URL without double-encoding
                    StringBuilder fullUrl = new StringBuilder();
                    fullUrl.append(endpointUri.getScheme()).append("://")
                           .append(endpointUri.getHost());
                    if (endpointUri.getPort() > 0) {
                        fullUrl.append(":").append(endpointUri.getPort());
                    }
                    fullUrl.append(path);
                    if (query != null) {
                        fullUrl.append("?").append(query);
                    }
                    
                    LOGGER.info("Full URL for signing: {}", fullUrl.toString());
                    awsRequest.setEndpoint(new URI(fullUrl.toString()));
                    
                    // Set method
                    String method = request.getRequestLine().getMethod();
                    awsRequest.setHttpMethod(HttpMethodName.valueOf(method));
                    
                    // Set headers exactly matching Python
                    awsRequest.addHeader("User-Agent", "python-requests/2.32.3");
                    awsRequest.addHeader("Accept-Encoding", "gzip, deflate, br, zstd");
                    awsRequest.addHeader("Accept", "*/*");
                    awsRequest.addHeader("Connection", "keep-alive");
                    awsRequest.addHeader("Content-Type", "application/json");
                    awsRequest.addHeader("x-amz-content-sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
                    
                    // Handle query parameters without additional encoding
                    if (query != null) {
                        for (String param : query.split("&")) {
                            String[] keyValue = param.split("=", 2);
                            if (keyValue.length == 2) {
                                // Use the parameters as-is without additional decoding/encoding
                                awsRequest.addParameter(keyValue[0], keyValue[1]);
                            }
                        }
                    }

                    // Configure signer
                    AWS4Signer signer = new AWS4Signer(false);  // false = don't double-url-encode
                    signer.setServiceName("aoss");
                    signer.setRegionName(config.awsRegion());

                    // Sign the request
                    LOGGER.info("Signing request");
                    signer.sign(awsRequest, credentialsProvider.getCredentials());
                    
                    // Clear existing headers
                    for (org.apache.http.Header header : request.getAllHeaders()) {
                        request.removeHeader(header);
                    }
                    
                    // Add back signed headers in the exact order as Python
                    String[] headerOrder = {
                        "User-Agent",
                        "Accept-Encoding",
                        "Accept",
                        "Connection",
                        "Content-Type",
                        "x-amz-date",
                        "x-amz-content-sha256",
                        "Authorization"
                    };
                    
                    for (String headerName : headerOrder) {
                        String value = awsRequest.getHeaders().get(headerName);
                        if (value != null) {
                            request.addHeader(headerName, value);
                            LOGGER.info("Added header: {} = {}", 
                                headerName,
                                headerName.equalsIgnoreCase("Authorization") ? "[REDACTED]" : value);
                        }
                    }
                    
                    LOGGER.info("Final request URI: {}", request.getRequestLine().getUri());
                    LOGGER.info("Request signing completed");
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