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
import com.amazonaws.http.apache.request.impl.ApacheHttpRequestFactory;
import com.amazonaws.Request;
import com.amazonaws.DefaultRequest;
import com.amazonaws.http.HttpMethodName;
import org.apache.http.Header;
import org.apache.http.HttpException;
import org.apache.http.HttpRequest;
import org.apache.http.protocol.HttpContext;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

public class AwsAuthenticationHelper {
    
    private final OpensearchSinkConnectorConfig config;
    
    public AwsAuthenticationHelper(OpensearchSinkConnectorConfig config) {
        this.config = config;
    }
    
    public void configureAwsAuthentication(RestClientBuilder builder) {
        if (!config.isAwsIamAuthEnabled()) {
            return;
        }

        final AWS4Signer signer = new AWS4Signer();
        signer.setServiceName("es");
        signer.setRegionName(config.awsRegion());

        final AWSCredentialsProvider credentialsProvider = createCredentialsProvider();

        HttpRequestInterceptor interceptor = new HttpRequestInterceptor() {
            @Override
            public void process(HttpRequest request, HttpContext context) throws HttpException, IOException {
                try {
                    // Create AWS Request
                    Request<?> awsRequest = new DefaultRequest<>("es");
                    URI uri = new URI(request.getRequestLine().getUri());
                    awsRequest.setEndpoint(uri);
                    awsRequest.setHttpMethod(HttpMethodName.valueOf(request.getRequestLine().getMethod()));
                    
                    // Sign the request
                    signer.sign(awsRequest, credentialsProvider.getCredentials());
                    
                    // Add the signed headers back to the original request
                    for (Map.Entry<String, String> header : awsRequest.getHeaders().entrySet()) {
                        request.setHeader(header.getKey(), header.getValue());
                    }
                } catch (URISyntaxException e) {
                    throw new IOException("Failed to parse request URI", e);
                }
            }
        };

        builder.setHttpClientConfigCallback(httpClientBuilder -> 
            httpClientBuilder.addInterceptorLast(interceptor)
        );
    }

    private AWSCredentialsProvider createCredentialsProvider() {
        // If role ARN is provided, use role-based authentication
        if (config.awsRoleArn().isPresent()) {
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

        // If session token is provided, use temporary credentials
        if (config.awsSessionToken().isPresent()) {
            return new AWSStaticCredentialsProvider(
                new BasicSessionCredentials(
                    config.awsAccessKeyId().get(),
                    config.awsSecretKey().get(),
                    config.awsSessionToken().get()
                )
            );
        }

        // Use standard AWS credentials
        return new AWSStaticCredentialsProvider(
            new BasicAWSCredentials(
                config.awsAccessKeyId().get(),
                config.awsSecretKey().get()
            )
        );
    }
}