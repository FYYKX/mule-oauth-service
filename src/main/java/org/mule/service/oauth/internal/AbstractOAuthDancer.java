/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.service.oauth.internal;

import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.mule.runtime.api.metadata.DataType.STRING;
import static org.mule.runtime.api.metadata.MediaType.ANY;
import static org.mule.runtime.api.metadata.MediaType.parse;
import static org.mule.runtime.http.api.HttpConstants.HttpStatus.BAD_REQUEST;
import static org.mule.runtime.http.api.HttpConstants.Method.POST;
import static org.mule.runtime.http.api.HttpHeaders.Names.AUTHORIZATION;
import static org.mule.runtime.http.api.HttpHeaders.Names.CONTENT_TYPE;
import static org.mule.runtime.http.api.HttpHeaders.Values.APPLICATION_X_WWW_FORM_URLENCODED;
import static org.mule.runtime.http.api.utils.HttpEncoderDecoderUtils.decodeUrlEncodedBody;
import static org.mule.runtime.http.api.utils.HttpEncoderDecoderUtils.encodeString;
import static org.mule.runtime.oauth.api.state.ResourceOwnerOAuthContext.DEFAULT_RESOURCE_OWNER_ID;
import org.mule.runtime.api.el.BindingContext;
import org.mule.runtime.api.el.MuleExpressionLanguage;
import org.mule.runtime.api.exception.MuleException;
import org.mule.runtime.api.lifecycle.Startable;
import org.mule.runtime.api.lifecycle.Stoppable;
import org.mule.runtime.api.lock.LockFactory;
import org.mule.runtime.api.metadata.DataType;
import org.mule.runtime.api.metadata.MediaType;
import org.mule.runtime.api.metadata.TypedValue;
import org.mule.runtime.core.api.util.IOUtils;
import org.mule.runtime.http.api.client.HttpClient;
import org.mule.runtime.http.api.domain.ParameterMap;
import org.mule.runtime.http.api.domain.entity.ByteArrayHttpEntity;
import org.mule.runtime.http.api.domain.message.request.HttpRequest;
import org.mule.runtime.http.api.domain.message.request.HttpRequestBuilder;
import org.mule.runtime.http.api.domain.message.response.HttpResponse;
import org.mule.runtime.oauth.api.exception.TokenNotFoundException;
import org.mule.runtime.oauth.api.exception.TokenUrlResponseException;
import org.mule.runtime.oauth.api.state.DefaultResourceOwnerOAuthContext;
import org.mule.runtime.oauth.api.state.ResourceOwnerOAuthContext;
import org.mule.service.oauth.internal.state.TokenResponse;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.Lock;
import java.util.function.Function;

/**
 * Base implementations with behavior common to all grant-types.
 *
 * @since 1.0
 */
public abstract class AbstractOAuthDancer implements Startable, Stoppable {

  private static final int TOKEN_REQUEST_TIMEOUT_MILLIS = 60000;

  protected final String clientId;
  protected final String clientSecret;
  protected final String tokenUrl;
  protected final Charset encoding;
  protected final String scopes;

  protected final String responseAccessTokenExpr;
  protected final String responseRefreshTokenExpr;
  protected final String responseExpiresInExpr;
  protected final Map<String, String> customParametersExtractorsExprs;
  protected final Function<String, String> resourceOwnerIdTransformer;

  private final LockFactory lockProvider;
  private final Map<String, DefaultResourceOwnerOAuthContext> tokensStore;
  private final HttpClient httpClient;
  private final MuleExpressionLanguage expressionEvaluator;

  protected AbstractOAuthDancer(String clientId, String clientSecret, String tokenUrl, Charset encoding, String scopes,
                                String responseAccessTokenExpr, String responseRefreshTokenExpr, String responseExpiresInExpr,
                                Map<String, String> customParametersExtractorsExprs,
                                Function<String, String> resourceOwnerIdTransformer, LockFactory lockProvider,
                                Map<String, DefaultResourceOwnerOAuthContext> tokensStore, HttpClient httpClient,
                                MuleExpressionLanguage expressionEvaluator) {
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.tokenUrl = tokenUrl;
    this.encoding = encoding;
    this.scopes = scopes;
    this.responseAccessTokenExpr = responseAccessTokenExpr;
    this.responseRefreshTokenExpr = responseRefreshTokenExpr;
    this.responseExpiresInExpr = responseExpiresInExpr;
    this.customParametersExtractorsExprs = customParametersExtractorsExprs;
    this.resourceOwnerIdTransformer = resourceOwnerIdTransformer;

    this.lockProvider = lockProvider;
    this.tokensStore = tokensStore;
    this.httpClient = httpClient;
    this.expressionEvaluator = expressionEvaluator;
  }

  @Override
  public void start() throws MuleException {
    httpClient.start();
  }

  @Override
  public void stop() throws MuleException {
    httpClient.stop();
  }

  protected TokenResponse invokeTokenUrl(String tokenUrl, Map<String, String> tokenRequestFormToSend, String authorization,
                                         boolean retrieveRefreshToken, Charset encoding)
      throws TokenUrlResponseException, TokenNotFoundException {
    try {
      final HttpRequestBuilder requestBuilder = HttpRequest.builder()
          .setUri(tokenUrl).setMethod(POST.name())
          .setEntity(new ByteArrayHttpEntity(encodeString(tokenRequestFormToSend, encoding).getBytes()))
          .addHeader(CONTENT_TYPE, APPLICATION_X_WWW_FORM_URLENCODED.toRfcString());

      if (authorization != null) {
        requestBuilder.addHeader(AUTHORIZATION, authorization);
      }

      // TODO MULE-11272 Support doing non-blocking requests
      final HttpResponse response = httpClient.send(requestBuilder.build(), TOKEN_REQUEST_TIMEOUT_MILLIS, true, null);

      MediaType responseContentType =
          response.getHeaderValueIgnoreCase(CONTENT_TYPE) != null ? parse(response.getHeaderValueIgnoreCase(CONTENT_TYPE)) : ANY;
      ParameterMap headers = new ParameterMap();
      for (String headerName : response.getHeaderNames()) {
        headers.put(headerName, response.getHeaderValues(headerName));
      }

      String readBody = IOUtils.toString(response.getEntity().getContent());
      Object body = readBody;
      if (responseContentType.withoutParameters().matches(APPLICATION_X_WWW_FORM_URLENCODED)) {
        body = decodeUrlEncodedBody(readBody, responseContentType.getCharset().orElse(encoding));
      }

      if (response.getStatusCode() >= BAD_REQUEST.getStatusCode()) {
        throw new TokenUrlResponseException(tokenUrl);
      }

      TokenResponse tokenResponse = new TokenResponse();

      tokenResponse
          .setAccessToken(resolveExpression(responseAccessTokenExpr, body, headers, responseContentType));
      if (tokenResponse.getAccessToken() == null) {
        throw new TokenNotFoundException(body);
      }
      if (retrieveRefreshToken) {
        tokenResponse
            .setRefreshToken(resolveExpression(responseRefreshTokenExpr, body, headers, responseContentType));
      }
      tokenResponse.setExpiresIn(resolveExpression(responseExpiresInExpr, body, headers, responseContentType));

      if (customParametersExtractorsExprs != null && !customParametersExtractorsExprs.isEmpty()) {
        Map<String, Object> customParams = new HashMap<>();
        for (Entry<String, String> customParamExpr : customParametersExtractorsExprs.entrySet()) {
          customParams.put(customParamExpr.getKey(),
                           resolveExpression(customParamExpr.getValue(), body, headers, responseContentType));
        }
        tokenResponse.setCustomResponseParameters(customParams);
      }

      return tokenResponse;
    } catch (IOException e) {
      throw new TokenUrlResponseException(tokenUrl, e);
    } catch (TimeoutException e) {
      throw new TokenUrlResponseException(tokenUrl, e);
    }
  }

  protected <T> T resolveExpression(String expr, Object body, ParameterMap headers, MediaType responseContentType) {
    if (expr == null) {
      return null;
    } else if (!expressionEvaluator.isExpression(expr)) {
      return (T) expr;
    } else {
      BindingContext resultContext = BindingContext.builder()
          .addBinding("payload",
                      new TypedValue(body, DataType.builder().fromObject(body)
                          .mediaType(responseContentType).build()))

          .addBinding("attributes", new TypedValue(Collections.singletonMap("headers", headers.toImmutableParameterMap()),
                                                   DataType.fromType(Map.class)))
          .addBinding("dataType",
                      new TypedValue(DataType.builder().fromObject(body).mediaType(responseContentType)
                          .build(), DataType.fromType(DataType.class)))
          .build();

      return (T) expressionEvaluator.evaluate(expr, STRING, resultContext).getValue();
    }
  }

  protected <T> T resolveExpression(String expr, Object body, ParameterMap headers, ParameterMap queryParams,
                                    MediaType responseContentType) {
    if (expr == null) {
      return null;
    } else if (!expressionEvaluator.isExpression(expr)) {
      return (T) expr;
    } else {
      Map<Object, Object> attributes = new HashMap<>(2);
      attributes.put("headers", headers.toImmutableParameterMap());
      attributes.put("queryParams", queryParams.toImmutableParameterMap());

      BindingContext resultContext = BindingContext.builder()
          .addBinding("payload",
                      new TypedValue(body, DataType.builder().fromObject(body)
                          .mediaType(responseContentType).build()))

          .addBinding("attributes", new TypedValue(attributes, DataType.fromType(Map.class)))
          .addBinding("dataType",
                      new TypedValue(DataType.builder().fromObject(body).mediaType(responseContentType)
                          .build(), DataType.fromType(DataType.class)))
          .build();

      return (T) expressionEvaluator.evaluate(expr, DataType.STRING, resultContext).getValue();
    }
  }

  public void invalidateContext(String resourceOwner) {
    DefaultResourceOwnerOAuthContext context = (DefaultResourceOwnerOAuthContext) getContextForResourceOwner(resourceOwner);
    context.getRefreshUserOAuthContextLock().lock();
    try {
      tokensStore.remove(resourceOwnerIdTransformer.apply(resourceOwner));
    } finally {
      context.getRefreshUserOAuthContextLock().unlock();
    }
  }

  /**
   * Retrieves the oauth context for a particular user. If there's no state for that user a new state is retrieve so never returns
   * null.
   *
   * @param resourceOwnerId id of the user.
   * @return oauth state
   */
  public ResourceOwnerOAuthContext getContextForResourceOwner(String resourceOwnerId) {
    if (resourceOwnerId == null) {
      resourceOwnerId = DEFAULT_RESOURCE_OWNER_ID;
    }

    final String transformedResourceOwnerId = resourceOwnerIdTransformer.apply(resourceOwnerId);

    DefaultResourceOwnerOAuthContext resourceOwnerOAuthContext = null;
    if (!tokensStore.containsKey(transformedResourceOwnerId)) {
      final Lock lock = lockProvider.createLock(toString() + "-config-oauth-context");
      lock.lock();
      try {
        if (!tokensStore.containsKey(transformedResourceOwnerId)) {
          resourceOwnerOAuthContext =
              new DefaultResourceOwnerOAuthContext(createLockForResourceOwner(transformedResourceOwnerId), resourceOwnerId);
          tokensStore.put(transformedResourceOwnerId, resourceOwnerOAuthContext);
        }
      } finally {
        lock.unlock();
      }
    }
    if (resourceOwnerOAuthContext == null) {
      resourceOwnerOAuthContext = tokensStore.get(transformedResourceOwnerId);
      resourceOwnerOAuthContext.setRefreshUserOAuthContextLock(createLockForResourceOwner(transformedResourceOwnerId));
    }
    return resourceOwnerOAuthContext;
  }

  private Lock createLockForResourceOwner(String resourceOwnerId) {
    String lockId = toString() + (isBlank(resourceOwnerId) ? "" : "-" + resourceOwnerId);
    return lockProvider.createLock(lockId);
  }

  /**
   * Updates the resource owner oauth context information
   *
   * @param resourceOwnerOAuthContext
   */
  protected void updateResourceOwnerOAuthContext(DefaultResourceOwnerOAuthContext resourceOwnerOAuthContext) {
    final Lock resourceOwnerContextLock = resourceOwnerOAuthContext.getRefreshUserOAuthContextLock();
    resourceOwnerContextLock.lock();
    try {
      tokensStore.put(resourceOwnerIdTransformer.apply(resourceOwnerOAuthContext.getResourceOwnerId()),
                      resourceOwnerOAuthContext);
    } finally {
      resourceOwnerContextLock.unlock();
    }
  }

}
