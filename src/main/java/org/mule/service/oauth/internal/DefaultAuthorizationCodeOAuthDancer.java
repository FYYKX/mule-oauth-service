/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.service.oauth.internal;

import static java.lang.String.format;
import static java.lang.String.valueOf;
import static java.lang.Thread.currentThread;
import static java.util.Collections.singleton;
import static java.util.concurrent.CompletableFuture.completedFuture;
import static org.mule.runtime.api.i18n.I18nMessageFactory.createStaticMessage;
import static org.mule.runtime.api.metadata.MediaType.ANY;
import static org.mule.runtime.api.metadata.MediaType.parse;
import static org.mule.runtime.core.api.util.ClassUtils.withContextClassLoader;
import static org.mule.runtime.core.api.util.StringUtils.isBlank;
import static org.mule.runtime.http.api.HttpConstants.HttpStatus.BAD_REQUEST;
import static org.mule.runtime.http.api.HttpConstants.HttpStatus.INTERNAL_SERVER_ERROR;
import static org.mule.runtime.http.api.HttpConstants.HttpStatus.MOVED_TEMPORARILY;
import static org.mule.runtime.http.api.HttpConstants.HttpStatus.OK;
import static org.mule.runtime.http.api.HttpConstants.Method.GET;
import static org.mule.runtime.http.api.HttpHeaders.Names.CONTENT_LENGTH;
import static org.mule.runtime.http.api.HttpHeaders.Names.CONTENT_TYPE;
import static org.mule.runtime.http.api.HttpHeaders.Names.LOCATION;
import static org.mule.runtime.http.api.utils.HttpEncoderDecoderUtils.appendQueryParam;
import static org.mule.runtime.oauth.api.OAuthAuthorizationStatusCode.AUTHORIZATION_CODE_RECEIVED_STATUS;
import static org.mule.runtime.oauth.api.OAuthAuthorizationStatusCode.AUTHORIZATION_STATUS_QUERY_PARAM_KEY;
import static org.mule.runtime.oauth.api.OAuthAuthorizationStatusCode.NO_AUTHORIZATION_CODE_STATUS;
import static org.mule.runtime.oauth.api.OAuthAuthorizationStatusCode.TOKEN_NOT_FOUND_STATUS;
import static org.mule.runtime.oauth.api.OAuthAuthorizationStatusCode.TOKEN_URL_CALL_FAILED_STATUS;
import static org.mule.runtime.oauth.api.state.ResourceOwnerOAuthContext.DEFAULT_RESOURCE_OWNER_ID;
import static org.mule.service.oauth.internal.OAuthConstants.CODE_PARAMETER;
import static org.mule.service.oauth.internal.OAuthConstants.GRANT_TYPE_AUTHENTICATION_CODE;
import static org.mule.service.oauth.internal.OAuthConstants.GRANT_TYPE_PARAMETER;
import static org.mule.service.oauth.internal.OAuthConstants.GRANT_TYPE_REFRESH_TOKEN;
import static org.mule.service.oauth.internal.OAuthConstants.REDIRECT_URI_PARAMETER;
import static org.mule.service.oauth.internal.OAuthConstants.REFRESH_TOKEN_PARAMETER;
import static org.mule.service.oauth.internal.OAuthConstants.STATE_PARAMETER;
import static org.slf4j.LoggerFactory.getLogger;

import org.mule.runtime.api.el.MuleExpressionLanguage;
import org.mule.runtime.api.exception.DefaultMuleException;
import org.mule.runtime.api.exception.MuleException;
import org.mule.runtime.api.exception.MuleRuntimeException;
import org.mule.runtime.api.lifecycle.InitialisationException;
import org.mule.runtime.api.lifecycle.Lifecycle;
import org.mule.runtime.api.lock.LockFactory;
import org.mule.runtime.api.metadata.MediaType;
import org.mule.runtime.api.util.MultiMap;
import org.mule.runtime.core.api.util.IOUtils;
import org.mule.runtime.core.api.util.StringUtils;
import org.mule.runtime.http.api.HttpConstants;
import org.mule.runtime.http.api.HttpConstants.HttpStatus;
import org.mule.runtime.http.api.HttpConstants.Method;
import org.mule.runtime.http.api.client.HttpClient;
import org.mule.runtime.http.api.domain.entity.ByteArrayHttpEntity;
import org.mule.runtime.http.api.domain.entity.EmptyHttpEntity;
import org.mule.runtime.http.api.domain.message.request.HttpRequest;
import org.mule.runtime.http.api.domain.message.response.HttpResponse;
import org.mule.runtime.http.api.domain.message.response.HttpResponseBuilder;
import org.mule.runtime.http.api.domain.request.HttpRequestContext;
import org.mule.runtime.http.api.server.HttpServer;
import org.mule.runtime.http.api.server.RequestHandler;
import org.mule.runtime.http.api.server.RequestHandlerManager;
import org.mule.runtime.http.api.server.async.HttpResponseReadyCallback;
import org.mule.runtime.http.api.server.async.ResponseStatusCallback;
import org.mule.runtime.oauth.api.AuthorizationCodeOAuthDancer;
import org.mule.runtime.oauth.api.AuthorizationCodeRequest;
import org.mule.runtime.oauth.api.builder.AuthorizationCodeDanceCallbackContext;
import org.mule.runtime.oauth.api.exception.RequestAuthenticationException;
import org.mule.runtime.oauth.api.exception.TokenNotFoundException;
import org.mule.runtime.oauth.api.exception.TokenUrlResponseException;
import org.mule.runtime.oauth.api.listener.AuthorizationCodeListener;
import org.mule.runtime.oauth.api.state.DefaultResourceOwnerOAuthContext;
import org.mule.runtime.oauth.api.state.ResourceOwnerOAuthContext;
import org.mule.service.oauth.internal.authorizationcode.AuthorizationRequestUrlBuilder;
import org.mule.service.oauth.internal.authorizationcode.DefaultAuthorizationCodeRequest;
import org.mule.service.oauth.internal.state.StateDecoder;
import org.mule.service.oauth.internal.state.StateEncoder;
import org.mule.service.oauth.internal.state.TokenResponse;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.Lock;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

import org.slf4j.Logger;

/**
 * Provides OAuth dance support for authorization-code grant-type.
 *
 * @since 1.0
 */
public class DefaultAuthorizationCodeOAuthDancer extends AbstractOAuthDancer implements AuthorizationCodeOAuthDancer, Lifecycle {

  private static final Logger LOGGER = getLogger(DefaultAuthorizationCodeOAuthDancer.class);

  private final Optional<HttpServer> httpServer;

  private final String localCallbackUrlPath;

  private final String localAuthorizationUrlPath;
  private final String localAuthorizationUrlResourceOwnerId;

  private final String externalCallbackUrl;

  private final String state;
  private final String authorizationUrl;
  private final Supplier<Map<String, String>> customParameters;

  private final Function<AuthorizationCodeRequest, AuthorizationCodeDanceCallbackContext> beforeDanceCallback;
  private final BiConsumer<AuthorizationCodeDanceCallbackContext, ResourceOwnerOAuthContext> afterDanceCallback;

  private RequestHandlerManager redirectUrlHandlerManager;
  private RequestHandlerManager localAuthorizationUrlHandlerManager;

  public DefaultAuthorizationCodeOAuthDancer(Optional<HttpServer> httpServer, String clientId, String clientSecret,
                                             String tokenUrl, String scopes, boolean encodeClientCredentialsInBody,
                                             String externalCallbackUrl, Charset encoding,
                                             String localCallbackUrlPath, String localAuthorizationUrlPath,
                                             String localAuthorizationUrlResourceOwnerId, String state, String authorizationUrl,
                                             String responseAccessTokenExpr, String responseRefreshTokenExpr,
                                             String responseExpiresInExpr, Supplier<Map<String, String>> customParameters,
                                             Map<String, String> customParametersExtractorsExprs,
                                             Function<String, String> resourceOwnerIdTransformer,
                                             LockFactory lockProvider, Map<String, DefaultResourceOwnerOAuthContext> tokensStore,
                                             HttpClient httpClient, MuleExpressionLanguage expressionEvaluator,
                                             Function<AuthorizationCodeRequest, AuthorizationCodeDanceCallbackContext> beforeDanceCallback,
                                             BiConsumer<AuthorizationCodeDanceCallbackContext, ResourceOwnerOAuthContext> afterDanceCallback,
                                             List<AuthorizationCodeListener> listeners) {
    super(clientId, clientSecret, tokenUrl, encoding, scopes, encodeClientCredentialsInBody, responseAccessTokenExpr,
          responseRefreshTokenExpr,
          responseExpiresInExpr, customParametersExtractorsExprs, resourceOwnerIdTransformer, lockProvider, tokensStore,
          httpClient, expressionEvaluator, listeners);

    this.httpServer = httpServer;
    this.localCallbackUrlPath = localCallbackUrlPath;
    this.localAuthorizationUrlPath = localAuthorizationUrlPath;
    this.localAuthorizationUrlResourceOwnerId = localAuthorizationUrlResourceOwnerId;
    this.externalCallbackUrl = externalCallbackUrl;
    this.state = state;
    this.authorizationUrl = authorizationUrl;
    this.customParameters = customParameters;

    this.beforeDanceCallback = beforeDanceCallback;
    this.afterDanceCallback = afterDanceCallback;
  }

  @Override
  public void initialise() throws InitialisationException {
    httpServer.ifPresent(s -> {
      redirectUrlHandlerManager = addRequestHandler(s, GET, localCallbackUrlPath, createRedirectUrlListener());
      localAuthorizationUrlHandlerManager =
          addRequestHandler(s, GET, localAuthorizationUrlPath, createLocalAuthorizationUrlListener());
    });
  }

  @Override
  public void addListener(AuthorizationCodeListener listener) {
    doAddListener(listener);
  }

  @Override
  public void removeListener(AuthorizationCodeListener listener) {
    doRemoveListener(listener);
  }

  private static RequestHandlerManager addRequestHandler(HttpServer server, Method method, String path,
                                                         RequestHandler callbackHandler) {
    ClassLoader appRegionClassLoader = currentThread().getContextClassLoader();

    RequestHandler requestHandler = new RequestHandler() {

      @Override
      public void handleRequest(HttpRequestContext requestContext, HttpResponseReadyCallback responseCallback) {
        withContextClassLoader(DefaultAuthorizationCodeOAuthDancer.class.getClassLoader(), () -> {
          try {
            callbackHandler.handleRequest(requestContext, responseCallback);
          } catch (Exception e) {
            LOGGER.error("Uncaught Exception on OAuth listener", e);
            sendErrorResponse(INTERNAL_SERVER_ERROR, e.getMessage(), responseCallback);
          }
        });
      }

      public ClassLoader getContextClassLoader() {
        return appRegionClassLoader;
      }
    };

    return server.addRequestHandler(singleton(method.name()), path, requestHandler);
  }

  private static void sendErrorResponse(final HttpConstants.HttpStatus status, String message,
                                        HttpResponseReadyCallback responseCallback) {
    responseCallback.responseReady(HttpResponse.builder()
        .statusCode(status.getStatusCode())
        .reasonPhrase(status.getReasonPhrase())
        .entity(message != null ? new ByteArrayHttpEntity(message.getBytes()) : new EmptyHttpEntity())
        .addHeader(CONTENT_LENGTH, message != null ? valueOf(message.length()) : "0")
        .build(), new ResponseStatusCallback() {

          @Override
          public void responseSendFailure(Throwable exception) {
            LOGGER.warn("Error while sending {} response {}", status.getStatusCode(), exception.getMessage());
            if (LOGGER.isDebugEnabled()) {
              LOGGER.debug("Exception thrown", exception);
            }
          }

          @Override
          public void responseSendSuccessfully() {}
        });
  }

  private RequestHandler createRedirectUrlListener() {
    ClassLoader appRegionClassLoader = currentThread().getContextClassLoader();

    return new RequestHandler() {

      @Override
      public void handleRequest(HttpRequestContext requestContext, HttpResponseReadyCallback responseCallback) {
        final HttpRequest request = requestContext.getRequest();
        final MultiMap<String, String> queryParams = request.getQueryParams();

        final String state = queryParams.get(STATE_PARAMETER);
        final StateDecoder stateDecoder = new StateDecoder(state);
        final String authorizationCode = queryParams.get(CODE_PARAMETER);

        String resourceOwnerId = stateDecoder.decodeResourceOwnerId();

        if (authorizationCode == null) {
          LOGGER.info("HTTP Request to redirect URL done by the OAuth provider does not contains a code query parameter. "
              + "Code query parameter is required to get the access token.");
          LOGGER.error("Could not extract authorization code from OAuth provider HTTP request done to the redirect URL");

          sendResponse(stateDecoder, responseCallback, BAD_REQUEST,
                       "Failure retrieving access token.\n OAuth Server uri from callback: " + request.getUri(),
                       NO_AUTHORIZATION_CODE_STATUS);
          return;
        }

        AuthorizationCodeDanceCallbackContext beforeCallbackContext = beforeDanceCallback
            .apply(new DefaultAuthorizationCodeRequest(resourceOwnerId, authorizationUrl, tokenUrl, clientId, clientSecret,
                                                       scopes,
                                                       stateDecoder.decodeOriginalState()));

        if (LOGGER.isDebugEnabled()) {
          LOGGER.debug("Redirect url request state: " + state);
          LOGGER.debug("Redirect url request code: " + authorizationCode);
        }

        final Map<String, String> formData = new HashMap<>();
        formData.put(CODE_PARAMETER, authorizationCode);
        String authorization = handleClientCredentials(formData, encodeClientCredentialsInBody);
        formData.put(GRANT_TYPE_PARAMETER, GRANT_TYPE_AUTHENTICATION_CODE);
        formData.put(REDIRECT_URI_PARAMETER, externalCallbackUrl);

        invokeTokenUrl(tokenUrl, formData, authorization, true, encoding)
            .exceptionally(e -> {
              withContextClassLoader(DefaultAuthorizationCodeOAuthDancer.class.getClassLoader(), () -> {
                if (e.getCause() instanceof TokenUrlResponseException) {
                  LOGGER.error(e.getMessage());
                  sendResponse(stateDecoder, responseCallback, INTERNAL_SERVER_ERROR,
                               format("Failure calling token url %s. Exception message is %s", tokenUrl, e.getMessage()),
                               TOKEN_URL_CALL_FAILED_STATUS);

                } else if (e.getCause() instanceof TokenNotFoundException) {
                  LOGGER.error(e.getMessage());
                  sendResponse(stateDecoder, responseCallback, INTERNAL_SERVER_ERROR,
                               "Failed getting access token or refresh token from token URL response. See logs for details.",
                               TOKEN_NOT_FOUND_STATUS);

                } else {
                  LOGGER.error("Uncaught Exception on OAuth listener", e);
                  sendErrorResponse(INTERNAL_SERVER_ERROR, e.getMessage(), responseCallback);
                }
              });
              return null;
            }).thenAccept(tokenResponse -> {
              withContextClassLoader(DefaultAuthorizationCodeOAuthDancer.class.getClassLoader(), () -> {
                if (tokenResponse == null) {
                  // This is just for the case where an error was already handled
                  return;
                }

                final DefaultResourceOwnerOAuthContext resourceOwnerOAuthContext =
                    (DefaultResourceOwnerOAuthContext) getContextForResourceOwner(resourceOwnerId == null
                        ? DEFAULT_RESOURCE_OWNER_ID
                        : resourceOwnerId);

                if (LOGGER.isDebugEnabled()) {
                  LOGGER.debug("Update OAuth Context for resourceOwnerId %s", resourceOwnerOAuthContext.getResourceOwnerId());
                  LOGGER.debug("Retrieved access token, refresh token and expires from token url are: %s, %s, %s",
                               tokenResponse.getAccessToken(), tokenResponse.getRefreshToken(),
                               tokenResponse.getExpiresIn());
                }

                updateResourceOwnerState(resourceOwnerOAuthContext, stateDecoder.decodeOriginalState(), tokenResponse);
                updateResourceOwnerOAuthContext(resourceOwnerOAuthContext);

                forEachListener(l -> l.onAuthorizationCompleted(resourceOwnerOAuthContext));
                afterDanceCallback.accept(beforeCallbackContext, resourceOwnerOAuthContext);

                sendResponse(stateDecoder, responseCallback, OK, "Successfully retrieved access token",
                             AUTHORIZATION_CODE_RECEIVED_STATUS);
              });
            });
      }

      public ClassLoader getContextClassLoader() {
        return appRegionClassLoader;
      }
    };
  }

  private static void sendResponse(StateDecoder stateDecoder, HttpResponseReadyCallback responseCallback,
                                   HttpStatus statusEmptyState, String message, int authorizationStatus) {
    String onCompleteRedirectToValue = stateDecoder.decodeOnCompleteRedirectTo();
    if (!isEmpty(onCompleteRedirectToValue)) {
      sendResponse(responseCallback, MOVED_TEMPORARILY, message, appendQueryParam(onCompleteRedirectToValue,
                                                                                  AUTHORIZATION_STATUS_QUERY_PARAM_KEY,
                                                                                  valueOf(authorizationStatus)));
    } else {
      sendResponse(responseCallback, statusEmptyState, message);
    }
  }

  private static void sendResponse(HttpResponseReadyCallback responseCallback, HttpStatus status, String message,
                                   String locationHeader) {
    HttpResponseBuilder httpResponseBuilder = HttpResponse.builder();
    httpResponseBuilder.statusCode(status.getStatusCode());
    httpResponseBuilder.reasonPhrase(status.getReasonPhrase());
    httpResponseBuilder.entity(new ByteArrayHttpEntity(message.getBytes()));
    httpResponseBuilder.addHeader(CONTENT_LENGTH, valueOf(message.length()));
    httpResponseBuilder.addHeader(LOCATION, locationHeader);
    responseCallback.responseReady(httpResponseBuilder.build(), new ResponseStatusCallback() {

      @Override
      public void responseSendFailure(Throwable exception) {
        LOGGER.warn("Error while sending {} response {}", status.getStatusCode(), exception.getMessage());
        if (LOGGER.isDebugEnabled()) {
          LOGGER.debug("Exception thrown", exception);
        }
      }

      @Override
      public void responseSendSuccessfully() {}
    });
  }

  private static void sendResponse(HttpResponseReadyCallback responseCallback, HttpStatus status, String message) {
    HttpResponseBuilder httpResponseBuilder = HttpResponse.builder();
    httpResponseBuilder.statusCode(status.getStatusCode());
    httpResponseBuilder.reasonPhrase(status.getReasonPhrase());
    httpResponseBuilder.entity(new ByteArrayHttpEntity(message.getBytes()));
    httpResponseBuilder.addHeader(CONTENT_LENGTH, valueOf(message.length()));
    responseCallback.responseReady(httpResponseBuilder.build(), new ResponseStatusCallback() {

      @Override
      public void responseSendFailure(Throwable exception) {
        LOGGER.warn("Error while sending {} response {}", status.getStatusCode(), exception.getMessage());
        if (LOGGER.isDebugEnabled()) {
          LOGGER.debug("Exception thrown", exception);
        }
      }

      @Override
      public void responseSendSuccessfully() {}
    });
  }

  private static boolean isEmpty(String value) {
    return value == null || StringUtils.isEmpty(value) || "null".equals(value);
  }

  private RequestHandler createLocalAuthorizationUrlListener() {
    ClassLoader appRegionClassLoader = currentThread().getContextClassLoader();

    return new RequestHandler() {

      @Override
      public void handleRequest(HttpRequestContext requestContext, HttpResponseReadyCallback responseCallback) {
        handleLocalAuthorizationRequest(requestContext.getRequest(), responseCallback);
      }

      public ClassLoader getContextClassLoader() {
        return appRegionClassLoader;
      }
    };
  }

  @Override
  public void handleLocalAuthorizationRequest(HttpRequest request, HttpResponseReadyCallback responseCallback) {
    final String body = readBody(request);
    final MultiMap<String, String> headers = readHeaders(request);
    final MediaType mediaType = getMediaType(request);
    final MultiMap<String, String> queryParams = request.getQueryParams();

    final String originalState = resolveExpression(state, body, headers, queryParams, mediaType);
    final StateEncoder stateEncoder = new StateEncoder(originalState);

    final String resourceOwnerId =
        resolveExpression(localAuthorizationUrlResourceOwnerId, body, headers, queryParams, mediaType);
    if (resourceOwnerId != null) {
      stateEncoder.encodeResourceOwnerIdInState(resourceOwnerId);
    }

    final String onCompleteRedirectToValue = queryParams.get("onCompleteRedirectTo");
    if (onCompleteRedirectToValue != null) {
      stateEncoder.encodeOnCompleteRedirectToInState(onCompleteRedirectToValue);
    }

    final String authorizationUrlWithParams = new AuthorizationRequestUrlBuilder()
        .setAuthorizationUrl(authorizationUrl)
        .setClientId(clientId)
        .setClientSecret(clientSecret)
        .setCustomParameters(customParameters.get())
        .setRedirectUrl(externalCallbackUrl)
        .setState(stateEncoder.getEncodedState())
        .setScope(scopes)
        .setEncoding(encoding)
        .buildUrl();

    sendResponse(responseCallback, MOVED_TEMPORARILY, body, authorizationUrlWithParams);
  }

  private String readBody(final HttpRequest request) {
    return IOUtils.toString(request.getEntity().getContent());
  }

  private MultiMap<String, String> readHeaders(final HttpRequest request) {
    return request.getHeaders();
  }

  private MediaType getMediaType(final HttpRequest request) {
    String contentType = request.getHeaderValue(CONTENT_TYPE);
    return contentType != null ? parse(contentType) : ANY;
  }

  @Override
  public void start() throws MuleException {
    super.start();
    if (httpServer.isPresent()) {
      try {
        httpServer.get().start();
      } catch (IOException e) {
        throw new DefaultMuleException(e);
      }
      redirectUrlHandlerManager.start();
      localAuthorizationUrlHandlerManager.start();
    }
  }

  @Override
  public void stop() throws MuleException {
    if (httpServer.isPresent()) {
      redirectUrlHandlerManager.stop();
      localAuthorizationUrlHandlerManager.stop();
      httpServer.get().stop();
    }
    super.stop();
  }

  @Override
  public void dispose() {
    if (httpServer.isPresent()) {
      redirectUrlHandlerManager.dispose();
      localAuthorizationUrlHandlerManager.dispose();
      httpServer.get().dispose();
    }
  }

  @Override
  public CompletableFuture<String> accessToken(String resourceOwner) throws RequestAuthenticationException {
    final String accessToken = getContextForResourceOwner(resourceOwner).getAccessToken();
    if (accessToken == null) {
      throw new RequestAuthenticationException(createStaticMessage(format("No access token found. "
          + "Verify that you have authenticated before trying to execute an operation to the API.")));
    }

    // TODO MULE-11858 proactively refresh if the token has already expired based on its 'expiresIn' parameter
    return completedFuture(accessToken);
  }

  private static final Map<String, CompletableFuture<Void>> activeRefreshFutures = new ConcurrentHashMap<>();

  @Override
  public CompletableFuture<Void> refreshToken(String resourceOwner) {
    return refreshToken(resourceOwner, false);
  }

  @Override
  public CompletableFuture<Void> refreshToken(String resourceOwner, boolean useQueryParameters) {
    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("Executing refresh token for user " + resourceOwner);
    }

    final DefaultResourceOwnerOAuthContext resourceOwnerOAuthContext =
        (DefaultResourceOwnerOAuthContext) getContextForResourceOwner(resourceOwner);

    String nullSafeResourceOwner = "" + resourceOwner;
    CompletableFuture<Void> activeRefreshFuture = activeRefreshFutures.get(nullSafeResourceOwner);
    if (activeRefreshFuture != null) {
      return activeRefreshFuture;
    }

    Lock lock = resourceOwnerOAuthContext.getRefreshUserOAuthContextLock();
    final boolean lockWasAcquired = lock.tryLock();
    if (lockWasAcquired) {
      try {
        final String userRefreshToken = resourceOwnerOAuthContext.getRefreshToken();
        if (userRefreshToken == null) {
          throw new MuleRuntimeException(createStaticMessage("The user with user id %s has no refresh token in his OAuth state so we can't execute the refresh token call",
                                                             resourceOwnerOAuthContext.getResourceOwnerId()));
        }

        final Map<String, String> formData = new HashMap<>();
        formData.put(REFRESH_TOKEN_PARAMETER, userRefreshToken);
        String authorization = handleClientCredentials(formData, encodeClientCredentialsInBody);
        formData.put(GRANT_TYPE_PARAMETER, GRANT_TYPE_REFRESH_TOKEN);
        formData.put(REDIRECT_URI_PARAMETER, externalCallbackUrl);

        CompletableFuture<Void> refreshFuture =
            invokeTokenUrl(tokenUrl, formData, authorization, true, encoding).thenAccept(tokenResponse -> {
              lock.lock();
              try {
                withContextClassLoader(DefaultAuthorizationCodeOAuthDancer.class.getClassLoader(), () -> {
                  if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug("Update OAuth Context for resourceOwnerId %s", resourceOwnerOAuthContext.getResourceOwnerId());
                  }
                  updateResourceOwnerState(resourceOwnerOAuthContext, null, tokenResponse);
                  updateResourceOwnerOAuthContext(resourceOwnerOAuthContext);
                  forEachListener(l -> l.onTokenRefreshed(resourceOwnerOAuthContext));
                });
              } finally {
                lock.unlock();
              }
            });
        activeRefreshFutures.put(nullSafeResourceOwner, refreshFuture);
        refreshFuture.thenRun(() -> activeRefreshFutures.remove(nullSafeResourceOwner, refreshFuture));
        return refreshFuture;
      } finally {
        lock.unlock();
      }
    } else {
      lock.lock();
      try {
        return activeRefreshFutures.get(nullSafeResourceOwner);
      } finally {
        lock.unlock();
      }
    }
  }

  private void updateResourceOwnerState(DefaultResourceOwnerOAuthContext resourceOwnerOAuthContext, String newState,
                                        TokenResponse tokenResponse) {
    resourceOwnerOAuthContext.setAccessToken(tokenResponse.getAccessToken());
    if (tokenResponse.getRefreshToken() != null) {
      resourceOwnerOAuthContext.setRefreshToken(tokenResponse.getRefreshToken());
    }
    resourceOwnerOAuthContext.setExpiresIn(tokenResponse.getExpiresIn());

    // State may be null because there's no state or because this was called after refresh token.
    if (newState != null) {
      resourceOwnerOAuthContext.setState(newState);
    }

    final Map<String, Object> customResponseParameters = tokenResponse.getCustomResponseParameters();
    for (String paramName : customResponseParameters.keySet()) {
      final Object paramValue = customResponseParameters.get(paramName);
      if (paramValue != null) {
        resourceOwnerOAuthContext.getTokenResponseParameters().put(paramName, paramValue);
      }
    }

    if (LOGGER.isDebugEnabled()) {
      LOGGER.debug("New OAuth State for resourceOwnerId %s is: accessToken(%s), refreshToken(%s), expiresIn(%s), state(%s)",
                   resourceOwnerOAuthContext.getResourceOwnerId(), resourceOwnerOAuthContext.getAccessToken(),
                   isBlank(resourceOwnerOAuthContext.getRefreshToken()) ? "Not issued"
                       : resourceOwnerOAuthContext.getRefreshToken(),
                   resourceOwnerOAuthContext.getExpiresIn(), resourceOwnerOAuthContext.getState());
    }
  }

  private void forEachListener(Consumer<AuthorizationCodeListener> action) {
    onEachListener(l -> action.accept((AuthorizationCodeListener) l));
  }
}
