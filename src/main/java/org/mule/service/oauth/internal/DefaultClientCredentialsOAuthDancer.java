/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.service.oauth.internal;

import static java.lang.Thread.currentThread;
import static java.util.concurrent.CompletableFuture.completedFuture;
import static org.mule.runtime.core.api.util.ClassUtils.withContextClassLoader;
import static org.mule.runtime.oauth.api.state.ResourceOwnerOAuthContext.DEFAULT_RESOURCE_OWNER_ID;
import static org.mule.service.oauth.internal.OAuthConstants.GRANT_TYPE_CLIENT_CREDENTIALS;
import static org.mule.service.oauth.internal.OAuthConstants.GRANT_TYPE_PARAMETER;
import static org.mule.service.oauth.internal.OAuthConstants.SCOPE_PARAMETER;
import static org.slf4j.LoggerFactory.getLogger;

import org.mule.runtime.api.el.MuleExpressionLanguage;
import org.mule.runtime.api.exception.MuleException;
import org.mule.runtime.api.lifecycle.LifecycleException;
import org.mule.runtime.api.lifecycle.Startable;
import org.mule.runtime.api.lock.LockFactory;
import org.mule.runtime.http.api.client.HttpClient;
import org.mule.runtime.oauth.api.ClientCredentialsOAuthDancer;
import org.mule.runtime.oauth.api.exception.RequestAuthenticationException;
import org.mule.runtime.oauth.api.exception.TokenNotFoundException;
import org.mule.runtime.oauth.api.exception.TokenUrlResponseException;
import org.mule.runtime.oauth.api.listener.ClientCredentialsListener;
import org.mule.runtime.oauth.api.state.DefaultResourceOwnerOAuthContext;
import org.mule.runtime.oauth.api.state.ResourceOwnerOAuthContext;

import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;

import org.slf4j.Logger;

/**
 * Provides OAuth dance support for client-credentials grant-type.
 *
 * @since 1.0
 */
public class DefaultClientCredentialsOAuthDancer extends AbstractOAuthDancer implements Startable, ClientCredentialsOAuthDancer {

  private static final Logger LOGGER = getLogger(DefaultClientCredentialsOAuthDancer.class);

  private boolean accessTokenRefreshedOnStart = false;

  public DefaultClientCredentialsOAuthDancer(String clientId, String clientSecret, String tokenUrl, String scopes,
                                             boolean encodeClientCredentialsInBody, Charset encoding,
                                             String responseAccessTokenExpr, String responseRefreshTokenExpr,
                                             String responseExpiresInExpr, Map<String, String> customParametersExprs,
                                             Function<String, String> resourceOwnerIdTransformer, LockFactory lockProvider,
                                             Map<String, DefaultResourceOwnerOAuthContext> tokensStore, HttpClient httpClient,
                                             MuleExpressionLanguage expressionEvaluator) {
    super(clientId, clientSecret, tokenUrl, encoding, scopes, encodeClientCredentialsInBody, responseAccessTokenExpr,
          responseRefreshTokenExpr, responseExpiresInExpr, customParametersExprs, resourceOwnerIdTransformer, lockProvider,
          tokensStore, httpClient,
          expressionEvaluator);
  }

  @Override
  public void start() throws MuleException {
    super.start();
    // We use a reentrant instead of one from the lock factory because the local state of this object cannot be shared in the
    // cluster.
    // For this to work within a cluster we would need some notifications mechaniusm from the object store to know when a token
    // was refreshen in another node.
    refreshTokenLock = new ReentrantLock();
    try {
      refreshToken().get();
      accessTokenRefreshedOnStart = true;
    } catch (ExecutionException e) {
      if (!(e.getCause() instanceof TokenUrlResponseException) && !(e.getCause() instanceof TokenNotFoundException)) {
        super.stop();
        throw new LifecycleException(e.getCause(), this);
      }
      // else nothing to do, accessTokenRefreshedOnStart remains false and this is called later
    } catch (InterruptedException e) {
      super.stop();
      currentThread().interrupt();
      throw new LifecycleException(e, this);
    }
  }

  @Override
  public CompletableFuture<String> accessToken() throws RequestAuthenticationException {
    if (!accessTokenRefreshedOnStart) {
      accessTokenRefreshedOnStart = true;
      return refreshToken().thenApply(v -> getContext().getAccessToken());
    }

    final String accessToken = getContext().getAccessToken();
    if (accessToken == null) {
      LOGGER.info("Previously stored token has been invalidated. Refreshing...");
      return refreshToken().thenApply(v -> getContext().getAccessToken());
    }

    // TODO MULE-11858 proactively refresh if the token has already expired based on its 'expiresIn' parameter
    return completedFuture(accessToken);
  }

  private volatile CompletableFuture<Void> lastRefreshTokenFuture;
  private Lock refreshTokenLock;

  @Override
  public CompletableFuture<Void> refreshToken() {
    boolean lockWasAcqired = refreshTokenLock.tryLock();

    if (lockWasAcqired) {
      try {
        lastRefreshTokenFuture = doRefreshToken();
        return lastRefreshTokenFuture;
      } finally {
        refreshTokenLock.unlock();
      }
    } else {
      refreshTokenLock.lock();
      try {
        return lastRefreshTokenFuture;
      } finally {
        refreshTokenLock.unlock();
      }
    }
  }

  private CompletableFuture<Void> doRefreshToken() {
    final Map<String, String> formData = new HashMap<>();

    formData.put(GRANT_TYPE_PARAMETER, GRANT_TYPE_CLIENT_CREDENTIALS);
    if (scopes != null) {
      formData.put(SCOPE_PARAMETER, scopes);
    }
    String authorization = handleClientCredentials(formData, encodeClientCredentialsInBody);

    return invokeTokenUrl(tokenUrl, formData, authorization, false, encoding).thenAccept(tokenResponse -> {
      withContextClassLoader(DefaultClientCredentialsOAuthDancer.class.getClassLoader(), () -> {
        if (LOGGER.isDebugEnabled()) {
          LOGGER.debug("Retrieved access token, refresh token and expires from token url are: %s, %s, %s",
                       tokenResponse.getAccessToken(), tokenResponse.getRefreshToken(), tokenResponse.getExpiresIn());
        }

        final DefaultResourceOwnerOAuthContext defaultUserState = (DefaultResourceOwnerOAuthContext) getContext();
        defaultUserState.setAccessToken(tokenResponse.getAccessToken());
        defaultUserState.setExpiresIn(tokenResponse.getExpiresIn());
        for (Entry<String, Object> customResponseParameterEntry : tokenResponse.getCustomResponseParameters().entrySet()) {
          defaultUserState.getTokenResponseParameters().put(customResponseParameterEntry.getKey(),
                                                            customResponseParameterEntry.getValue());
        }

        updateResourceOwnerOAuthContext(defaultUserState);
      });
    });
  }

  @Override
  public void invalidateContext() {
    invalidateContext(DEFAULT_RESOURCE_OWNER_ID);
  }

  @Override
  public ResourceOwnerOAuthContext getContext() {
    return getContextForResourceOwner(DEFAULT_RESOURCE_OWNER_ID);
  }

  @Override
  public void addListener(ClientCredentialsListener listener) {
    doAddListener(listener);
  }

  @Override
  public void removeListener(ClientCredentialsListener listener) {
    doRemoveListener(listener);
  }
}
