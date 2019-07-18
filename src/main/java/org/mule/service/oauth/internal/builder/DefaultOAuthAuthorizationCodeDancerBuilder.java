/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.service.oauth.internal.builder;

import static java.util.Collections.emptyMap;
import static java.util.Objects.requireNonNull;
import static java.util.Optional.empty;
import static java.util.Optional.of;
import static org.apache.commons.lang3.StringUtils.isNotBlank;
import static org.mule.runtime.api.util.Preconditions.checkArgument;

import org.mule.runtime.api.el.MuleExpressionLanguage;
import org.mule.runtime.api.exception.MuleRuntimeException;
import org.mule.runtime.api.lock.LockFactory;
import org.mule.runtime.api.scheduler.SchedulerService;
import org.mule.runtime.api.tls.TlsContextFactory;
import org.mule.runtime.api.util.Pair;
import org.mule.runtime.http.api.HttpService;
import org.mule.runtime.http.api.client.HttpClient;
import org.mule.runtime.http.api.client.proxy.ProxyConfig;
import org.mule.runtime.http.api.server.HttpServer;
import org.mule.runtime.http.api.server.HttpServerConfiguration;
import org.mule.runtime.http.api.server.ServerCreationException;
import org.mule.runtime.oauth.api.AuthorizationCodeOAuthDancer;
import org.mule.runtime.oauth.api.AuthorizationCodeRequest;
import org.mule.runtime.oauth.api.builder.AuthorizationCodeDanceCallbackContext;
import org.mule.runtime.oauth.api.listener.AuthorizationCodeListener;
import org.mule.runtime.oauth.api.builder.OAuthAuthorizationCodeDancerBuilder;
import org.mule.runtime.oauth.api.state.DefaultResourceOwnerOAuthContext;
import org.mule.runtime.oauth.api.state.ResourceOwnerOAuthContext;
import org.mule.service.oauth.internal.DefaultAuthorizationCodeOAuthDancer;

import java.net.URL;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.function.Supplier;

import com.github.benmanes.caffeine.cache.LoadingCache;

public class DefaultOAuthAuthorizationCodeDancerBuilder extends AbstractOAuthDancerBuilder<AuthorizationCodeOAuthDancer>
    implements OAuthAuthorizationCodeDancerBuilder {

  private final HttpService httpService;

  private Supplier<HttpServer> localCallbackServerFactory;
  private String localCallbackUrlPath;
  private String localAuthorizationUrlPath;
  private String localAuthorizationUrlResourceOwnerId;
  private String externalCallbackUrl;

  private String state;
  private String authorizationUrl;
  private final List<AuthorizationCodeListener> listeners = new LinkedList<>();

  private Supplier<Map<String, String>> customParameters = () -> emptyMap();

  private Function<AuthorizationCodeRequest, AuthorizationCodeDanceCallbackContext> beforeDanceCallback = r -> k -> empty();
  private BiConsumer<AuthorizationCodeDanceCallbackContext, ResourceOwnerOAuthContext> afterDanceCallback = (vars, ctx) -> {
  };

  public DefaultOAuthAuthorizationCodeDancerBuilder(SchedulerService schedulerService, LockFactory lockProvider,
                                                    Map<String, DefaultResourceOwnerOAuthContext> tokensStore,
                                                    HttpService httpService,
                                                    LoadingCache<Pair<TlsContextFactory, ProxyConfig>, HttpClient> httpClientCache,
                                                    MuleExpressionLanguage expressionEvaluator) {
    super(lockProvider, tokensStore, httpClientCache, expressionEvaluator);
    this.httpService = httpService;
    encodeClientCredentialsInBody = true;
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder localCallback(URL localCallbackUrl) {
    localCallbackServerFactory = () -> {
      final HttpServerConfiguration.Builder serverConfigBuilder = new HttpServerConfiguration.Builder();
      serverConfigBuilder.setHost(localCallbackUrl.getHost()).setPort(localCallbackUrl.getPort())
          .setName(localCallbackUrl.toString());
      try {
        return httpService.getServerFactory().create(serverConfigBuilder.build());
      } catch (ServerCreationException e) {
        throw new MuleRuntimeException(e);
      }
    };
    localCallbackUrlPath = localCallbackUrl.getPath();

    return this;
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder localCallback(URL localCallbackUrl, TlsContextFactory tlsContextFactory) {
    localCallbackServerFactory = () -> {
      final HttpServerConfiguration.Builder serverConfigBuilder = new HttpServerConfiguration.Builder();
      serverConfigBuilder.setHost(localCallbackUrl.getHost()).setPort(localCallbackUrl.getPort())
          .setName(localCallbackUrl.toString());
      serverConfigBuilder.setTlsContextFactory(tlsContextFactory);
      try {
        return httpService.getServerFactory().create(serverConfigBuilder.build());
      } catch (ServerCreationException e) {
        throw new MuleRuntimeException(e);
      }
    };
    localCallbackUrlPath = localCallbackUrl.getPath();

    return this;
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder localCallback(HttpServer server, String localCallbackConfigPath) {
    localCallbackServerFactory = () -> server;

    localCallbackUrlPath = localCallbackConfigPath;
    return this;
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder localAuthorizationUrlPath(String path) {
    this.localAuthorizationUrlPath = path;
    return this;
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder localAuthorizationUrlResourceOwnerId(String localAuthorizationUrlResourceOwnerIdExpr) {
    this.localAuthorizationUrlResourceOwnerId = localAuthorizationUrlResourceOwnerIdExpr;
    return this;
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder customParameters(Map<String, String> customParameters) {
    requireNonNull(customParameters, "customParameters cannot be null");
    return customParameters(() -> customParameters);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder customParameters(Supplier<Map<String, String>> customParameters) {
    requireNonNull(customParameters, "customParameters cannot be null");
    this.customParameters = customParameters;
    return this;
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder state(String stateExpr) {
    this.state = stateExpr;
    return this;
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder authorizationUrl(String authorizationUrl) {
    this.authorizationUrl = authorizationUrl;
    return this;
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder externalCallbackUrl(String externalCallbackUrl) {
    this.externalCallbackUrl = externalCallbackUrl;
    return this;
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder beforeDanceCallback(Function<AuthorizationCodeRequest, AuthorizationCodeDanceCallbackContext> beforeDanceCallback) {
    requireNonNull(beforeDanceCallback, "beforeDanceCallback cannot be null");
    this.beforeDanceCallback = beforeDanceCallback;
    return this;
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder afterDanceCallback(BiConsumer<AuthorizationCodeDanceCallbackContext, ResourceOwnerOAuthContext> afterDanceCallback) {
    requireNonNull(afterDanceCallback, "afterDanceCallback cannot be null");
    this.afterDanceCallback = afterDanceCallback;
    return this;
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder encodeClientCredentialsInBody(boolean encodeClientCredentialsInBody) {
    return (OAuthAuthorizationCodeDancerBuilder) super.encodeClientCredentialsInBody(encodeClientCredentialsInBody);
  }

  @Override
  public OAuthAuthorizationCodeDancerBuilder addListener(AuthorizationCodeListener listener) {
    requireNonNull(listener, "Cannot add a null listener");
    listeners.add(listener);

    return this;
  }

  @Override
  public AuthorizationCodeOAuthDancer build() {
    checkArgument(isNotBlank(clientId), "clientId cannot be blank");
    checkArgument(isNotBlank(clientSecret), "clientSecret cannot be blank");
    checkArgument(isNotBlank(tokenUrl), "tokenUrl cannot be blank");
    checkArgument(isNotBlank(authorizationUrl), "authorizationUrl cannot be blank");

    Optional<HttpServer> httpServer = localCallbackServerFactory != null ? of(localCallbackServerFactory.get()) : empty();

    return new DefaultAuthorizationCodeOAuthDancer(httpServer, clientId, clientSecret,
                                                   tokenUrl, scopes, encodeClientCredentialsInBody, externalCallbackUrl, encoding,
                                                   localCallbackUrlPath, localAuthorizationUrlPath,
                                                   localAuthorizationUrlResourceOwnerId, state,
                                                   authorizationUrl, responseAccessTokenExpr, responseRefreshTokenExpr,
                                                   responseExpiresInExpr, customParameters, customParametersExtractorsExprs,
                                                   resourceOwnerIdTransformer, lockProvider, tokensStore,
                                                   httpClientFactory.get(), expressionEvaluator, beforeDanceCallback,
                                                   afterDanceCallback, listeners);
  }

}
