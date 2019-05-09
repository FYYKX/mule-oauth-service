/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.test.oauth;

import static java.util.concurrent.Executors.newSingleThreadExecutor;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mule.runtime.core.api.lifecycle.LifecycleUtils.initialiseIfNeeded;
import static org.mule.runtime.core.api.lifecycle.LifecycleUtils.startIfNeeded;

import org.mule.runtime.api.el.MuleExpressionLanguage;
import org.mule.runtime.api.exception.MuleException;
import org.mule.runtime.api.lifecycle.InitialisationException;
import org.mule.runtime.api.lock.LockFactory;
import org.mule.runtime.api.scheduler.SchedulerService;
import org.mule.runtime.http.api.HttpService;
import org.mule.runtime.http.api.client.HttpClient;
import org.mule.runtime.http.api.client.HttpClientFactory;
import org.mule.runtime.http.api.domain.entity.InputStreamHttpEntity;
import org.mule.runtime.http.api.domain.message.response.HttpResponse;
import org.mule.runtime.http.api.server.HttpServer;
import org.mule.runtime.http.api.server.HttpServerFactory;
import org.mule.runtime.oauth.api.OAuthService;
import org.mule.runtime.oauth.api.builder.OAuthAuthorizationCodeDancerBuilder;
import org.mule.runtime.oauth.api.builder.OAuthClientCredentialsDancerBuilder;
import org.mule.runtime.oauth.api.builder.OAuthDancerBuilder;
import org.mule.service.oauth.internal.DefaultOAuthService;
import org.mule.tck.junit4.AbstractMuleContextTestCase;

import java.io.StringReader;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;

import javax.inject.Inject;

import org.apache.commons.io.input.ReaderInputStream;
import org.junit.After;
import org.junit.Before;

public abstract class AbstractOAuthTestCase extends AbstractMuleContextTestCase {

  protected OAuthService service;
  protected HttpClient httpClient;
  protected HttpServer httpServer;

  protected ExecutorService httpClientCallbackExecutor;

  @Inject
  protected LockFactory lockFactory;

  public AbstractOAuthTestCase() {
    setStartContext(true);
  }

  @Override
  protected boolean doTestClassInjection() {
    return true;
  }

  @Before
  public void setupServices() throws Exception {
    httpClientCallbackExecutor = newSingleThreadExecutor();

    final HttpService httpService = mock(HttpService.class);
    final HttpClientFactory httpClientFactory = mock(HttpClientFactory.class);
    httpClient = mock(HttpClient.class);
    when(httpClientFactory.create(any())).thenReturn(httpClient);
    when(httpService.getClientFactory()).thenReturn(httpClientFactory);

    final HttpServerFactory httpServerFactory = mock(HttpServerFactory.class);
    httpServer = mock(HttpServer.class);
    when(httpServerFactory.create(any())).thenReturn(httpServer);
    when(httpService.getServerFactory()).thenReturn(httpServerFactory);

    service = new DefaultOAuthService(httpService, mock(SchedulerService.class));

    final HttpResponse httpResponse = mock(HttpResponse.class);
    final InputStreamHttpEntity httpEntity = mock(InputStreamHttpEntity.class);
    when(httpEntity.getContent()).thenReturn(new ReaderInputStream(new StringReader("")));
    when(httpResponse.getEntity()).thenReturn(httpEntity);
    when(httpClient.sendAsync(any(), any())).thenAnswer(invocation -> {

      final CompletableFuture<HttpResponse> httpResponseFuture = new CompletableFuture<>();

      httpClientCallbackExecutor.execute(() -> {
        httpResponseFuture.complete(httpResponse);
      });

      return httpResponseFuture;
    });
  }

  @After
  public void teardownServices() {
    httpClientCallbackExecutor.shutdownNow();
  }

  protected OAuthClientCredentialsDancerBuilder baseClientCredentialsDancerBuilder() {
    return baseClientCredentialsDancerBuilder(new HashMap<>());
  }

  protected OAuthClientCredentialsDancerBuilder baseClientCredentialsDancerBuilder(Map<String, ?> tokensStore) {
    final OAuthClientCredentialsDancerBuilder builder =
        service.clientCredentialsGrantTypeDancerBuilder(lockFactory, tokensStore, mock(MuleExpressionLanguage.class));

    builder.clientCredentials("clientId", "clientSecret");
    return builder;
  }

  protected OAuthAuthorizationCodeDancerBuilder baseAuthCodeDancerbuilder() {
    final OAuthAuthorizationCodeDancerBuilder builder =
        service.authorizationCodeGrantTypeDancerBuilder(lockFactory, new HashMap<>(), mock(MuleExpressionLanguage.class));

    builder.clientCredentials("clientId", "clientSecret");
    return builder;
  }

  protected <D> D startDancer(final OAuthDancerBuilder<D> builder)
      throws InitialisationException, MuleException {
    final D dancer = builder.build();
    initialiseIfNeeded(dancer);
    startIfNeeded(dancer);

    return dancer;
  }
}
