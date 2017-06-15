/*
 * Copyright (c) MuleSoft, Inc.  All rights reserved.  http://www.mulesoft.com
 * The software in this package is published under the terms of the CPAL v1.0
 * license, a copy of which has been included with this distribution in the
 * LICENSE.txt file.
 */
package org.mule.test.oauth.internal;

import static java.util.Collections.emptyMap;
import static java.util.Collections.singleton;
import static java.util.Collections.singletonMap;
import static java.util.Optional.empty;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.Matchers.sameInstance;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentCaptor.forClass;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyBoolean;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mule.runtime.core.api.lifecycle.LifecycleUtils.initialiseIfNeeded;
import static org.mule.runtime.core.api.lifecycle.LifecycleUtils.startIfNeeded;
import static org.mule.runtime.core.api.lifecycle.LifecycleUtils.stopIfNeeded;
import static org.mule.runtime.http.api.HttpConstants.Method.GET;
import static org.mule.service.oauth.internal.OAuthConstants.CODE_PARAMETER;
import static org.mule.service.oauth.internal.OAuthConstants.STATE_PARAMETER;
import static org.mule.service.oauth.internal.state.StateEncoder.RESOURCE_OWNER_PARAM_NAME_ASSIGN;

import org.mule.runtime.api.connection.ConnectionException;
import org.mule.runtime.api.el.MuleExpressionLanguage;
import org.mule.runtime.api.exception.MuleException;
import org.mule.runtime.api.lifecycle.InitialisationException;
import org.mule.runtime.api.lock.LockFactory;
import org.mule.runtime.core.api.registry.RegistrationException;
import org.mule.runtime.core.api.scheduler.SchedulerService;
import org.mule.runtime.http.api.HttpService;
import org.mule.runtime.http.api.client.HttpClient;
import org.mule.runtime.http.api.client.HttpClientFactory;
import org.mule.runtime.http.api.domain.ParameterMap;
import org.mule.runtime.http.api.domain.entity.InputStreamHttpEntity;
import org.mule.runtime.http.api.domain.message.request.HttpRequest;
import org.mule.runtime.http.api.domain.message.response.HttpResponse;
import org.mule.runtime.http.api.domain.request.HttpRequestContext;
import org.mule.runtime.http.api.server.HttpServer;
import org.mule.runtime.http.api.server.HttpServerFactory;
import org.mule.runtime.http.api.server.RequestHandler;
import org.mule.runtime.http.api.server.RequestHandlerManager;
import org.mule.runtime.http.api.server.async.HttpResponseReadyCallback;
import org.mule.runtime.oauth.api.AuthorizationCodeOAuthDancer;
import org.mule.runtime.oauth.api.OAuthService;
import org.mule.runtime.oauth.api.builder.AuthorizationCodeDanceCallbackContext;
import org.mule.runtime.oauth.api.builder.OAuthAuthorizationCodeDancerBuilder;
import org.mule.runtime.oauth.api.builder.OAuthClientCredentialsDancerBuilder;
import org.mule.runtime.oauth.api.builder.OAuthDancerBuilder;
import org.mule.runtime.oauth.api.state.DefaultResourceOwnerOAuthContext;
import org.mule.service.oauth.internal.DefaultOAuthService;
import org.mule.tck.junit4.AbstractMuleContextTestCase;

import java.io.IOException;
import java.io.StringReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.locks.ReentrantLock;

import org.apache.commons.io.input.ReaderInputStream;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import ru.yandex.qatools.allure.annotations.Features;

@Features("OAuth Service")
public class DancerConfigTestCase extends AbstractMuleContextTestCase {

  private OAuthService service;
  private HttpClient httpClient;
  private HttpServer httpServer;

  private ArgumentCaptor<RequestHandler> requestHandlerCaptor = forClass(RequestHandler.class);

  @Before
  public void before() throws ConnectionException, IOException, TimeoutException {
    final HttpService httpService = mock(HttpService.class);
    final HttpClientFactory httpClientFactory = mock(HttpClientFactory.class);
    httpClient = mock(HttpClient.class);
    when(httpClientFactory.create(any())).thenReturn(httpClient);
    when(httpService.getClientFactory()).thenReturn(httpClientFactory);

    final HttpServerFactory httpServerFactory = mock(HttpServerFactory.class);
    httpServer = mock(HttpServer.class);
    when(httpServer.addRequestHandler(anyString(), requestHandlerCaptor.capture())).thenReturn(mock(RequestHandlerManager.class));
    when(httpServer.addRequestHandler(any(), anyString(), requestHandlerCaptor.capture()))
        .thenReturn(mock(RequestHandlerManager.class));
    when(httpServerFactory.create(any())).thenReturn(httpServer);
    when(httpService.getServerFactory()).thenReturn(httpServerFactory);

    service = new DefaultOAuthService(httpService, mock(SchedulerService.class));

    final HttpResponse httpResponse = mock(HttpResponse.class);
    final InputStreamHttpEntity httpEntity = mock(InputStreamHttpEntity.class);
    when(httpEntity.getContent()).thenReturn(new ReaderInputStream(new StringReader("")));
    when(httpResponse.getEntity()).thenReturn(httpEntity);
    when(httpClient.send(any(), anyInt(), anyBoolean(), any())).thenReturn(httpResponse);
  }

  @Test
  public void clientCredentialsMinimal() throws MuleException {
    final OAuthClientCredentialsDancerBuilder builder = baseClientCredentialsDancerBuilder();
    builder.tokenUrl("http://host/token");

    Object minimalDancer = startDancer(builder);
    verify(httpClient).start();

    stopIfNeeded(minimalDancer);
    verify(httpClient).stop();
  }

  @Test
  public void authorizationCodeMinimal() throws MuleException, MalformedURLException {
    final OAuthAuthorizationCodeDancerBuilder builder = baseAuthCodeDancerbuilder();
    minimalAuthCodeConfig(builder);

    Object minimalDancer = startDancer(builder);
    verify(httpClient).start();

    stopIfNeeded(minimalDancer);
    verify(httpClient).stop();
  }

  private void minimalAuthCodeConfig(final OAuthAuthorizationCodeDancerBuilder builder) throws MalformedURLException {
    builder.tokenUrl("http://host/token");
    builder.authorizationUrl("http://host/auth");
    builder.localCallback(new URL("http://localhost:8080/localCallback"));
  }

  @Test
  public void clientCredentialsReuseHttpClient() throws MuleException, MalformedURLException {
    final OAuthAuthorizationCodeDancerBuilder builder = baseAuthCodeDancerbuilder();
    minimalAuthCodeConfig(builder);
    builder.tokenUrl(httpClient, "http://host/token");

    Object minimalDancer = startDancer(builder);
    verify(httpClient, never()).start();

    stopIfNeeded(minimalDancer);
    verify(httpClient, never()).stop();
  }

  @Test
  public void authorizationCodeReuseHttpClient() throws MuleException, MalformedURLException {
    final OAuthAuthorizationCodeDancerBuilder builder = baseAuthCodeDancerbuilder();
    minimalAuthCodeConfig(builder);
    builder.tokenUrl(httpClient, "http://host/token");
    builder.authorizationUrl("http://host/auth");
    builder.localCallback(new URL("http://localhost:8080/localCallback"));

    Object minimalDancer = startDancer(builder);
    verify(httpClient, never()).start();

    stopIfNeeded(minimalDancer);
    verify(httpClient, never()).stop();
  }

  @Test
  public void authorizationCodeReuseHttpServer() throws MuleException, IOException {
    final OAuthAuthorizationCodeDancerBuilder builder = baseAuthCodeDancerbuilder();
    minimalAuthCodeConfig(builder);
    builder.tokenUrl("http://host/token");
    builder.authorizationUrl("http://host/auth");
    builder.localCallback(httpServer, "/localCallback");

    Object minimalDancer = startDancer(builder);
    verify(httpServer).start();
    verify(httpServer).addRequestHandler(eq(singleton(GET.name())), eq("/localCallback"), any());

    stopIfNeeded(minimalDancer);
    verify(httpServer).stop();
  }

  @Test
  public void authorizationCodeBeforeCallback() throws MuleException, IOException {
    AtomicBoolean beforeCallbackCalled = new AtomicBoolean(false);
    String resourceOwner = "someOwner";

    final OAuthAuthorizationCodeDancerBuilder builder = baseAuthCodeDancerbuilder();
    minimalAuthCodeConfig(builder);
    builder.beforeDanceCallback(r -> {
      assertThat(r.getResourceOwnerId(), is(resourceOwner));
      assertThat(r.getAuthorizationUrl(), is("http://host/auth"));
      assertThat(r.getTokenUrl(), is("http://host/token"));
      assertThat(r.getClientId(), is("clientId"));
      assertThat(r.getClientSecret(), is("clientSecret"));
      assertThat(r.getScopes(), is(nullValue()));
      assertThat(r.getState(), is(empty()));

      beforeCallbackCalled.set(true);
      return null;
    });

    startDancer(builder);

    configureRequestHandler(resourceOwner, "");

    assertThat(beforeCallbackCalled.get(), is(true));
  }

  @Test
  public void authorizationCodeBeforeCallbackWithState() throws MuleException, IOException {
    AtomicBoolean beforeCallbackCalled = new AtomicBoolean(false);
    String originalState = "originalState";
    String resourceOwner = "someOwner";

    final OAuthAuthorizationCodeDancerBuilder builder = baseAuthCodeDancerbuilder();
    minimalAuthCodeConfig(builder);
    builder.beforeDanceCallback(r -> {
      assertThat(r.getState().get(), is(originalState));

      beforeCallbackCalled.set(true);
      return null;
    });

    startDancer(builder);

    configureRequestHandler(resourceOwner, originalState);

    assertThat(beforeCallbackCalled.get(), is(true));
  }

  @Test
  public void authorizationCodeBeforeCallbackWithScopes() throws MuleException, IOException {
    AtomicBoolean beforeCallbackCalled = new AtomicBoolean(false);
    String resourceOwner = "someOwner";

    final OAuthAuthorizationCodeDancerBuilder builder = baseAuthCodeDancerbuilder();
    minimalAuthCodeConfig(builder);
    builder.scopes("aScope");
    builder.beforeDanceCallback(r -> {
      assertThat(r.getScopes(), is("aScope"));

      beforeCallbackCalled.set(true);
      return null;
    });

    startDancer(builder);

    configureRequestHandler(resourceOwner, "");

    assertThat(beforeCallbackCalled.get(), is(true));
  }

  @Test
  public void authorizationCodeAfterCallback() throws MuleException, IOException {
    AtomicBoolean afterCallbackCalled = new AtomicBoolean(false);
    String resourceOwner = "someOwner";

    final OAuthAuthorizationCodeDancerBuilder builder = baseAuthCodeDancerbuilder();
    minimalAuthCodeConfig(builder);
    builder.responseAccessTokenExpr("someAccessToken")
        .responseExpiresInExpr("someExpiresIn")
        .responseRefreshTokenExpr("someRefreshToken");

    builder.afterDanceCallback((vars, ctx) -> {
      assertThat(ctx.getAccessToken(), is("someAccessToken"));
      assertThat(ctx.getExpiresIn(), is("someExpiresIn"));
      assertThat(ctx.getRefreshToken(), is("someRefreshToken"));
      assertThat(ctx.getResourceOwnerId(), is(resourceOwner));
      assertThat(ctx.getState(), is(nullValue()));
      assertThat(ctx.getTokenResponseParameters(), equalTo(emptyMap()));

      afterCallbackCalled.set(true);
    });

    startDancer(builder);

    configureRequestHandler(resourceOwner, "");

    assertThat(afterCallbackCalled.get(), is(true));
  }

  @Test
  public void authorizationCodeAfterCallbackWithState() throws MuleException, IOException {
    AtomicBoolean afterCallbackCalled = new AtomicBoolean(false);
    String originalState = "originalState";
    String resourceOwner = "someOwner";

    final OAuthAuthorizationCodeDancerBuilder builder = baseAuthCodeDancerbuilder();
    minimalAuthCodeConfig(builder);
    builder.responseAccessTokenExpr("someAccessToken")
        .responseExpiresInExpr("someExpiresIn")
        .responseRefreshTokenExpr("someRefreshToken");

    builder.afterDanceCallback((vars, ctx) -> {
      assertThat(ctx.getState(), is(originalState));

      afterCallbackCalled.set(true);
    });

    startDancer(builder);

    configureRequestHandler(resourceOwner, originalState);

    assertThat(afterCallbackCalled.get(), is(true));
  }

  @Test
  public void authorizationCodeAfterCallbackWithTokenResponseParams() throws MuleException, IOException {
    AtomicBoolean afterCallbackCalled = new AtomicBoolean(false);
    String resourceOwner = "someOwner";

    final OAuthAuthorizationCodeDancerBuilder builder = baseAuthCodeDancerbuilder();
    minimalAuthCodeConfig(builder);
    builder.responseAccessTokenExpr("someAccessToken")
        .responseExpiresInExpr("someExpiresIn")
        .responseRefreshTokenExpr("someRefreshToken");
    builder.customParametersExtractorsExprs(singletonMap("someKey", "someValue"));

    builder.afterDanceCallback((vars, ctx) -> {
      assertThat(ctx.getTokenResponseParameters(), equalTo(singletonMap("someKey", "someValue")));

      afterCallbackCalled.set(true);
    });

    startDancer(builder);

    configureRequestHandler(resourceOwner, "");

    assertThat(afterCallbackCalled.get(), is(true));
  }

  @Test
  public void authorizationCodeBeforeAfterCallbackVariables() throws MuleException, IOException {
    AtomicBoolean afterCallbackCalled = new AtomicBoolean(false);
    String resourceOwner = "someOwner";

    AuthorizationCodeDanceCallbackContext callbackContext = paramKey -> empty();

    final OAuthAuthorizationCodeDancerBuilder builder = baseAuthCodeDancerbuilder();
    minimalAuthCodeConfig(builder);
    builder.beforeDanceCallback(r -> {
      return callbackContext;
    });
    builder.afterDanceCallback((callbackCtx, ctx) -> {
      assertThat(callbackCtx, sameInstance(callbackContext));

      afterCallbackCalled.set(true);
    });

    startDancer(builder);

    configureRequestHandler(resourceOwner, "");

    assertThat(afterCallbackCalled.get(), is(true));
  }

  @Test
  public void multipleDancersShareTokensStore() throws MalformedURLException, InitialisationException, MuleException {
    final LockFactory lockFactory = muleContext.getRegistry().lookupObject(LockFactory.class);
    final Map<String, Object> tokensStore = new HashMap<>();
    final MuleExpressionLanguage el = mock(MuleExpressionLanguage.class);

    final OAuthAuthorizationCodeDancerBuilder builder1 =
        service.authorizationCodeGrantTypeDancerBuilder(lockFactory, tokensStore, el);
    final OAuthAuthorizationCodeDancerBuilder builder2 =
        service.authorizationCodeGrantTypeDancerBuilder(lockFactory, tokensStore, el);

    builder1.clientCredentials("clientId", "clientSecret");
    builder2.clientCredentials("clientId", "clientSecret");

    minimalAuthCodeConfig(builder1);
    minimalAuthCodeConfig(builder2);

    builder1.resourceOwnerIdTransformer(roid -> "conn1-" + roid);
    builder2.resourceOwnerIdTransformer(roid -> "conn2-" + roid);

    final AuthorizationCodeOAuthDancer dancer1 = startDancer(builder1);
    final AuthorizationCodeOAuthDancer dancer2 = startDancer(builder2);

    final DefaultResourceOwnerOAuthContext contextOwnerConn1 = new DefaultResourceOwnerOAuthContext(new ReentrantLock(), "owner");
    final DefaultResourceOwnerOAuthContext contextOwnerConn2 = new DefaultResourceOwnerOAuthContext(new ReentrantLock(), "owner");
    tokensStore.put("conn1-owner", contextOwnerConn1);
    tokensStore.put("conn2-owner", contextOwnerConn2);

    assertThat(dancer1.getContextForResourceOwner("owner"), sameInstance(contextOwnerConn1));
    assertThat(dancer2.getContextForResourceOwner("owner"), sameInstance(contextOwnerConn2));
  }

  private OAuthClientCredentialsDancerBuilder baseClientCredentialsDancerBuilder() throws RegistrationException {
    final OAuthClientCredentialsDancerBuilder builder =
        service.clientCredentialsGrantTypeDancerBuilder(muleContext.getRegistry().lookupObject(LockFactory.class),
                                                        new HashMap<>(), mock(MuleExpressionLanguage.class));

    builder.clientCredentials("clientId", "clientSecret");
    return builder;
  }

  private OAuthAuthorizationCodeDancerBuilder baseAuthCodeDancerbuilder() throws RegistrationException {
    final OAuthAuthorizationCodeDancerBuilder builder =
        service.authorizationCodeGrantTypeDancerBuilder(muleContext.getRegistry().lookupObject(LockFactory.class),
                                                        new HashMap<>(), mock(MuleExpressionLanguage.class));

    builder.clientCredentials("clientId", "clientSecret");
    return builder;
  }

  private <D> D startDancer(final OAuthDancerBuilder<D> builder)
      throws InitialisationException, MuleException {
    final D dancer = builder.build();
    initialiseIfNeeded(dancer);
    startIfNeeded(dancer);

    return dancer;
  }

  private void configureRequestHandler(String resourceOwner, String state) {
    HttpRequest authorizationRequest = mock(HttpRequest.class);
    ParameterMap authReqQueryParams = new ParameterMap();
    authReqQueryParams.put(STATE_PARAMETER, state + RESOURCE_OWNER_PARAM_NAME_ASSIGN + resourceOwner);
    authReqQueryParams.put(CODE_PARAMETER, "");
    when(authorizationRequest.getQueryParams()).thenReturn(authReqQueryParams);

    HttpRequestContext authorizationRequestContext = mock(HttpRequestContext.class);
    when(authorizationRequestContext.getRequest()).thenReturn(authorizationRequest);

    requestHandlerCaptor.getAllValues().get(0).handleRequest(authorizationRequestContext,
                                                             mock(HttpResponseReadyCallback.class));
  }
}
