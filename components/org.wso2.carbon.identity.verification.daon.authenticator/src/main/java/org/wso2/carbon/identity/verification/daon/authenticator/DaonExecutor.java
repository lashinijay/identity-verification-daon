/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com) All Rights Reserved.
 *
 *  WSO2 LLC. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */

package org.wso2.carbon.identity.verification.daon.authenticator;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.json.JSONObject;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.OpenIDConnectExecutor;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;
import org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants;

import java.util.HashMap;
import java.util.Map;

import static org.wso2.carbon.identity.flow.execution.engine.Constants.USERNAME_CLAIM_URI;
import static org.wso2.carbon.identity.verification.daon.authenticator.constants.DaonAuthenticatorConstants.*;

/**
 * Flow executor for Daon identity verification (IDV).
 *
 * <p>Handles the OIDC authorization-code flow against Daon's token endpoint. The returned
 * ID token carries a nested {@code claims} object containing IDV attributes (name, birthdate,
 * document details, address). These are extracted and stored in thread-local properties for
 * deferred persistence by {@link DaonPostUserRegistrationHandler}.</p>
 */
public class DaonExecutor extends OpenIDConnectExecutor {

    private static final Log LOG = LogFactory.getLog(DaonExecutor.class);
    private static final String DAON_EXECUTOR_NAME = "DaonExecutor";

    @Override
    public String getName() {
        return DAON_EXECUTOR_NAME;
    }

    @Override
    public String getAMRValue() {
        return DAON_EXECUTOR_NAME;
    }

    @Override
    public String getAuthorizationServerEndpoint(Map<String, String> authenticatorProperties) {
        String endpoint = authenticatorProperties.get(DaonAuthenticatorConstants.DAON_AUTH_ENDPOINT_PARAM);
        return StringUtils.isNotBlank(endpoint) ? endpoint : DaonAuthenticatorConstants.DAON_OAUTH_ENDPOINT;
    }

    @Override
    public String getTokenEndpoint(Map<String, String> authenticatorProperties) {
        String endpoint = authenticatorProperties.get(DaonAuthenticatorConstants.DAON_TOKEN_ENDPOINT_PARAM);
        return StringUtils.isNotBlank(endpoint) ? endpoint : DaonAuthenticatorConstants.DAON_TOKEN_ENDPOINT;
    }

    @Override
    public ExecutorResponse execute(FlowExecutionContext flowExecutionContext) {

        flowExecutionContext.setPortalUrl("https://is.test.com:9443/accounts/register");
        return super.execute(flowExecutionContext);
    }

    @Override
    public Map<String, String> getAdditionalQueryParams(Map<String, String> authenticatorProperties) {

        Map<String, String> params = new HashMap<>();
        try {
            params.put("claims", java.net.URLEncoder.encode(
                    DaonAuthenticatorConstants.DAON_CLAIMS_REQUEST_JSON, "UTF-8"));
        } catch (java.io.UnsupportedEncodingException e) {
            // UTF-8 is always supported; this branch is unreachable
            LOG.warn("Failed to URL-encode Daon claims request parameter.", e);
        }
        return params;
    }

    @Override
    protected Map<String, Object> resolveUserAttributes(FlowExecutionContext flowExecutionContext, String code)
            throws FlowEngineException {

        OAuthClientResponse oAuthResponse = requestAccessToken(flowExecutionContext, code);
        resolveAccessToken(oAuthResponse);

        String idToken = oAuthResponse.getParam(OIDCAuthenticatorConstants.ID_TOKEN);
        if (StringUtils.isBlank(idToken)) {
            throw handleFlowEngineServerException("ID token is empty or null.", null);
        }

        JSONObject idTokenPayload;
        try {
            idTokenPayload = DaonJwtUtil.decodeJwtPayload(idToken);
        } catch (IllegalArgumentException e) {
            throw handleFlowEngineServerException(e.getMessage(), e);
        }

        String subject = idTokenPayload.optString(DaonAuthenticatorConstants.JWT_SUBJECT_CLAIM, null);
        if (StringUtils.isBlank(subject)) {
            throw handleFlowEngineServerException("Subject (sub) claim not found in Daon ID token.", null);
        }

        Map<String, Object> userAttributes = new HashMap<>();
//        userAttributes.put(USERNAME_CLAIM_URI, subject);

        if (!idTokenPayload.has(DaonAuthenticatorConstants.JWT_VERIFIED_CLAIMS_OBJECT)) {
            LOG.warn("No 'verifiedClaims' object in Daon ID token for subject: " + subject);
            return userAttributes;
        }

        JSONObject verifiedClaims = idTokenPayload.getJSONObject(DaonAuthenticatorConstants.JWT_VERIFIED_CLAIMS_OBJECT);
        if (!verifiedClaims.has(DaonAuthenticatorConstants.JWT_CLAIMS_OBJECT)) {
            LOG.warn("No 'claims' object inside 'verifiedClaims' in Daon ID token for subject: " + subject);
            return userAttributes;
        }

        JSONObject daonClaims = verifiedClaims.getJSONObject(DaonAuthenticatorConstants.JWT_CLAIMS_OBJECT);
        Map<String, String> extractedClaims = new HashMap<>();
        for (Object keyObj : daonClaims.keySet()) {
            String key = (String) keyObj;
            String claimValue = DaonJwtUtil.resolveClaimValue(key, daonClaims.get(key));
            if (claimValue == null) {
                continue;
            }
            String claimUri = DaonAuthenticatorConstants.CLAIM_DIALECT_URI + "/" + key;
            extractedClaims.put(claimUri, claimValue);
//            userAttributes.put(claimUri, claimValue);
        }

        storeVerifiedClaimsInThreadLocal(extractedClaims);

        return userAttributes;
    }

    private void storeVerifiedClaimsInThreadLocal(Map<String, String> verifiedClaims) {

        Map<String, Object> threadLocalProps = IdentityUtil.threadLocalProperties.get();
        threadLocalProps.put(THREAD_LOCAL_DAON_VERIFIED_CLAIMS, verifiedClaims);
        threadLocalProps.put(THREAD_LOCAL_DAON_IDVP_ID, DAON_IDV_ID);
    }
}
