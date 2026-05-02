/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.verification.daon.authenticator.internal;

import org.wso2.carbon.extension.identity.verification.mgt.IdentityVerificationManager;
import org.wso2.carbon.extension.identity.verification.provider.IdVProviderManager;
import org.wso2.carbon.idp.mgt.IdpManager;

/**
 * Service holder for the Daon TrustX authenticator OSGi bundle.
 */
public class DaonAuthenticatorDataHolder {

    private static IdVProviderManager idVProviderManager;
    private static IdentityVerificationManager identityVerificationManager;
    private static IdpManager idpManager;

    private DaonAuthenticatorDataHolder() {
    }

    public static IdVProviderManager getIdVProviderManager() {

        if (idVProviderManager == null) {
            throw new RuntimeException("IdVProviderManager was not set during " +
                    "DaonAuthenticatorServiceComponent startup");
        }
        return idVProviderManager;
    }

    public static void setIdVProviderManager(IdVProviderManager idVProviderManager) {

        DaonAuthenticatorDataHolder.idVProviderManager = idVProviderManager;
    }
//
//    public static IdpManager getIdpManager() {
//
//        if (idpManager == null) {
//            throw new RuntimeException("IdpProviderManager was not set during " +
//                    "DaonAuthenticatorServiceComponent startup");
//        }
//        return idpManager;
//    }
//
//    public static void setIdpManager(IdpManager idpManager) {
//
//        DaonAuthenticatorDataHolder.idpManager = idpManager;
//    }

    public static IdentityVerificationManager getIdentityVerificationManager() {

        return identityVerificationManager;
    }

    public static void setIdentityVerificationManager(IdentityVerificationManager identityVerificationManager) {

        DaonAuthenticatorDataHolder.identityVerificationManager = identityVerificationManager;
    }
}
