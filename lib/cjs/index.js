'use strict';

Object.defineProperty(exports, '__esModule', { value: true });

var crossFetch = require('cross-fetch');

function _interopDefaultLegacy (e) { return e && typeof e === 'object' && 'default' in e ? e : { 'default': e }; }

var crossFetch__default = /*#__PURE__*/_interopDefaultLegacy(crossFetch);

/*! *****************************************************************************
Copyright (c) Microsoft Corporation.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
***************************************************************************** */

function __awaiter(thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
}

const DEFAULT_AUTHORIZE_TIMEOUT_IN_SECONDS = 60;
const CLEANUP_IFRAME_TIMEOUT_IN_SECONDS = 2;

exports.OAuthProviders = void 0;
(function (OAuthProviders) {
    OAuthProviders["Apple"] = "apple";
    OAuthProviders["Github"] = "github";
    OAuthProviders["Google"] = "google";
    OAuthProviders["Facebook"] = "facebook";
    OAuthProviders["LinkedIn"] = "linkedin";
})(exports.OAuthProviders || (exports.OAuthProviders = {}));
exports.ResponseTypes = void 0;
(function (ResponseTypes) {
    ResponseTypes["Code"] = "code";
    ResponseTypes["Token"] = "token";
})(exports.ResponseTypes || (exports.ResponseTypes = {}));

const hasWindow = () => typeof window !== 'undefined';
const trimURL = (url) => {
    let trimmedData = url.trim();
    const lastChar = trimmedData[trimmedData.length - 1];
    if (lastChar === '/') {
        trimmedData = trimmedData.slice(0, -1);
    }
    else {
        trimmedData = trimmedData;
    }
    return trimmedData;
};
const getCrypto = () => {
    return hasWindow()
        ? (window.crypto || window.msCrypto)
        : null;
};
const getCryptoSubtle = () => {
    const crypto = getCrypto();
    return (crypto && crypto.subtle) || crypto.webkitSubtle;
};
const createRandomString = () => {
    const charset = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_~.';
    let random = '';
    const crypto = getCrypto();
    if (crypto) {
        const randomValues = Array.from(crypto.getRandomValues(new Uint8Array(43)));
        randomValues.forEach((v) => (random += charset[v % charset.length]));
    }
    return random;
};
const encode = (value) => hasWindow() ? btoa(value) : Buffer.from(value).toString('base64');
const createQueryParams = (params) => {
    return Object.keys(params)
        .filter((k) => typeof params[k] !== 'undefined')
        .map((k) => encodeURIComponent(k) + '=' + encodeURIComponent(params[k]))
        .join('&');
};
const sha256 = (s) => __awaiter(void 0, void 0, void 0, function* () {
    const digestOp = getCryptoSubtle().digest({ name: 'SHA-256' }, new TextEncoder().encode(s));
    if (window.msCrypto) {
        return new Promise((res, rej) => {
            digestOp.oncomplete = (e) => {
                res(e.target.result);
            };
            digestOp.onerror = (e) => {
                rej(e.error);
            };
            digestOp.onabort = () => {
                rej('The digest operation was aborted');
            };
        });
    }
    return yield digestOp;
});
const urlEncodeB64 = (input) => {
    const b64Chars = { '+': '-', '/': '_', '=': '' };
    return input.replace(/[+/=]/g, (m) => b64Chars[m]);
};
const bufferToBase64UrlEncoded = (input) => {
    const ie11SafeInput = new Uint8Array(input);
    return urlEncodeB64(window.btoa(String.fromCharCode(...Array.from(ie11SafeInput))));
};
const executeIframe = (authorizeUrl, eventOrigin, timeoutInSeconds = DEFAULT_AUTHORIZE_TIMEOUT_IN_SECONDS) => {
    return new Promise((res, rej) => {
        const iframe = window.document.createElement('iframe');
        iframe.setAttribute('id', 'authorizer-iframe');
        iframe.setAttribute('width', '0');
        iframe.setAttribute('height', '0');
        iframe.style.display = 'none';
        const removeIframe = () => {
            if (window.document.body.contains(iframe)) {
                window.document.body.removeChild(iframe);
                window.removeEventListener('message', iframeEventHandler, false);
            }
        };
        let iframeEventHandler;
        const timeoutSetTimeoutId = setTimeout(() => {
            removeIframe();
        }, timeoutInSeconds * 1000);
        iframeEventHandler = function (e) {
            if (e.origin != eventOrigin)
                return;
            if (!e.data || !e.data.response)
                return;
            const eventSource = e.source;
            if (eventSource) {
                eventSource.close();
            }
            e.data.response.error ? rej(e.data.response) : res(e.data.response);
            clearTimeout(timeoutSetTimeoutId);
            window.removeEventListener('message', iframeEventHandler, false);
            setTimeout(removeIframe, CLEANUP_IFRAME_TIMEOUT_IN_SECONDS * 1000);
        };
        window.addEventListener('message', iframeEventHandler, false);
        window.document.body.appendChild(iframe);
        iframe.setAttribute('src', authorizeUrl);
    });
};

const userFragment = `id email email_verified given_name family_name middle_name nickname preferred_username picture signup_methods gender birthdate phone_number phone_number_verified roles created_at updated_at is_multi_factor_auth_enabled `;
const authTokenFragment = `message access_token expires_in refresh_token id_token should_show_otp_screen user { ${userFragment} }`;
const getFetcher = () => (hasWindow() ? window.fetch : crossFetch__default['default']);
class Authorizer {
    constructor(config) {
        this.authorize = (data) => __awaiter(this, void 0, void 0, function* () {
            if (!hasWindow()) {
                throw new Error(`this feature is only supported in browser`);
            }
            const scopes = ['openid', 'profile', 'email'];
            if (data.use_refresh_token) {
                scopes.push('offline_access');
            }
            const requestData = {
                redirect_uri: this.config.redirectURL,
                response_mode: data.response_mode || 'web_message',
                state: encode(createRandomString()),
                nonce: encode(createRandomString()),
                response_type: data.response_type,
                scope: scopes.join(' '),
                client_id: this.config.clientID,
            };
            if (data.response_type === exports.ResponseTypes.Code) {
                this.codeVerifier = createRandomString();
                const sha = yield sha256(this.codeVerifier);
                const codeChallenge = bufferToBase64UrlEncoded(sha);
                requestData.code_challenge = codeChallenge;
            }
            const authorizeURL = `${this.config.authorizerURL}/authorize?${createQueryParams(requestData)}`;
            try {
                const iframeRes = yield executeIframe(authorizeURL, this.config.authorizerURL, DEFAULT_AUTHORIZE_TIMEOUT_IN_SECONDS);
                if (data.response_type === exports.ResponseTypes.Code) {
                    const token = yield this.getToken({ code: iframeRes.code });
                    return token;
                }
                return iframeRes;
            }
            catch (err) {
                if (err.error) {
                    window.location.replace(`${this.config.authorizerURL}/app?state=${encode(JSON.stringify(this.config))}&redirect_uri=${this.config.redirectURL}`);
                }
                throw err;
            }
        });
        this.browserLogin = () => __awaiter(this, void 0, void 0, function* () {
            try {
                const token = yield this.getSession();
                return token;
            }
            catch (err) {
                if (!hasWindow()) {
                    throw new Error(`browserLogin is only supported for browsers`);
                }
                window.location.replace(`${this.config.authorizerURL}/app?state=${encode(JSON.stringify(this.config))}&redirect_uri=${this.config.redirectURL}`);
            }
        });
        this.forgotPassword = (data) => __awaiter(this, void 0, void 0, function* () {
            if (!data.state) {
                data.state = encode(createRandomString());
            }
            if (!data.redirect_uri) {
                data.redirect_uri = this.config.redirectURL;
            }
            try {
                const forgotPasswordRes = yield this.graphqlQuery({
                    query: `mutation forgotPassword($data: ForgotPasswordInput!) {	forgot_password(params: $data) { message } }`,
                    variables: {
                        data,
                    },
                });
                return forgotPasswordRes.forgot_password;
            }
            catch (error) {
                throw error;
            }
        });
        this.getMetaData = () => __awaiter(this, void 0, void 0, function* () {
            try {
                const res = yield this.graphqlQuery({
                    query: `query { meta { version is_google_login_enabled is_facebook_login_enabled is_github_login_enabled is_linkedin_login_enabled is_apple_login_enabled is_twitter_login_enabled is_email_verification_enabled is_basic_authentication_enabled is_magic_link_login_enabled is_sign_up_enabled is_strong_password_enabled } }`,
                });
                return res.meta;
            }
            catch (err) {
                throw err;
            }
        });
        this.getProfile = (headers) => __awaiter(this, void 0, void 0, function* () {
            try {
                const profileRes = yield this.graphqlQuery({
                    query: `query {	profile { ${userFragment} } }`,
                    headers,
                });
                return profileRes.profile;
            }
            catch (error) {
                throw error;
            }
        });
        this.getSession = (headers, params) => __awaiter(this, void 0, void 0, function* () {
            try {
                const res = yield this.graphqlQuery({
                    query: `query getSession($params: SessionQueryInput){session(params: $params) { ${authTokenFragment} } }`,
                    headers,
                    variables: {
                        params,
                    },
                });
                return res.session;
            }
            catch (err) {
                throw err;
            }
        });
        this.getToken = (data) => __awaiter(this, void 0, void 0, function* () {
            if (!data.grant_type) {
                data.grant_type = 'authorization_code';
            }
            if (data.grant_type === 'refresh_token' && !data.refresh_token) {
                throw new Error(`Invalid refresh_token`);
            }
            if (data.grant_type === 'authorization_code' && !this.codeVerifier) {
                throw new Error(`Invalid code verifier`);
            }
            const requestData = {
                client_id: this.config.clientID,
                code: data.code || '',
                code_verifier: this.codeVerifier || '',
                grant_type: data.grant_type || '',
                refresh_token: data.refresh_token || '',
            };
            try {
                const fetcher = getFetcher();
                const res = yield fetcher(`${this.config.authorizerURL}/oauth/token`, {
                    method: 'POST',
                    body: JSON.stringify(requestData),
                    headers: Object.assign({}, this.config.extraHeaders),
                    credentials: 'include',
                });
                const json = yield res.json();
                if (res.status >= 400) {
                    throw new Error(json);
                }
                return json;
            }
            catch (err) {
                throw err;
            }
        });
        this.graphqlQuery = (data) => __awaiter(this, void 0, void 0, function* () {
            const fetcher = getFetcher();
            const res = yield fetcher(this.config.authorizerURL + '/graphql', {
                method: 'POST',
                body: JSON.stringify({
                    query: data.query,
                    variables: data.variables || {},
                }),
                headers: Object.assign(Object.assign({}, this.config.extraHeaders), (data.headers || {})),
                credentials: 'include',
            });
            const json = yield res.json();
            if (json.errors && json.errors.length) {
                console.error(json.errors);
                throw new Error(json.errors[0].message);
            }
            return json.data;
        });
        this.login = (data) => __awaiter(this, void 0, void 0, function* () {
            try {
                const res = yield this.graphqlQuery({
                    query: `
					mutation login($data: LoginInput!) { login(params: $data) { ${authTokenFragment}}}
				`,
                    variables: { data },
                });
                return res.login;
            }
            catch (err) {
                throw err;
            }
        });
        this.logout = (headers) => __awaiter(this, void 0, void 0, function* () {
            try {
                const res = yield this.graphqlQuery({
                    query: ` mutation { logout { message } } `,
                    headers,
                });
                return res.logout;
            }
            catch (err) {
                console.error(err);
            }
        });
        this.magicLinkLogin = (data) => __awaiter(this, void 0, void 0, function* () {
            try {
                if (!data.state) {
                    data.state = encode(createRandomString());
                }
                if (!data.redirect_uri) {
                    data.redirect_uri = this.config.redirectURL;
                }
                const res = yield this.graphqlQuery({
                    query: `
					mutation magicLinkLogin($data: MagicLinkLoginInput!) { magic_link_login(params: $data) { message }}
				`,
                    variables: { data },
                });
                return res.magic_link_login;
            }
            catch (err) {
                throw err;
            }
        });
        this.oauthLogin = (oauthProvider, roles, redirect_uri, state) => __awaiter(this, void 0, void 0, function* () {
            let urlState = state;
            if (!urlState) {
                urlState = encode(createRandomString());
            }
            if (!Object.values(exports.OAuthProviders).includes(oauthProvider)) {
                throw new Error(`only following oauth providers are supported: ${Object.values(oauthProvider).toString()}`);
            }
            if (!hasWindow()) {
                throw new Error(`oauthLogin is only supported for browsers`);
            }
            window.location.replace(`${this.config.authorizerURL}/oauth_login/${oauthProvider}?redirect_uri=${redirect_uri || this.config.redirectURL}&state=${urlState}${roles && roles.length ? `&roles=${roles.join(',')}` : ``}`);
        });
        this.resendOtp = (data) => __awaiter(this, void 0, void 0, function* () {
            try {
                const res = yield this.graphqlQuery({
                    query: `
					mutation resendOtp($data: ResendOTPRequest!) { resend_otp(params: $data) { message }}
				`,
                    variables: { data },
                });
                return res.resend_otp;
            }
            catch (err) {
                throw err;
            }
        });
        this.resetPassword = (data) => __awaiter(this, void 0, void 0, function* () {
            try {
                const resetPasswordRes = yield this.graphqlQuery({
                    query: `mutation resetPassword($data: ResetPasswordInput!) {	reset_password(params: $data) { message } }`,
                    variables: {
                        data,
                    },
                });
                return resetPasswordRes.reset_password;
            }
            catch (error) {
                throw error;
            }
        });
        this.revokeToken = (data) => __awaiter(this, void 0, void 0, function* () {
            if (!data.refresh_token && !data.refresh_token.trim()) {
                throw new Error(`Invalid refresh_token`);
            }
            const fetcher = getFetcher();
            const res = yield fetcher(this.config.authorizerURL + '/oauth/revoke', {
                method: 'POST',
                headers: Object.assign({}, this.config.extraHeaders),
                body: JSON.stringify({
                    refresh_token: data.refresh_token,
                    client_id: this.config.clientID,
                }),
            });
            return yield res.json();
        });
        this.signup = (data) => __awaiter(this, void 0, void 0, function* () {
            try {
                const res = yield this.graphqlQuery({
                    query: `
					mutation signup($data: SignUpInput!) { signup(params: $data) { ${authTokenFragment}}}
				`,
                    variables: { data },
                });
                return res.signup;
            }
            catch (err) {
                throw err;
            }
        });
        this.updateProfile = (data, headers) => __awaiter(this, void 0, void 0, function* () {
            try {
                const updateProfileRes = yield this.graphqlQuery({
                    query: `mutation updateProfile($data: UpdateProfileInput!) {	update_profile(params: $data) { message } }`,
                    headers,
                    variables: {
                        data,
                    },
                });
                return updateProfileRes.update_profile;
            }
            catch (error) {
                throw error;
            }
        });
        this.validateJWTToken = (params) => __awaiter(this, void 0, void 0, function* () {
            try {
                const res = yield this.graphqlQuery({
                    query: `query validateJWTToken($params: ValidateJWTTokenInput!){validate_jwt_token(params: $params) { is_valid claims } }`,
                    variables: {
                        params,
                    },
                });
                return res.validate_jwt_token;
            }
            catch (error) {
                throw error;
            }
        });
        this.verifyEmail = (data) => __awaiter(this, void 0, void 0, function* () {
            try {
                const res = yield this.graphqlQuery({
                    query: `
					mutation verifyEmail($data: VerifyEmailInput!) { verify_email(params: $data) { ${authTokenFragment}}}
				`,
                    variables: { data },
                });
                return res.verify_email;
            }
            catch (err) {
                throw err;
            }
        });
        this.verifyOtp = (data) => __awaiter(this, void 0, void 0, function* () {
            try {
                const res = yield this.graphqlQuery({
                    query: `
					mutation verifyOtp($data: VerifyOTPRequest!) { verify_otp(params: $data) { ${authTokenFragment}}}
				`,
                    variables: { data },
                });
                return res.verify_otp;
            }
            catch (err) {
                throw err;
            }
        });
        if (!config) {
            throw new Error(`Configuration is required`);
        }
        this.config = config;
        if (!config.authorizerURL && !config.authorizerURL.trim()) {
            throw new Error(`Invalid authorizerURL`);
        }
        if (config.authorizerURL) {
            this.config.authorizerURL = trimURL(config.authorizerURL);
        }
        if (!config.redirectURL && !config.redirectURL.trim()) {
            throw new Error(`Invalid redirectURL`);
        }
        else {
            this.config.redirectURL = trimURL(config.redirectURL);
        }
        this.config.extraHeaders = Object.assign(Object.assign({}, (config.extraHeaders || {})), { 'x-authorizer-url': this.config.authorizerURL, 'Content-Type': 'application/json' });
        this.config.clientID = config.clientID.trim();
    }
}

exports.Authorizer = Authorizer;
//# sourceMappingURL=index.js.map
