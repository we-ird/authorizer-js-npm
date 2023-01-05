import * as Types from './types';
export * from './types';
export declare class Authorizer {
    config: Types.ConfigType;
    codeVerifier: string;
    constructor(config: Types.ConfigType);
    authorize: (data: Types.AuthorizeInput) => Promise<Types.AuthorizeResponse | Types.GetTokenResponse>;
    browserLogin: () => Promise<Types.AuthToken | void>;
    forgotPassword: (data: Types.ForgotPasswordInput) => Promise<Types.Response | void>;
    getMetaData: () => Promise<Types.MetaData | void>;
    getProfile: (headers?: Types.Headers | undefined) => Promise<Types.User | void>;
    getSession: (headers?: Types.Headers | undefined, params?: Types.SessionQueryInput | undefined) => Promise<Types.AuthToken>;
    getToken: (data: Types.GetTokenInput) => Promise<Types.GetTokenResponse>;
    graphqlQuery: (data: Types.GraphqlQueryInput) => Promise<any>;
    login: (data: Types.LoginInput) => Promise<Types.AuthToken | void>;
    logout: (headers?: Types.Headers | undefined) => Promise<Types.Response | void>;
    magicLinkLogin: (data: Types.MagicLinkLoginInput) => Promise<Types.Response>;
    oauthLogin: (oauthProvider: string, roles?: string[] | undefined, redirect_uri?: string | undefined, state?: string | undefined) => Promise<void>;
    resendOtp: (data: Types.ResendOtpInput) => Promise<Types.Response | void>;
    resetPassword: (data: Types.ResetPasswordInput) => Promise<Types.Response | void>;
    revokeToken: (data: {
        refresh_token: string;
    }) => Promise<any>;
    signup: (data: Types.SignupInput) => Promise<Types.AuthToken | void>;
    updateProfile: (data: Types.UpdateProfileInput, headers?: Types.Headers | undefined) => Promise<Types.Response | void>;
    validateJWTToken: (params?: Types.ValidateJWTTokenInput | undefined) => Promise<Types.ValidateJWTTokenResponse>;
    verifyEmail: (data: Types.VerifyEmailInput) => Promise<Types.AuthToken | void>;
    verifyOtp: (data: Types.VerifyOtpInput) => Promise<Types.AuthToken | void>;
}
