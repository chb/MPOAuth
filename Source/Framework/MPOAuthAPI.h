//
//  MPOAuthAPI.h
//  MPOAuthConnection
//
//  Created by Karl Adam on 08.12.05.
//  Copyright 2008 matrixPointer. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "MPOAuthCredentialStore.h"
#import "MPOAuthParameterFactory.h"
#import "MPOAuthAPIRequestLoader.h"

extern NSString * const MPOAuthNotificationAccessTokenReceived;
extern NSString * const MPOAuthNotificationAccessTokenRejected;
extern NSString * const MPOAuthNotificationAccessTokenRefreshed;
extern NSString * const MPOAuthNotificationOAuthCredentialsReady;
extern NSString * const MPOAuthNotificationErrorHasOccurred;

extern NSString * const MPOAuthTokenRefreshDateDefaultsKey;

extern NSString * const MPOAuthBaseURLKey;
extern NSString * const MPOAuthAuthenticationURLKey;
extern NSString * const MPOAuthAuthenticationMethodKey;

typedef enum {
	MPOAuthSignatureSchemePlainText,
	MPOAuthSignatureSchemeHMACSHA1,
	MPOAuthSignatureSchemeRSASHA1
} MPOAuthSignatureScheme;

typedef enum {
	MPOAuthAuthenticationStateUnauthenticated		= 0,
	MPOAuthAuthenticationStateAuthenticating		= 1,
	MPOAuthAuthenticationStateAuthenticated			= 2
} MPOAuthAuthenticationState;


@protocol MPOAuthAPILoadDelegate <NSObject>

// one of the two will be called when the connection finishes
- (void)connectionFinishedWithResponse:(NSURLResponse *)aResponse data:(NSData *)inData;
- (void)connectionFailedWithResponse:(NSURLResponse *)aResponse error:(NSError *)inError;

@end


@protocol MPOAuthAPIAuthDelegate <NSObject>

@optional
- (NSString *)oauthVerifierForCompletedUserAuthorization;
- (NSDictionary *)additionalRequestTokenParameters;
- (NSURL *)callbackURLForCompletedUserAuthorization;
- (BOOL)automaticallyRequestAuthenticationFromURL:(NSURL *)inAuthURL withCallbackURL:(NSURL *)inCallbackURL;

- (void)authenticationDidSucceed;
- (void)authenticationDidFailWithError:(NSError *)error;

@end


@class MPOAuthAuthenticationMethod;

@interface MPOAuthAPI : NSObject <MPOAuthAPIRequestLoaderDelegate>

@property (nonatomic, readwrite, assign) id <MPOAuthAPIAuthDelegate> authDelegate;
@property (nonatomic, readwrite, assign) id <MPOAuthAPILoadDelegate> loadDelegate;
@property (nonatomic, readonly, strong) id <MPOAuthCredentialStore, MPOAuthParameterFactory> credentials;
@property (nonatomic, readwrite, copy) NSString *defaultHTTPMethod;
@property (nonatomic, readonly, strong) NSURL *baseURL;
@property (nonatomic, readonly, strong) NSURL *authenticationURL;
@property (nonatomic, readwrite, strong) MPOAuthAuthenticationMethod *authenticationMethod;
@property (nonatomic, readwrite, assign) MPOAuthSignatureScheme signatureScheme;

@property (nonatomic, readonly, assign) MPOAuthAuthenticationState authenticationState;

// Publicly useful methods
- (id)initWithCredentials:(NSDictionary *)inCredentials andBaseURL:(NSURL *)inURL;
- (id)initWithCredentials:(NSDictionary *)inCredentials authenticationURL:(NSURL *)inAuthURL andBaseURL:(NSURL *)inBaseURL;
- (id)initWithCredentials:(NSDictionary *)inCredentials authenticationURL:(NSURL *)inAuthURL andBaseURL:(NSURL *)inBaseURL autoStart:(BOOL)aFlag;
- (id)initWithCredentials:(NSDictionary *)inCredentials withConfiguration:(NSDictionary *)inConfiguration autoStart:(BOOL)aFlag;

- (void)authenticate;
- (BOOL)isAuthenticated;

- (void)performMethod:(NSString *)inMethod withDelegate:(id <MPOAuthAPILoadDelegate>)aDelegate;
- (void)performMethod:(NSString *)inMethod withParameters:(NSArray *)inParameters delegate:(id <MPOAuthAPILoadDelegate>)aDelegate;

- (void)performPOSTMethod:(NSString *)inMethod withDelegate:(id <MPOAuthAPILoadDelegate>)aDelegate;
- (void)performPOSTMethod:(NSString *)inMethod withParameters:(NSArray *)inParameters delegate:(id <MPOAuthAPILoadDelegate>)aDelegate;

- (void)performURLRequest:(NSURLRequest *)inRequest withDelegate:(id <MPOAuthAPILoadDelegate>)aDelegate;

- (NSData *)dataForMethod:(NSString *)inMethod;
- (NSData *)dataForMethod:(NSString *)inMethod withParameters:(NSArray *)inParameters;
- (NSData *)dataForURL:(NSURL *)inURL andMethod:(NSString *)inMethod withParameters:(NSArray *)inParameters;

- (id)credentialNamed:(NSString *)inCredentialName;
- (void)setCredential:(id)inCredential withName:(NSString *)inName;
- (void)removeCredentialNamed:(NSString *)inName;

- (void)discardCredentials;

// Mostly internally used methods
- (void)performMethod:(NSString *)inMethod atURL:(NSURL *)inURL withParameters:(NSArray *)inParameters withTarget:(id <MPOAuthAPIRequestLoaderDelegate>)inTarget;
- (void)performPOSTMethod:(NSString *)inMethod atURL:(NSURL *)inURL withParameters:(NSArray *)inParameters withTarget:(id <MPOAuthAPIRequestLoaderDelegate>)inTarget;
- (void)performURLRequest:(NSURLRequest *)inRequest withTarget:(id <MPOAuthAPIRequestLoaderDelegate>)inTarget;


@end
