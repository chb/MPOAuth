//
//  MPOAuthAPI.m
//  MPOAuthConnection
//
//  Created by Karl Adam on 08.12.05.
//  Copyright 2008 matrixPointer. All rights reserved.
//

#import "MPOAuthAPIRequestLoader.h"
#import "MPOAuthAPI.h"
#import "MPOAuthCredentialConcreteStore.h"
#import "MPOAuthURLRequest.h"
#import "MPOAuthURLResponse.h"
#import "MPURLRequestParameter.h"
#import "MPOAuthAuthenticationMethod.h"

#import "NSURL+MPURLParameterAdditions.h"

NSString *kMPOAuthCredentialConsumerKey				= @"kMPOAuthCredentialConsumerKey";
NSString *kMPOAuthCredentialConsumerSecret			= @"kMPOAuthCredentialConsumerSecret";
NSString *kMPOAuthCredentialUsername				= @"kMPOAuthCredentialUsername";
NSString *kMPOAuthCredentialPassword				= @"kMPOAuthCredentialPassword";
NSString *kMPOAuthCredentialRequestToken			= @"kMPOAuthCredentialRequestToken";
NSString *kMPOAuthCredentialRequestTokenSecret		= @"kMPOAuthCredentialRequestTokenSecret";
NSString *kMPOAuthCredentialAccessToken				= @"kMPOAuthCredentialAccessToken";
NSString *kMPOAuthCredentialAccessTokenSecret		= @"kMPOAuthCredentialAccessTokenSecret";
NSString *kMPOAuthCredentialSessionHandle			= @"kMPOAuthCredentialSessionHandle";

NSString *kMPOAuthSignatureMethod					= @"kMPOAuthSignatureMethod";
NSString * const MPOAuthTokenRefreshDateDefaultsKey	= @"MPOAuthAutomaticTokenRefreshLastExpiryDate";

NSString * const MPOAuthBaseURLKey					= @"MPOAuthBaseURL";
NSString * const MPOAuthAuthenticationURLKey		= @"MPOAuthAuthenticationURL";
NSString * const MPOAuthAuthenticationMethodKey		= @"MPOAuthAuthenticationMethod";

@interface MPOAuthAPI ()
@property (nonatomic, readwrite, retain) id <MPOAuthCredentialStore, MPOAuthParameterFactory> credentials;
@property (nonatomic, readwrite, retain) NSURL *authenticationURL;
@property (nonatomic, readwrite, retain) NSURL *baseURL;
@property (nonatomic, readwrite, retain) NSMutableArray *activeLoaders;
@property (nonatomic, readwrite, assign) MPOAuthAuthenticationState authenticationState;

- (void)performMethod:(NSString *)inMethod atURL:(NSURL *)inURL withParameters:(NSArray *)inParameters withTarget:(id)inTarget andAction:(SEL)inAction usingHTTPMethod:(NSString *)inHTTPMethod;
@end

@implementation MPOAuthAPI

- (id)initWithCredentials:(NSDictionary *)inCredentials andBaseURL:(NSURL *)inBaseURL {
	return [self initWithCredentials:inCredentials authenticationURL:inBaseURL andBaseURL:inBaseURL autoStart:YES];
}

- (id)initWithCredentials:(NSDictionary *)inCredentials authenticationURL:(NSURL *)inAuthURL andBaseURL:(NSURL *)inBaseURL {
	return [self initWithCredentials:inCredentials authenticationURL:inBaseURL andBaseURL:inBaseURL autoStart:YES];	
}

- (id)initWithCredentials:(NSDictionary *)inCredentials authenticationURL:(NSURL *)inAuthURL andBaseURL:(NSURL *)inBaseURL autoStart:(BOOL)aFlag {
	if ((self = [super init])) {
		self.defaultHTTPMethod = @"GET";
		self.authenticationURL = inAuthURL;
		self.baseURL = inBaseURL;
		self.authenticationState = MPOAuthAuthenticationStateUnauthenticated;
		credentials_ = [[MPOAuthCredentialConcreteStore alloc] initWithCredentials:inCredentials forBaseURL:inBaseURL withAuthenticationURL:inAuthURL];
		self.authenticationMethod = [[[MPOAuthAuthenticationMethod alloc] initWithAPI:self forURL:inAuthURL] autorelease];
		self.signatureScheme = MPOAuthSignatureSchemeHMACSHA1;

		activeLoaders_ = [[NSMutableArray alloc] initWithCapacity:10];
		
		if (aFlag) {
			[self authenticate];
		}
	}
	return self;	
}

- (id)initWithCredentials:(NSDictionary *)inCredentials withConfiguration:(NSDictionary *)inConfiguration autoStart:(BOOL)aFlag {
	if ((self = [super init])) {
		self.defaultHTTPMethod = @"GET";
		self.authenticationURL = [inConfiguration valueForKey:MPOAuthAuthenticationURLKey];
		self.baseURL = [inConfiguration valueForKey:MPOAuthBaseURLKey];
		self.authenticationState = MPOAuthAuthenticationStateUnauthenticated;
		credentials_ = [[MPOAuthCredentialConcreteStore alloc] initWithCredentials:inCredentials forBaseURL:self.baseURL withAuthenticationURL:self.authenticationURL];
		NSString *authMethod = [inConfiguration objectForKey:MPOAuthAuthenticationMethodKey];
		self.authenticationMethod = [[[MPOAuthAuthenticationMethod alloc] initWithAPI:self forURL:self.authenticationURL withConfiguration:inConfiguration preferredMethod:authMethod] autorelease];
		self.signatureScheme = MPOAuthSignatureSchemeHMACSHA1;
		
		activeLoaders_ = [[NSMutableArray alloc] initWithCapacity:10];
		
		if (aFlag) {
			[self authenticate];
		}
	}
	return self;	
}

- (oneway void)dealloc {
	self.credentials = nil;
	self.defaultHTTPMethod = nil;
	self.baseURL = nil;
	self.authenticationURL = nil;
	self.authenticationMethod = nil;
	self.activeLoaders = nil;
	
	[super dealloc];
}

@synthesize authDelegate = _authDelegate;
@synthesize loadDelegate = _loadDelegate;
@synthesize credentials = credentials_;
@synthesize defaultHTTPMethod = defaultHttpMethod_;
@synthesize baseURL = baseURL_;
@synthesize authenticationURL = authenticationURL_;
@synthesize authenticationMethod = authenticationMethod_;
@synthesize signatureScheme = signatureScheme_;
@synthesize activeLoaders = activeLoaders_;
@synthesize authenticationState = oauthAuthenticationState_;

#pragma mark - KVC Overrides

- (void)setSignatureScheme:(MPOAuthSignatureScheme)inScheme {
	signatureScheme_ = inScheme;
	
	NSString *methodString = @"HMAC-SHA1";
	
	switch (signatureScheme_) {
		case MPOAuthSignatureSchemePlainText:
			methodString = @"PLAINTEXT";
			break;
		case MPOAuthSignatureSchemeRSASHA1:
			methodString = @"RSA-SHA1";
		case MPOAuthSignatureSchemeHMACSHA1:
		default:
			// already initted to the default
			break;
	}
	
	[(MPOAuthCredentialConcreteStore *)credentials_ setSignatureMethod:methodString];
}

- (void)setAuthenticationMethod:(MPOAuthAuthenticationMethod *)newMethod {
	if (newMethod != authenticationMethod_) {
		//if ([authenticationMethod_ respondsToSelector:@selector(setDelegate:)]) {
		//	[authenticationMethod_ performSelector:@selector(setDelegate:) withObject:nil];
		//}
		
		[authenticationMethod_ release];
		authenticationMethod_ = [newMethod retain];
		
		if ([authenticationMethod_ respondsToSelector:@selector(setDelegate:)]) {
			[authenticationMethod_ performSelector:@selector(setDelegate:) withObject:self];
		}
	}
}

#pragma mark - Authentication

- (void)authenticate {
	NSAssert(credentials_.consumerKey, @"A Consumer Key is required for use of OAuth.");
	[self.authenticationMethod authenticate];
}

- (BOOL)isAuthenticated {
	if (MPOAuthAuthenticationStateUnauthenticated == self.authenticationState) {
		if (credentials_.accessToken && credentials_.accessTokenSecret) {
			[self setAuthenticationState:MPOAuthAuthenticationStateAuthenticated];
		}
	}
	return (self.authenticationState == MPOAuthAuthenticationStateAuthenticated);
}

#pragma mark - Asynchronous Loading

- (void)performMethod:(NSString *)inMethod withDelegate:(id <MPOAuthAPILoadDelegate>)aDelegate {
	self.loadDelegate = aDelegate;
	[self performMethod:inMethod atURL:self.baseURL withParameters:nil withTarget:self andAction:nil usingHTTPMethod:defaultHttpMethod_];
}

- (void)performMethod:(NSString *)inMethod withParameters:(NSArray *)inParameters delegate:(id <MPOAuthAPILoadDelegate>)aDelegate {
	self.loadDelegate = aDelegate;
	[self performMethod:inMethod atURL:self.baseURL withParameters:inParameters withTarget:self andAction:nil usingHTTPMethod:defaultHttpMethod_];
}

- (void)performMethod:(NSString *)inMethod withTarget:(id)inTarget andAction:(SEL)inAction {
	[self performMethod:inMethod atURL:self.baseURL withParameters:nil withTarget:inTarget andAction:inAction usingHTTPMethod:defaultHttpMethod_];
}

- (void)performMethod:(NSString *)inMethod withParameters:(NSArray *)inParameters withTarget:(id)inTarget andAction:(SEL)inAction {
	[self performMethod:inMethod atURL:self.baseURL withParameters:inParameters withTarget:inTarget andAction:inAction usingHTTPMethod:defaultHttpMethod_];
}

- (void)performMethod:(NSString *)inMethod atURL:(NSURL *)inURL withParameters:(NSArray *)inParameters withTarget:(id)inTarget andAction:(SEL)inAction {
	[self performMethod:inMethod atURL:inURL withParameters:inParameters withTarget:inTarget andAction:inAction usingHTTPMethod:defaultHttpMethod_];
}


- (void)performPOSTMethod:(NSString *)inMethod withDelegate:(id <MPOAuthAPILoadDelegate>)aDelegate {
	self.loadDelegate = aDelegate;
	[self performMethod:inMethod atURL:self.baseURL withParameters:nil withTarget:self andAction:nil usingHTTPMethod:@"POST"];
}

- (void)performPOSTMethod:(NSString *)inMethod withParameters:(NSArray *)inParameters delegate:(id <MPOAuthAPILoadDelegate>)aDelegate {
	self.loadDelegate = aDelegate;
	[self performMethod:inMethod atURL:self.baseURL withParameters:inParameters withTarget:self andAction:nil usingHTTPMethod:@"POST"];
}

- (void)performPOSTMethod:(NSString *)inMethod withParameters:(NSArray *)inParameters withTarget:(id)inTarget andAction:(SEL)inAction {
	[self performPOSTMethod:inMethod atURL:self.baseURL withParameters:inParameters withTarget:inTarget andAction:inAction];
}

- (void)performPOSTMethod:(NSString *)inMethod atURL:(NSURL *)inURL withParameters:(NSArray *)inParameters withTarget:(id)inTarget andAction:(SEL)inAction {
	[self performMethod:inMethod atURL:inURL withParameters:inParameters withTarget:inTarget andAction:inAction usingHTTPMethod:@"POST"];
}

- (void)performMethod:(NSString *)inMethod atURL:(NSURL *)inURL withParameters:(NSArray *)inParameters withTarget:(id)inTarget andAction:(SEL)inAction usingHTTPMethod:(NSString *)inHTTPMethod {
	if (!inMethod && ![inURL path] && ![inURL query]) {
		[NSException raise:@"MPOAuthNilMethodRequestException" format:@"Nil was passed as the method to be performed on %@", inURL];
	}
	
	NSURL *requestURL = inMethod ? [NSURL URLWithString:inMethod relativeToURL:inURL] : inURL;
	MPOAuthURLRequest *aRequest = [[MPOAuthURLRequest alloc] initWithURL:requestURL andParameters:inParameters];
	MPOAuthAPIRequestLoader *loader = [[MPOAuthAPIRequestLoader alloc] initWithRequest:aRequest];
	
	aRequest.HTTPMethod = inHTTPMethod;
	loader.api = self;
	loader.credentials = self.credentials;
	loader.target = inTarget;
	loader.action = inAction ? inAction : @selector(_performedLoad:receivingData:);
	
	[loader loadSynchronously:NO];
	//	[self.activeLoaders addObject:loader];
	
	[loader release];
	[aRequest release];
}

- (void)performURLRequest:(NSURLRequest *)inRequest withDelegate:(id <MPOAuthAPILoadDelegate>)aDelegate {
	self.loadDelegate = aDelegate;
	[self performURLRequest:inRequest withTarget:self andAction:nil];
}

- (void)performURLRequest:(NSURLRequest *)inRequest withTarget:(id)inTarget andAction:(SEL)inAction {
	if (!inRequest && ![[inRequest URL] path] && ![[inRequest URL] query]) {
		[NSException raise:@"MPOAuthNilMethodRequestException" format:@"Nil was passed as the method to be performed on %@", inRequest];
	}

	MPOAuthURLRequest *aRequest = [[MPOAuthURLRequest alloc] initWithURLRequest:inRequest];
	MPOAuthAPIRequestLoader *loader = [[MPOAuthAPIRequestLoader alloc] initWithRequest:aRequest];
	
	loader.api = self;
	loader.credentials = self.credentials;
	loader.target = inTarget;
	loader.action = inAction ? inAction : @selector(_performedLoad:receivingData:);
	
	[loader loadSynchronously:NO];
	//	[self.activeLoaders addObject:loader];
	
	[loader release];
	[aRequest release];	
}

#pragma mark - Synchronous Loading

- (NSData *)dataForMethod:(NSString *)inMethod {
	return [self dataForURL:self.baseURL andMethod:inMethod withParameters:nil];
}

- (NSData *)dataForMethod:(NSString *)inMethod withParameters:(NSArray *)inParameters {
	return [self dataForURL:self.baseURL andMethod:inMethod withParameters:inParameters];
}

- (NSData *)dataForURL:(NSURL *)inURL andMethod:(NSString *)inMethod withParameters:(NSArray *)inParameters {
	NSURL *requestURL = [NSURL URLWithString:inMethod relativeToURL:inURL];
	MPOAuthURLRequest *aRequest = [[MPOAuthURLRequest alloc] initWithURL:requestURL andParameters:inParameters];
	MPOAuthAPIRequestLoader *loader = [[MPOAuthAPIRequestLoader alloc] initWithRequest:aRequest];
	
	loader.api = self;
	loader.credentials = self.credentials;
	[loader loadSynchronously:YES];
	
	[loader autorelease];
	[aRequest release];
	
	return loader.data;
}

#pragma mark - Authentication Responses

- (NSURL *)callbackURLForCompletedUserAuthorization {
	if ([_authDelegate respondsToSelector:@selector(callbackURLForCompletedUserAuthorization)]) {
		return [_authDelegate callbackURLForCompletedUserAuthorization];
	}
	return nil;
}

- (BOOL)automaticallyRequestAuthenticationFromURL:(NSURL *)inAuthURL withCallbackURL:(NSURL *)inCallbackURL {
	if ([_authDelegate respondsToSelector:@selector(automaticallyRequestAuthenticationFromURL:withCallbackURL:)]) {
		return [_authDelegate automaticallyRequestAuthenticationFromURL:inAuthURL withCallbackURL:inCallbackURL];
	}
	return NO;
}

- (NSString *)oauthVerifierForCompletedUserAuthorization {
	if ([_authDelegate respondsToSelector:@selector(oauthVerifierForCompletedUserAuthorization)]) {
		return [_authDelegate oauthVerifierForCompletedUserAuthorization];
	}
	return nil;
}


- (void)authenticationDidSucceed {
	if ([_authDelegate respondsToSelector:@selector(authenticationDidSucceed)]) {
		[_authDelegate authenticationDidSucceed];
	}
}

- (void)authenticationDidFailWithError:(NSError *)error {
	if ([_authDelegate respondsToSelector:@selector(authenticationDidFailWithError:)]) {
		[_authDelegate authenticationDidFailWithError:error];
	}
}

#pragma mark - Standard Load Responses

- (void)_performedLoad:(MPOAuthAPIRequestLoader *)inLoader receivingData:(NSData *)inData {
	if (_loadDelegate) {
		NSURLResponse *urlResponse = [[[inLoader.oauthResponse urlResponse] retain] autorelease];
		NSInteger status = [(NSHTTPURLResponse *)urlResponse statusCode];
		if (200 == status) {
			[_loadDelegate connectionFinishedWithResponse:urlResponse data:inData];
		}
		else {
			NSString *errorMessage = inLoader.responseString ? inLoader.responseString : [NSString stringWithFormat:@"%d", status];
			NSDictionary *userInfo = [NSDictionary dictionaryWithObject:errorMessage forKey:NSLocalizedDescriptionKey];
			NSError *error = [NSError errorWithDomain:NSCocoaErrorDomain code:status userInfo:userInfo];
			[_loadDelegate connectionFailedWithResponse:urlResponse error:error];
		}
	}
}

- (void)loader:(MPOAuthAPIRequestLoader *)inLoader didFailWithError:(NSError *)error {
	if (_loadDelegate) {
		NSURLResponse *urlResponse = [[[inLoader.oauthResponse urlResponse] retain] autorelease];
		[_loadDelegate connectionFailedWithResponse:urlResponse error:error];
	}
}

#pragma mark - Credential Handling

- (id)credentialNamed:(NSString *)inCredentialName {
	return [self.credentials credentialNamed:inCredentialName];
}

- (void)setCredential:(id)inCredential withName:(NSString *)inName {
	[(MPOAuthCredentialConcreteStore *)self.credentials setCredential:inCredential withName:inName];
}

- (void)removeCredentialNamed:(NSString *)inName {
	[(MPOAuthCredentialConcreteStore *)self.credentials removeCredentialNamed:inName];
}

- (void)discardCredentials {
	[self.credentials discardOAuthCredentials];
	
	self.authenticationState = MPOAuthAuthenticationStateUnauthenticated;
}

@end
