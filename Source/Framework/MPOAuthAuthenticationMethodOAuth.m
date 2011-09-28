//
//  MPOAuthAuthenticationMethodOAuth.m
//  MPOAuthConnection
//
//  Created by Karl Adam on 09.12.19.
//  Copyright 2009 matrixPointer. All rights reserved.
//

#import "MPOAuthAuthenticationMethodOAuth.h"
#import "MPOAuthAPI.h"
#import "MPOAuthAPIRequestLoader.h"
#import "MPOAuthURLResponse.h"
#import "MPOAuthCredentialStore.h"
#import "MPOAuthCredentialConcreteStore.h"
#import "MPURLRequestParameter.h"

#import "NSURL+MPURLParameterAdditions.h"

NSString * const MPOAuthRequestTokenURLKey					= @"MPOAuthRequestTokenURL";
NSString * const MPOAuthUserAuthorizationURLKey				= @"MPOAuthUserAuthorizationURL";
NSString * const MPOAuthUserAuthorizationMobileURLKey		= @"MPOAuthUserAuthorizationMobileURL";

NSString * const MPOAuthCredentialRequestTokenKey			= @"oauth_token_request";
NSString * const MPOAuthCredentialRequestTokenSecretKey		= @"oauth_token_request_secret";
NSString * const MPOAuthCredentialAccessTokenKey			= @"oauth_token_access";
NSString * const MPOAuthCredentialAccessTokenSecretKey		= @"oauth_token_access_secret";
NSString * const MPOAuthCredentialSessionHandleKey			= @"oauth_session_handle";
NSString * const MPOAuthCredentialVerifierKey				= @"oauth_verifier";

@interface MPOAuthAPI ()
@property (nonatomic, readwrite, assign) MPOAuthAuthenticationState authenticationState;
@end


@interface MPOAuthAuthenticationMethodOAuth ()
@property (nonatomic, readwrite, assign) BOOL oauth10aModeActive;

- (void)_authenticationRequestForRequestToken;
- (void)_authenticationRequestForUserPermissionsConfirmationAtURL:(NSURL *)inURL;
- (void)_authenticationRequestForAccessToken;
- (void)loader:(MPOAuthAPIRequestLoader *)inLoader didFailWithError:(NSError *)error;

@end

@implementation MPOAuthAuthenticationMethodOAuth

- (id)initWithAPI:(MPOAuthAPI *)inAPI forURL:(NSURL *)inURL withConfiguration:(NSDictionary *)inConfig {
	if ((self = [super initWithAPI:inAPI forURL:inURL withConfiguration:inConfig])) {
		
		NSAssert( [inConfig count] >= 3, @"Incorrect number of oauth authorization methods");
		self.oauthRequestTokenURL = [NSURL URLWithString:[inConfig objectForKey:MPOAuthRequestTokenURLKey]];
		self.oauthAuthorizeTokenURL = [NSURL URLWithString:[inConfig objectForKey:MPOAuthUserAuthorizationURLKey]];
		self.oauthGetAccessTokenURL = [NSURL URLWithString:[inConfig objectForKey:MPOAuthAccessTokenURLKey]];		
		
		[[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(_requestTokenReceived:) name:MPOAuthNotificationRequestTokenReceived object:nil];
		[[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(_requestTokenRejected:) name:MPOAuthNotificationRequestTokenRejected object:nil];
		[[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(_accessTokenReceived:) name:MPOAuthNotificationAccessTokenReceived object:nil];		
	}
	return self;
}

- (oneway void)dealloc {
	[[NSNotificationCenter defaultCenter] removeObserver:self];
	
	self.oauthRequestTokenURL = nil;
	self.oauthAuthorizeTokenURL = nil;

	[super dealloc];
}

@synthesize delegate = delegate_;
@synthesize oauthRequestTokenURL = oauthRequestTokenURL_;
@synthesize oauthAuthorizeTokenURL = oauthAuthorizeTokenURL_;
@synthesize oauth10aModeActive = oauth10aModeActive_;

#pragma mark -

- (void)authenticate {
	id <MPOAuthCredentialStore> credentials = [self.oauthAPI credentials];
	
	if (!credentials.accessToken && !credentials.requestToken) {
		[self _authenticationRequestForRequestToken];
	} else if (!credentials.accessToken) {
		[self _authenticationRequestForAccessToken];
	} else if (credentials.accessToken && [[NSUserDefaults standardUserDefaults] objectForKey:MPOAuthTokenRefreshDateDefaultsKey]) {
		NSTimeInterval expiryDateInterval = [[NSUserDefaults standardUserDefaults] doubleForKey:MPOAuthTokenRefreshDateDefaultsKey];
		NSDate *tokenExpiryDate = [NSDate dateWithTimeIntervalSinceReferenceDate:expiryDateInterval];
			
		if ([tokenExpiryDate compare:[NSDate date]] == NSOrderedAscending) {
			[self refreshAccessToken];
		}
	}	
}

- (void)_authenticationRequestForRequestToken {
	if (self.oauthRequestTokenURL) {
		MPLog(@"--> Performing Request Token Request: %@", self.oauthRequestTokenURL);
		
		// Append the oauth_callbackUrl parameter for requesting the request token
		NSURL *callbackURL = nil;
		MPURLRequestParameter *callbackParameter = nil;
		if (self.delegate && [self.delegate respondsToSelector: @selector(callbackURLForCompletedUserAuthorization)]) {
			callbackURL = [self.delegate callbackURLForCompletedUserAuthorization];
		}
		if (callbackURL) {
			callbackParameter = [[[MPURLRequestParameter alloc] initWithName:@"oauth_callback" andValue:[callbackURL absoluteString]] autorelease];
		} else {
			// oob = "Out of bounds"
			callbackParameter = [[[MPURLRequestParameter alloc] initWithName:@"oauth_callback" andValue:@"oob"] autorelease];
		}
		
		NSArray *params = [NSArray arrayWithObject:callbackParameter];
		[self.oauthAPI performMethod:nil atURL:self.oauthRequestTokenURL withParameters:params withTarget:self andAction:nil];
	}
	else if ([delegate_ respondsToSelector:@selector(authenticationDidFailWithError:)]) {
		NSDictionary *errDict = [NSDictionary dictionaryWithObjectsAndKeys:@"Can not authenticate without oauthRequestTokenURL", NSLocalizedDescriptionKey, nil];
		[delegate_ authenticationDidFailWithError:[NSError errorWithDomain:NSCocoaErrorDomain code:0 userInfo:errDict]];
	}
}

- (void)_performedLoad:(MPOAuthAPIRequestLoader *)inLoader receivingData:(NSData *)inData {
	NSDictionary *oauthResponseParameters = inLoader.oauthResponse.oauthParameters;
	NSString *xoauthRequestAuthURL = [oauthResponseParameters objectForKey:@"xoauth_request_auth_url"]; // a common custom extension, used by Yahoo!
	NSURL *userAuthURL = xoauthRequestAuthURL ? [NSURL URLWithString:xoauthRequestAuthURL] : self.oauthAuthorizeTokenURL;
	NSURL *callbackURL = nil;
	
	if (!self.oauth10aModeActive) {
		callbackURL = [self.delegate respondsToSelector:@selector(callbackURLForCompletedUserAuthorization)] ? [self.delegate callbackURLForCompletedUserAuthorization] : nil;
	}
	
	NSString *token = [oauthResponseParameters objectForKey:@"oauth_token"];
	if (token) {
		NSDictionary *parameters = [NSDictionary dictionaryWithObjectsAndKeys:token, @"oauth_token", callbackURL, @"oauth_callback", nil];
		userAuthURL = [userAuthURL urlByAddingParameterDictionary:parameters];
		BOOL delegateWantsToBeInvolved = [self.delegate respondsToSelector:@selector(automaticallyRequestAuthenticationFromURL:withCallbackURL:)];
		
		if (!delegateWantsToBeInvolved || (delegateWantsToBeInvolved && [self.delegate automaticallyRequestAuthenticationFromURL:userAuthURL withCallbackURL:callbackURL])) {
			MPLog(@"--> Automatically Performing User Auth Request: %@", userAuthURL);
			[self _authenticationRequestForUserPermissionsConfirmationAtURL:userAuthURL];
		}
		else {
			NSDictionary *userInfo = [NSDictionary dictionaryWithObject:@"User did not authenticate" forKey:NSLocalizedDescriptionKey];
			NSError *error = [NSError errorWithDomain:NSCocoaErrorDomain code:200 userInfo:userInfo];
			[self loader:inLoader didFailWithError:error];
		}
	}
	else {
		NSDictionary *userInfo = [NSDictionary dictionaryWithObject:inLoader.responseString forKey:NSLocalizedDescriptionKey];
		NSUInteger status = [(NSHTTPURLResponse *)[inLoader.oauthResponse urlResponse] statusCode];
		NSError *error = [NSError errorWithDomain:NSCocoaErrorDomain code:status userInfo:userInfo];
		[self loader:inLoader didFailWithError:error];
	}
}

- (void)loader:(MPOAuthAPIRequestLoader *)inLoader didFailWithError:(NSError *)error {
	if ([delegate_ respondsToSelector:@selector(authenticationDidFailWithError:)]) {
		[delegate_ authenticationDidFailWithError:error];
	}
}

- (void)_authenticationRequestForUserPermissionsConfirmationAtURL:(NSURL *)userAuthURL {
#if TARGET_OS_IPHONE || TARGET_IPHONE_SIMULATOR
	[[UIApplication sharedApplication] openURL:userAuthURL];
#else
	[[NSWorkspace sharedWorkspace] openURL:userAuthURL];
#endif
}

- (void)_authenticationRequestForAccessToken {
	NSArray *params = nil;
	
	if (self.delegate && [self.delegate respondsToSelector: @selector(oauthVerifierForCompletedUserAuthorization)]) {
		MPURLRequestParameter *verifierParameter = nil;

		NSString *verifier = [self.delegate oauthVerifierForCompletedUserAuthorization];
		if (verifier) {
			verifierParameter = [[[MPURLRequestParameter alloc] initWithName:@"oauth_verifier" andValue:verifier] autorelease];
			params = [NSArray arrayWithObject:verifierParameter];
		}
	}
	
	if (self.oauthGetAccessTokenURL) {
		MPLog(@"--> Performing Access Token Request: %@", self.oauthGetAccessTokenURL);
		[self.oauthAPI performMethod:nil atURL:self.oauthGetAccessTokenURL withParameters:params withTarget:self andAction:nil];
	}
}

#pragma mark -

- (void)_requestTokenReceived:(NSNotification *)inNotification {
	if ([[inNotification userInfo] objectForKey:@"oauth_callback_confirmed"]) {
		self.oauth10aModeActive = YES;
	}
	
	[self.oauthAPI setCredential:[[inNotification userInfo] objectForKey:@"oauth_token"] withName:kMPOAuthCredentialRequestToken];
	[self.oauthAPI setCredential:[[inNotification userInfo] objectForKey:@"oauth_token_secret"] withName:kMPOAuthCredentialRequestTokenSecret];
}

- (void)_requestTokenRejected:(NSNotification *)inNotification {
	[self.oauthAPI removeCredentialNamed:MPOAuthCredentialRequestTokenKey];
	[self.oauthAPI removeCredentialNamed:MPOAuthCredentialRequestTokenSecretKey];
}

- (void)_accessTokenReceived:(NSNotification *)inNotification {
	[self.oauthAPI removeCredentialNamed:MPOAuthCredentialRequestTokenKey];
	[self.oauthAPI removeCredentialNamed:MPOAuthCredentialRequestTokenSecretKey];
	
	[self.oauthAPI setCredential:[[inNotification userInfo] objectForKey:@"oauth_token"] withName:kMPOAuthCredentialAccessToken];
	[self.oauthAPI setCredential:[[inNotification userInfo] objectForKey:@"oauth_token_secret"] withName:kMPOAuthCredentialAccessTokenSecret];
	
	if ([[inNotification userInfo] objectForKey:MPOAuthCredentialSessionHandleKey]) {
		[self.oauthAPI setCredential:[[inNotification userInfo] objectForKey:MPOAuthCredentialSessionHandleKey] withName:kMPOAuthCredentialSessionHandle];
	}

	[self.oauthAPI setAuthenticationState:MPOAuthAuthenticationStateAuthenticated];
	
	if ([[inNotification userInfo] objectForKey:@"oauth_expires_in"]) {
		NSTimeInterval tokenRefreshInterval = (NSTimeInterval)[[[inNotification userInfo] objectForKey:@"oauth_expires_in"] intValue];
		NSDate *tokenExpiryDate = [NSDate dateWithTimeIntervalSinceNow:tokenRefreshInterval];
		[[NSUserDefaults standardUserDefaults] setDouble:[tokenExpiryDate timeIntervalSinceReferenceDate] forKey:MPOAuthTokenRefreshDateDefaultsKey];
	
		if (tokenRefreshInterval > 0.0) {
			[self setTokenRefreshInterval:tokenRefreshInterval];
		}
	} else {
		[[NSUserDefaults standardUserDefaults] removeObjectForKey:MPOAuthTokenRefreshDateDefaultsKey];
	}
}


@end
