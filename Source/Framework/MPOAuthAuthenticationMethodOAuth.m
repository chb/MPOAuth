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


@interface MPOAuthAPI ()

@property (nonatomic, readwrite, assign) MPOAuthAuthenticationState authenticationState;

@end


@interface MPOAuthAuthenticationMethodOAuth ()

@property (nonatomic, readwrite, assign) BOOL oauth10aModeActive;

- (void)_authenticationRequestForRequestToken;
- (void)_authenticationRequestForUserPermissionsConfirmationAtURL:(NSURL *)inURL;
- (void)_authenticationRequestForAccessToken;

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
	

}

@synthesize delegate = delegate_;
@synthesize oauthRequestTokenURL = oauthRequestTokenURL_;
@synthesize oauthAuthorizeTokenURL = oauthAuthorizeTokenURL_;
@synthesize oauth10aModeActive = oauth10aModeActive_;

#pragma mark -

- (void)authenticate {
	id <MPOAuthCredentialStore> credentials = [self.oauthAPI credentials];
	if (restartOnFail_) {
		MPLog(@"Restarting authentication after fail")
		didRestartOnFail_ = YES;
	}
	restartOnFail_ = NO;
	
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
		if (delegate_ && [delegate_ respondsToSelector: @selector(callbackURLForCompletedUserAuthorization)]) {
			callbackURL = [delegate_ callbackURLForCompletedUserAuthorization];
		}
		if (callbackURL) {
			callbackParameter = [[MPURLRequestParameter alloc] initWithName:@"oauth_callback" andValue:[callbackURL absoluteString]];
		} else {
			// oob = "Out of bounds"
			callbackParameter = [[MPURLRequestParameter alloc] initWithName:@"oauth_callback" andValue:@"oob"];
		}
		
		NSArray *params = [NSArray arrayWithObject:callbackParameter];
		
		// additional parameters?
		if (delegate_ && [delegate_ respondsToSelector: @selector(additionalRequestTokenParameters)]) {
			NSDictionary *additionalParams = [delegate_ additionalRequestTokenParameters];
			if ([additionalParams count] > 0) {
				NSMutableArray *mutParams = [params mutableCopy];
				for (NSString *key in [additionalParams allKeys]) {
					MPURLRequestParameter *param = [[MPURLRequestParameter alloc] initWithName:key andValue:[additionalParams objectForKey:key]];
					[mutParams addObject:param];
				}
				params = mutParams;
			}
		}
		
		// perform method
		[self.oauthAPI performMethod:nil atURL:self.oauthRequestTokenURL withParameters:params withTarget:self];
	}
	else if ([delegate_ respondsToSelector:@selector(authenticationDidFailWithError:)]) {
		NSDictionary *errDict = [NSDictionary dictionaryWithObjectsAndKeys:@"Can not authenticate without oauthRequestTokenURL", NSLocalizedDescriptionKey, nil];
		[delegate_ authenticationDidFailWithError:[NSError errorWithDomain:NSCocoaErrorDomain code:0 userInfo:errDict]];
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
			verifierParameter = [[MPURLRequestParameter alloc] initWithName:@"oauth_verifier" andValue:verifier];
			params = [NSArray arrayWithObject:verifierParameter];
		}
	}
	
	if (self.oauthGetAccessTokenURL) {
		MPLog(@"--> Performing Access Token Request: %@", self.oauthGetAccessTokenURL);
		[self.oauthAPI performMethod:nil atURL:self.oauthGetAccessTokenURL withParameters:params withTarget:self];
	}
}

#pragma mark -

- (void)loader:(MPOAuthAPIRequestLoader *)inLoader didReceiveData:(NSData *)inData {
	NSDictionary *oauthResponseParameters = inLoader.oauthResponse.oauthParameters;
	NSString *xoauthRequestAuthURL = [oauthResponseParameters objectForKey:@"xoauth_request_auth_url"]; // a common custom extension, used by Yahoo!
	NSURL *userAuthURL = xoauthRequestAuthURL ? [NSURL URLWithString:xoauthRequestAuthURL] : self.oauthAuthorizeTokenURL;
	NSURL *callbackURL = nil;
	
	if (!self.oauth10aModeActive) {
		callbackURL = [self.delegate respondsToSelector:@selector(callbackURLForCompletedUserAuthorization)] ? [self.delegate callbackURLForCompletedUserAuthorization] : nil;
	}
	
	NSString *token = [oauthResponseParameters objectForKey:@"oauth_token"];
	if (token) {
		
		// authentication finished
		if ([self.oauthAPI isAuthenticated]) {
			if ([delegate_ respondsToSelector:@selector(authenticationDidSucceed)]) {
				[delegate_ authenticationDidSucceed];
			}
		}
		else {
			NSDictionary *parameters = [NSDictionary dictionaryWithObjectsAndKeys:token, @"oauth_token", callbackURL, @"oauth_callback", nil];
			userAuthURL = [userAuthURL urlByAddingParameterDictionary:parameters];
			BOOL delegateWantsToBeInvolved = [self.delegate respondsToSelector:@selector(automaticallyRequestAuthenticationFromURL:withCallbackURL:)];
			
			if (!delegateWantsToBeInvolved || (delegateWantsToBeInvolved && [self.delegate automaticallyRequestAuthenticationFromURL:userAuthURL withCallbackURL:callbackURL])) {
				MPLog(@"--> Automatically Performing User Auth Request: %@", userAuthURL);
				[self _authenticationRequestForUserPermissionsConfirmationAtURL:userAuthURL];
			}
			else {
				MPLog(@"--> Not automatically performing User Auth Request, you should be doing this right now.");
			}
		}
	}
	else {
		NSUInteger status = [(NSHTTPURLResponse *)[inLoader.oauthResponse urlResponse] statusCode];
		NSDictionary *userInfo = [NSDictionary dictionaryWithObject:inLoader.responseString forKey:NSLocalizedDescriptionKey];
		NSError *error = [NSError errorWithDomain:NSCocoaErrorDomain code:status userInfo:userInfo];
		[self loader:inLoader didFailWithError:error];
	}
}

- (void)loader:(MPOAuthAPIRequestLoader *)inLoader didFailWithError:(NSError *)error {
	if (restartOnFail_) {
//	if (restartOnFail_ && !didRestartOnFail_) {
		[self authenticate];
	}
	else if ([delegate_ respondsToSelector:@selector(authenticationDidFailWithError:)]) {
		[delegate_ authenticationDidFailWithError:error];
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
	restartOnFail_ = YES;
	
	[self.oauthAPI removeCredentialNamed:kMPOAuthCredentialRequestToken];
	[self.oauthAPI removeCredentialNamed:kMPOAuthCredentialRequestTokenSecret];
}

- (void)_accessTokenReceived:(NSNotification *)inNotification {
	[self.oauthAPI removeCredentialNamed:kMPOAuthCredentialRequestToken];
	[self.oauthAPI removeCredentialNamed:kMPOAuthCredentialRequestTokenSecret];
	
	[self.oauthAPI setCredential:[[inNotification userInfo] objectForKey:@"oauth_token"] withName:kMPOAuthCredentialAccessToken];
	[self.oauthAPI setCredential:[[inNotification userInfo] objectForKey:@"oauth_token_secret"] withName:kMPOAuthCredentialAccessTokenSecret];
	
	if ([[inNotification userInfo] objectForKey:@"oauth_session_handle"]) {
		[self.oauthAPI setCredential:[[inNotification userInfo] objectForKey:@"oauth_session_handle"] withName:kMPOAuthCredentialSessionHandle];
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
