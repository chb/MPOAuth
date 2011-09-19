//
//  MPOAuthAuthenticationMethodAuthExchange.m
//  MPOAuthMobile
//
//  Created by Pascal Pfiffner on 09/16/2011.
//  Copyright 2011 Children's Hospital Boston. All rights reserved.
//

#import "MPOAuthAuthenticationMethodTwoLegged.h"
#import "MPOAuthAPI.h"
#import "MPOAuthAPIRequestLoader.h"
#import "MPOAuthCredentialStore.h"
#import "MPURLRequestParameter.h"

@interface MPOAuthAPI ()
@property (nonatomic, readwrite, assign) MPOAuthAuthenticationState authenticationState;
@end

@implementation MPOAuthAuthenticationMethodTwoLegged

- (id)initWithAPI:(MPOAuthAPI *)inAPI forURL:(NSURL *)inURL withConfiguration:(NSDictionary *)inConfig
{
	if ((self = [super initWithAPI:inAPI forURL:inURL withConfiguration:inConfig])) {
		self.oauthGetAccessTokenURL = [NSURL URLWithString:[inConfig objectForKey:MPOAuthAccessTokenURLKey]];
	}
	return self;
}

@synthesize delegate = delegate_;


- (void)authenticate
{
	id <MPOAuthCredentialStore> credentials = [self.oauthAPI credentials];
	
	// no access token, get a new one
	if (!credentials.accessToken || !credentials.accessTokenSecret) {
		MPLog(@"--> Performing Access Token Request: %@", self.oauthGetAccessTokenURL);
		NSString *username = [[self.oauthAPI credentials] username];
		NSString *password = [[self.oauthAPI credentials] password];
		NSAssert(username, @"AuthTwoLegged requires a Username credential");
		NSAssert(password, @"AuthTwoLegged requires a Password credential");
		
		MPURLRequestParameter *usernameParameter = [[MPURLRequestParameter alloc] initWithName:@"username" andValue:username];
		MPURLRequestParameter *passwordParameter = [[MPURLRequestParameter alloc] initWithName:@"password" andValue:password];
		
		[self.oauthAPI performPOSTMethod:nil
								   atURL:self.oauthGetAccessTokenURL
						  withParameters:[NSArray arrayWithObjects:usernameParameter, passwordParameter, nil]
							  withTarget:self
							   andAction:nil];
		
		[usernameParameter release];
		[passwordParameter release];
		return;
	}
	
	// we already have an access token
	[self.oauthAPI removeCredentialNamed:kMPOAuthCredentialPassword];
	[self.oauthAPI setAuthenticationState:MPOAuthAuthenticationStateAuthenticated];
	
	NSDictionary *params = [NSDictionary dictionaryWithObjectsAndKeys:
							credentials.accessToken, @"oauth_token",
							credentials.accessTokenSecret, @"oauth_token_secret",
							nil];
	[[NSNotificationCenter defaultCenter] postNotificationName:MPOAuthNotificationOAuthCredentialsReady
														object:nil
													  userInfo:params];
}

- (void)_performedLoad:(MPOAuthAPIRequestLoader *)inLoader receivingData:(NSData *)inData
{
	NSString *accessToken = nil;
	NSString *accessTokenSecret = nil;
	
	// did we get a token?
	NSDictionary *params = [MPURLRequestParameter parameterDictionaryFromString:inLoader.responseString];
	accessToken = [params objectForKey:@"oauth_token"];
	accessTokenSecret = [params objectForKey:@"oauth_token_secret"];
	
	// inform delegate
	if ([delegate_ respondsToSelector:@selector(authenticationDidReturnParameter:)]) {
		[delegate_ performSelector:@selector(authenticationDidReturnParameter:) withObject:params];
	}
	
	// yes, we got tokens!
	if (accessToken && accessTokenSecret) {
		[self.oauthAPI removeCredentialNamed:kMPOAuthCredentialPassword];
		[self.oauthAPI setCredential:accessToken withName:kMPOAuthCredentialAccessToken];
		[self.oauthAPI setCredential:accessTokenSecret withName:kMPOAuthCredentialAccessTokenSecret];
		
		[self.oauthAPI setAuthenticationState:MPOAuthAuthenticationStateAuthenticated];
		
		[[NSNotificationCenter defaultCenter] postNotificationName:MPOAuthNotificationOAuthCredentialsReady
															object:nil
														  userInfo:params];
	}
	
	// nope, we failed
	else {
		[[NSNotificationCenter defaultCenter] postNotificationName:MPOAuthNotificationErrorHasOccurred
															object:nil
														  userInfo:[NSDictionary dictionaryWithObject:inLoader.responseString forKey:NSLocalizedDescriptionKey]];
	}
}

- (void)loader:(MPOAuthAPIRequestLoader *)inLoader didFailWithError:(NSError *)inError {
	if ([delegate_ respondsToSelector:@selector(authenticationDidFailWithError:)]) {
		[delegate_ authenticationDidFailWithError:inError];
	}
}


@end
