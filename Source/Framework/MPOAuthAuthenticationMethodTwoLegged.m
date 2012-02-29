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
	if (!credentials.consumerKey || !credentials.consumerSecret) {
		NSDictionary *userInfo = [NSDictionary dictionaryWithObject:@"Consumer key or secret is missing" forKey:NSLocalizedDescriptionKey];
		
		[[NSNotificationCenter defaultCenter] postNotificationName:MPOAuthNotificationErrorHasOccurred
															object:self.oauthAPI
														  userInfo:userInfo];
		return;
	}
	
	// alright, we have the key and the secret, that's all we need
	[self.oauthAPI setAuthenticationState:MPOAuthAuthenticationStateAuthenticated];
	if ([delegate_ respondsToSelector:@selector(authenticationDidSucceed)]) {
		[delegate_ authenticationDidSucceed];
	}
}

- (void)loader:(MPOAuthAPIRequestLoader *)inLoader didFailWithError:(NSError *)inError
{
	if ([delegate_ respondsToSelector:@selector(authenticationDidFailWithError:)]) {
		[delegate_ authenticationDidFailWithError:inError];
	}
}


@end
