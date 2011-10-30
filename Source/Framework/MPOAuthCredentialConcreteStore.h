//
//  MPOAuthCredentialConcreteStore.h
//  MPOAuthConnection
//
//  Created by Karl Adam on 08.12.11.
//  Copyright 2008 matrixPointer. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "MPOAuthCredentialStore.h"
#import "MPOAuthParameterFactory.h"

@interface MPOAuthCredentialConcreteStore : NSObject <MPOAuthCredentialStore, MPOAuthParameterFactory> 

@property (nonatomic, readonly, strong) NSURL *baseURL;
@property (nonatomic, readonly, strong) NSURL *authenticationURL;

@property (weak, nonatomic, readonly) NSString *tokenSecret;
@property (weak, nonatomic, readonly) NSString *signingKey;

@property (nonatomic, readwrite, strong) NSString *requestToken;
@property (nonatomic, readwrite, strong) NSString *requestTokenSecret;
@property (nonatomic, readwrite, strong) NSString *accessToken;
@property (nonatomic, readwrite, strong) NSString *accessTokenSecret;

@property (nonatomic, readwrite, strong) NSString *sessionHandle;

- (id)initWithCredentials:(NSDictionary *)inCredentials forBaseURL:(NSURL *)inBaseURL;
- (id)initWithCredentials:(NSDictionary *)inCredentials forBaseURL:(NSURL *)inBaseURL withAuthenticationURL:(NSURL *)inAuthenticationURL;

- (void)setCredential:(id)inCredential withName:(NSString *)inName;
- (void)removeCredentialNamed:(NSString *)inName;
	

@end
