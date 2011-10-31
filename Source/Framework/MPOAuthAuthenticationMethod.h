//
//  MPOAuthAuthenticationMethod.h
//  MPOAuthConnection
//
//  Created by Karl Adam on 09.12.19.
//  Copyright 2009 matrixPointer. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "MPOAuthAPIRequestLoader.h"

extern NSString * const MPOAuthAccessTokenURLKey;

@class MPOAuthAPI;

@interface MPOAuthAuthenticationMethod : NSObject <MPOAuthAPIRequestLoaderDelegate>

@property (nonatomic, readwrite, unsafe_unretained) MPOAuthAPI *oauthAPI;
@property (nonatomic, readwrite, strong) NSURL *oauthGetAccessTokenURL;

- (id)initWithAPI:(MPOAuthAPI *)inAPI forURL:(NSURL *)inURL;
- (id)initWithAPI:(MPOAuthAPI *)inAPI forURL:(NSURL *)inURL withConfiguration:(NSDictionary *)inConfig;
- (id)initWithAPI:(MPOAuthAPI *)inAPI forURL:(NSURL *)inURL withConfiguration:(NSDictionary *)inConfig preferredMethod:(NSString *)inMethod;
- (void)authenticate;

- (void)setTokenRefreshInterval:(NSTimeInterval)inTimeInterval;
- (void)refreshAccessToken;


@end
