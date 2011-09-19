//
//  MPOAuthAuthenticationMethodAuthExchange.h
//  MPOAuthMobile
//
//  Created by Pascal Pfiffner on 09/16/2011.
//  Copyright 2011 Children's Hospital Boston. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "MPOAuthAPI.h"
#import "MPOAuthAuthenticationMethod.h"

@protocol MPOAuthAuthenticationMethodTwoLeggedDelegate;

@interface MPOAuthAuthenticationMethodTwoLegged : MPOAuthAuthenticationMethod <MPOAuthAPIInternalClient> {
	id <MPOAuthAuthenticationMethodTwoLeggedDelegate> delegate_;
}

@property (nonatomic, readwrite, assign) id <MPOAuthAuthenticationMethodTwoLeggedDelegate> delegate;


@end

@protocol MPOAuthAuthenticationMethodTwoLeggedDelegate <NSObject>

@optional
- (void)authenticationDidReturnParameter:(NSDictionary *)params;
- (void)authenticationDidFailWithError:(NSError *)error;

@end
