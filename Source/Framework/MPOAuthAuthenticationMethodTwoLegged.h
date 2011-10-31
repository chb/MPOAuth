//
//  MPOAuthAuthenticationMethodTwoLeggedDelegate.h
//  MPOAuthMobile
//
//  Created by Pascal Pfiffner on 09/16/2011.
//  Copyright 2011 Children's Hospital Boston. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "MPOAuthAPI.h"
#import "MPOAuthAuthenticationMethod.h"


@protocol MPOAuthAuthenticationMethodTwoLeggedDelegate <NSObject>

@optional
- (void)authenticationDidSucceed;
- (void)authenticationDidFailWithError:(NSError *)error;

@end


@interface MPOAuthAuthenticationMethodTwoLegged : MPOAuthAuthenticationMethod

@property (nonatomic, readwrite, unsafe_unretained) id <MPOAuthAuthenticationMethodTwoLeggedDelegate> delegate;

@end
