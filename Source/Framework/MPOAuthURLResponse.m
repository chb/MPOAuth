//
//  MPOAuthURLResponse.m
//  MPOAuthConnection
//
//  Created by Karl Adam on 08.12.05.
//  Copyright 2008 matrixPointer. All rights reserved.
//

#import "MPOAuthURLResponse.h"

@interface MPOAuthURLResponse ()
@property (nonatomic, readwrite, strong) NSURLResponse *urlResponse;
@property (nonatomic, readwrite, strong) NSDictionary *oauthParameters;
@end

@implementation MPOAuthURLResponse

@synthesize urlResponse = _urlResponse;
@synthesize oauthParameters = _oauthParameters;


@end
