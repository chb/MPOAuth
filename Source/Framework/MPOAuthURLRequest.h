//
//  MPOAuthURLRequest.h
//  MPOAuthConnection
//
//  Created by Karl Adam on 08.12.05.
//  Copyright 2008 matrixPointer. All rights reserved.
//

#import <Foundation/Foundation.h>


@interface MPOAuthURLRequest : NSObject

@property (nonatomic, readwrite, strong) NSURL *url;
@property (nonatomic, readwrite, strong) NSString *HTTPMethod;
@property (nonatomic, readonly, strong) NSURLRequest *urlRequest;
@property (nonatomic, readwrite, strong) NSMutableArray *parameters;

- (id)initWithURL:(NSURL *)inURL andParameters:(NSArray *)parameters;
- (id)initWithURLRequest:(NSURLRequest *)inRequest;

- (void)addParameters:(NSArray *)inParameters;

- (NSURLRequest  *)urlRequestSignedWithSecret:(NSString *)inSecret usingMethod:(NSString *)inScheme;


@end
