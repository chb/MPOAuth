//
//  MPOAuthURLRequest.m
//  MPOAuthConnection
//
//  Created by Karl Adam on 08.12.05.
//  Copyright 2008 matrixPointer. All rights reserved.
//

#import "MPOAuthURLRequest.h"
#import "MPURLRequestParameter.h"
#import "MPOAuthSignatureParameter.h"

#import "NSURL+MPURLParameterAdditions.h"
#import "NSString+URLEscapingAdditions.h"

@interface MPOAuthURLRequest ()

@property (nonatomic, readwrite, strong) NSURLRequest *urlRequest;

@end


@implementation MPOAuthURLRequest

@synthesize url = _url;
@synthesize HTTPMethod = _httpMethod;
@synthesize urlRequest = _urlRequest;
@synthesize parameters = _parameters;


- (id)initWithURL:(NSURL *)inURL andParameters:(NSArray *)inParameters {
	if ((self = [super init])) {
		self.url = inURL;
		
		// check supplied parameters
		if ([inParameters count] > 0) {
			if ([[inParameters objectAtIndex:0] isKindOfClass:[MPURLRequestParameter class]]) {
				_parameters = [inParameters mutableCopy];
			}
			else {
				_parameters = [[MPURLRequestParameter parametersFromStringArray:inParameters] mutableCopy];
			}
		}
		else {
			_parameters = [[NSMutableArray alloc] initWithCapacity:10];
		}
		self.HTTPMethod = @"GET";
	}
	return self;
}

- (id)initWithURLRequest:(NSURLRequest *)inRequest {
	if ((self = [super init])) {
		self.url = [[inRequest URL] urlByRemovingQuery];
		self.parameters = [[MPURLRequestParameter parametersFromString:[[inRequest URL] query]] mutableCopy];
		self.HTTPMethod = [inRequest HTTPMethod];
		self.urlRequest = [inRequest mutableCopy];
	}
	return self;
}



#pragma mark -

- (NSArray *)nonOAuthParameters {
	NSArray *oauthParameters = [NSArray arrayWithObjects:@"oauth_signature", @"oauth_nonce", @"oauth_token", @"oauth_consumer_key", @"oauth_timestamp", @"oauth_version", @"oauth_signature_method", @"oauth_body_hash", nil];
	NSPredicate *filterPredicate = [NSPredicate predicateWithFormat:@"!(name IN %@)", oauthParameters];
	return [self.parameters filteredArrayUsingPredicate:filterPredicate];
}

- (NSString *)authorizationHeaderValueFromParameterArray:(NSArray *)parameterArray {
	NSMutableArray *authParts = [NSMutableArray arrayWithCapacity:[parameterArray count]];
	for (MPURLRequestParameter *param in parameterArray) {
		if ([param.name length] >= 6 && [@"oauth_" isEqualToString:[param.name substringToIndex:6]] && param.value) {
			[authParts addObject:[param URLEncodedParameterString]];
		}
	}
	
	NSString *fullAuthString = @"OAuth ";
	return [fullAuthString stringByAppendingString:[authParts componentsJoinedByString:@","]];
}

- (NSURLRequest  *)urlRequestSignedWithSecret:(NSString *)inSecret usingMethod:(NSString *)inScheme {
	NSMutableURLRequest *aRequest = [self.urlRequest mutableCopy];
	
	if (!aRequest ) {
		aRequest = [[NSMutableURLRequest alloc] init];
	}
	[aRequest setHTTPMethod:self.HTTPMethod];
	
	NSArray *nonOauthParameters = [self nonOAuthParameters];
	BOOL addNonOauthParametersToURL = NO;
	
	// a GET or DELETE call
	if ([_httpMethod isEqualToString:@"GET"] || [_httpMethod isEqualToString:@"DELETE"]) {
		addNonOauthParametersToURL = ([nonOauthParameters count] > 0);
	}
	
	// a POST or PUT call
	else if  ([_httpMethod isEqualToString:@"POST"] || [_httpMethod isEqualToString:@"PUT"]) {
		if ([nonOauthParameters count] > 0 && [aRequest HTTPBody]) {
			[NSException raise:@"MalformedHTTPPOSTMethodException" format:@"The request has both an HTTP Body and additional parameters. This is not supported."];
		}
		else if ([nonOauthParameters count] > 0) {
			NSString *dataString = [MPURLRequestParameter parameterStringForParameters:nonOauthParameters];
			NSData *myData = [dataString dataUsingEncoding:NSUTF8StringEncoding];
			MPLog(@"%@ dataString - %@", _httpMethod, dataString);
			
			[aRequest setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
			[aRequest setValue:[NSString stringWithFormat:@"%d", [myData length]] forHTTPHeaderField:@"Content-Length"];
			[aRequest setHTTPBody:myData];
		}
		else if ([aRequest HTTPBody]) {
			NSString *bodyHash = [MPOAuthSignatureParameter HMAC_SHA1DigestForData:[aRequest HTTPBody]];
			
			MPURLRequestParameter *bodyHashParam = [[MPURLRequestParameter alloc] initWithName:@"oauth_body_hash" andValue:bodyHash];
			[_parameters addObject:bodyHashParam];
		}
	}
	
	// unimplemented method
	else {
		[NSException raise:@"UnhandledHTTPMethodException" format:@"The requested HTTP method, %@, is not supported", _httpMethod];
	}
	
	// Signing
	[_parameters sortUsingSelector:@selector(compare:)];
	NSMutableString *parameterString = [[NSMutableString alloc] initWithString:[MPURLRequestParameter parameterStringForParameters:_parameters]];
	MPOAuthSignatureParameter *signatureParameter = [[MPOAuthSignatureParameter alloc] initWithText:parameterString andSecret:inSecret forRequest:self usingMethod:inScheme];
	
	[parameterString appendFormat:@"&%@", [signatureParameter URLEncodedParameterString]];
	
	// compose the request
	if (addNonOauthParametersToURL) {
		self.url = [_url urlByAddingParameters:nonOauthParameters];
	}
	NSArray *allParameters = [_parameters arrayByAddingObject:signatureParameter];
	[aRequest setValue:[self authorizationHeaderValueFromParameterArray:allParameters] forHTTPHeaderField:@"Authorization"];		// always use the Authorization Header
	
	MPLog(@"URL - %@", self.url);
	MPLog(@"Headers - %@", [aRequest allHTTPHeaderFields]);
	[aRequest setURL:self.url];
	self.urlRequest = aRequest;
	
	
	return aRequest;
}

#pragma mark -

- (void)addParameters:(NSArray *)inParameters {
	[self.parameters addObjectsFromArray:inParameters];
}

@end
