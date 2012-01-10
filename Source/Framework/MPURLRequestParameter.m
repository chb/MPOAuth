//
//  MPURLParameter.m
//  MPOAuthConnection
//
//  Created by Karl Adam on 08.12.05.
//  Copyright 2008 matrixPointer. All rights reserved.
//

#import "MPURLRequestParameter.h"
#import "MPOAuthAPI.h"
#import "NSString+URLEscapingAdditions.h"

@implementation MPURLRequestParameter

+ (NSArray *)parametersFromString:(NSString *)inString {
	NSMutableArray *foundParameters = [NSMutableArray arrayWithCapacity:10];
	if ([inString length] > 0) {
		NSScanner *parameterScanner = [[NSScanner alloc] initWithString:inString];
		NSString *name = nil;
		NSString *value = nil;
		MPURLRequestParameter *currentParameter = nil;
		
		while (![parameterScanner isAtEnd]) {
			name = nil;
			value = nil;
			
			[parameterScanner scanUpToString:@"=" intoString:&name];
			[parameterScanner scanString:@"=" intoString:NULL];
			[parameterScanner scanUpToString:@"&" intoString:&value];
			[parameterScanner scanString:@"&" intoString:NULL];		
			
			currentParameter = [[MPURLRequestParameter alloc] init];
			currentParameter.name = name;
			currentParameter.value = [value stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
			
			[foundParameters addObject:currentParameter];
			
		}
	}
	
	return foundParameters;
}

+ (NSArray *)parametersFromStringArray:(NSArray *)inArray {
	NSMutableArray *parameterArray = [[NSMutableArray alloc] init];
	MPURLRequestParameter *aURLParameter = nil;
	
	for (NSString *aString in inArray) {
		NSArray *parts = [aString componentsSeparatedByString:@"="];
		if (2 == [parts count]) {
			aURLParameter = [[MPURLRequestParameter alloc] init];
			aURLParameter.name = [parts objectAtIndex:0];
			aURLParameter.value = [parts objectAtIndex:1];
			
			[parameterArray addObject:aURLParameter];
		}
		else {
			MPLog(@"Invalid parameter: %@", aString);
		}
	}
	
	return parameterArray;
}

+ (NSArray *)parametersFromDictionary:(NSDictionary *)inDictionary {
	NSMutableArray *parameterArray = [[NSMutableArray alloc] init];
	MPURLRequestParameter *aURLParameter = nil;
	
	for (NSString *aKey in [inDictionary allKeys]) {
		aURLParameter = [[MPURLRequestParameter alloc] init];
		aURLParameter.name = aKey;
		aURLParameter.value = [inDictionary objectForKey:aKey];
		
		[parameterArray addObject:aURLParameter];
	}
	
	return parameterArray;
}

+ (NSDictionary *)parameterDictionaryFromString:(NSString *)inString {
	NSMutableDictionary *foundParameters = [NSMutableDictionary dictionaryWithCapacity:10];
	if (inString) {
		NSScanner *parameterScanner = [[NSScanner alloc] initWithString:inString];
		NSString *name = nil;
		NSString *value = nil;
		
		while (![parameterScanner isAtEnd]) {
			name = nil;
			value = nil;
			
			[parameterScanner scanUpToString:@"=" intoString:&name];
			[parameterScanner scanString:@"=" intoString:NULL];
			[parameterScanner scanUpToString:@"&" intoString:&value];
			[parameterScanner scanString:@"&" intoString:NULL];		
			
			NSString *unescapedValue = [value stringByReplacingPercentEscapesUsingEncoding:NSUTF8StringEncoding];
			if (name && unescapedValue) {
				[foundParameters setObject:unescapedValue forKey:name];
			}
		}
		
	}
	return foundParameters;
}

+ (NSString *)parameterStringForParameters:(NSArray *)inParameters {
	NSMutableString *queryString = [[NSMutableString alloc] init];
	int i = 0;
	int parameterCount = [inParameters count];	
	MPURLRequestParameter *aParameter = nil;
	
	for (; i < parameterCount; i++) {
		aParameter = [inParameters objectAtIndex:i];
		[queryString appendString:[aParameter URLEncodedParameterString]];
		
		if (i < parameterCount - 1) {
			[queryString appendString:@"&"];
		}
	}
	
	return queryString;
}

+ (NSString *)parameterStringForDictionary:(NSDictionary *)inParameterDictionary {
	NSArray *parameters = [self parametersFromDictionary:inParameterDictionary];
	NSString *queryString = [self parameterStringForParameters:parameters];
	
	return queryString;
}

#pragma mark -

- (id)initWithName:(NSString *)inName andValue:(NSString *)inValue {
	if ((self = [super init])) {
		self.name = inName;
		self.value = inValue;
	}
	return self;
}


@synthesize name = _name;
@synthesize value = _value;

#pragma mark -

- (NSString *)URLEncodedParameterString {
	NSString *key = [self.name stringByAddingURIPercentEscapesUsingEncoding:NSUTF8StringEncoding];
	NSString *val = self.value ? [self.value stringByAddingURIPercentEscapesUsingEncoding:NSUTF8StringEncoding] : @"";
	return [NSString stringWithFormat:@"%@=%@", key, val];
}

#pragma mark -

- (NSComparisonResult)compare:(id)inObject {
	NSComparisonResult result = [self.name compare:[(MPURLRequestParameter *)inObject name]];
	
	if (result == NSOrderedSame) {
		result = [self.value compare:[(MPURLRequestParameter *)inObject value]];
	}
								 
	return result;
}

- (NSString *)description {
	return [NSString stringWithFormat:@"<%@: %p %@>", NSStringFromClass([self class]), self, [self URLEncodedParameterString]];
}

@end
