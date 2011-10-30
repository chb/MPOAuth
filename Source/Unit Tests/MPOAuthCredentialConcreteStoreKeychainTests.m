//
//  MPOAuthCredentialConcreteStoreKeychainTests.m
//  MPOAuthConnection
//
//  Created by Karl Adam on 08.12.18.
//  Copyright 2008 matrixPointer. All rights reserved.
//

#import "MPOAuthCredentialConcreteStoreKeychainTests.h"


@implementation MPOAuthCredentialConcreteStoreKeychainTests

@synthesize store;

- (void)setUp {
	self.store = [[MPOAuthCredentialConcreteStore alloc] initWithCredentials:nil forBaseURL:[NSURL URLWithString:@"http://example.com/oauth"]];
}

- (void)tearDown {
	self.store = nil;
}

- (void)testWritingToAndReadingFromKeychain {
	[store removeValueFromKeychainUsingName:@"test_name"];
	
	NSString *testValue = [store findValueFromKeychainUsingName:@"test_name"];
	STAssertNil(testValue, @"The value read from the keychain for \"test_name\" should start as nil");
	
	[store addToKeychainUsingName:@"test_name" andValue:@"test_value"];
	NSString *savedValue = [store findValueFromKeychainUsingName:@"test_name"];
	STAssertEqualObjects(savedValue, @"test_value", @"The value read from the keychain \"%@\" was different from the one written to the keychain: %@", savedValue, @"test_value");


	[store addToKeychainUsingName:@"test_name" andValue:@"test_value2"];
	NSString *savedValue2 = [store findValueFromKeychainUsingName:@"test_name"];
	STAssertEqualObjects(savedValue2, @"test_value2", @"The value read from the keychain \"%@\" was different from the one written to the keychain \"%@\" to overwrite \"%@\"", savedValue, @"test_value2", @"test_value");	

	[store removeValueFromKeychainUsingName:@"test_name"];
	NSString *deletedValue = [store findValueFromKeychainUsingName:@"test_name"];
	STAssertNil(deletedValue, @"The value read from the keychain for \"test_name\" should now be nil");
}

@end
