//
//  MPOAuthCredentialConcreteStore+TokenAdditionsiPhone.m
//  MPOAuthConnection
//
//  Created by Karl Adam on 08.12.13.
//  Copyright 2008 matrixPointer. All rights reserved.
//

#import "MPOAuthCredentialConcreteStore+KeychainAdditions.h"
#import <Security/Security.h>

#if TARGET_OS_IPHONE

@interface MPOAuthCredentialConcreteStore (TokenAdditionsiPhone)

- (NSString *)findValueFromKeychainUsingName:(NSString *)inName returningItem:(__autoreleasing NSDictionary **)outKeychainItemRef;

@end


@implementation MPOAuthCredentialConcreteStore (KeychainAdditions)

- (void)addToKeychainUsingName:(NSString *)inName andValue:(NSString *)inValue {
	NSString *serverName = [self.baseURL host];
	NSString *securityDomain = [self.authenticationURL host];
//	NSString *itemID = [NSString stringWithFormat:@"%@.oauth.%@", [[NSBundle mainBundle] bundleIdentifier], inName];
	NSDictionary *keychainItemAttributeDictionary = [NSDictionary dictionaryWithObjectsAndKeys:	(__bridge id)kSecClassInternetPassword, kSecClass,
																								securityDomain, kSecAttrSecurityDomain,
																								serverName, kSecAttrServer,
																								inName, kSecAttrAccount,
																								kSecAttrAuthenticationTypeDefault, kSecAttrAuthenticationType,
																								[NSNumber numberWithUnsignedLongLong:'oaut'], kSecAttrType,
																								[inValue dataUsingEncoding:NSUTF8StringEncoding], kSecValueData,
													 nil];
	
	
	// just try to add the item, checking for an existing item does not reliably work
	OSStatus success = SecItemAdd((__bridge CFDictionaryRef)keychainItemAttributeDictionary, NULL);
	
	// the item already exists, let's update
	if (success == errSecDuplicateItem) {
		NSMutableDictionary *updateDictionary = [keychainItemAttributeDictionary mutableCopy];
		[updateDictionary removeObjectForKey:(__bridge id)kSecClass];
		
		SecItemUpdate((__bridge CFDictionaryRef)keychainItemAttributeDictionary, (__bridge CFDictionaryRef)updateDictionary);
	}
	else if (success == errSecNotAvailable) {
		[NSException raise:@"Keychain Not Available" format:@"Keychain Access Not Currently Available"];
	}
}

- (NSString *)findValueFromKeychainUsingName:(NSString *)inName {
	return [self findValueFromKeychainUsingName:inName returningItem:NULL];
}

- (NSString *)findValueFromKeychainUsingName:(NSString *)inName returningItem:(__autoreleasing NSDictionary **)outKeychainItemRef {
	NSString *foundPassword = nil;
	NSString *serverName = [self.baseURL host];
	NSString *securityDomain = [self.authenticationURL host];
	NSDictionary *attributesDictionary = nil;
	NSData *foundValue = nil;
	OSStatus status = noErr;
//	NSString *itemID = [NSString stringWithFormat:@"%@.oauth.%@", [[NSBundle mainBundle] bundleIdentifier], inName];
	
	NSMutableDictionary *searchDictionary = [NSMutableDictionary dictionaryWithObjectsAndKeys:
											 (__bridge id)kSecClassInternetPassword, (__bridge id)kSecClass,
											 (__bridge id)kSecMatchLimitOne, (__bridge id)kSecMatchLimit,
											 (id)kCFBooleanTrue, (__bridge id)kSecReturnData,
											 (id)kCFBooleanTrue, (__bridge id)kSecReturnAttributes,
											 (id)kCFBooleanTrue, (__bridge id)kSecReturnPersistentRef,
											 inName, (__bridge id)kSecAttrAccount,
											 securityDomain, (__bridge id)kSecAttrSecurityDomain,
											 serverName, (__bridge id)kSecAttrServer,
											 nil];
	
	CFTypeRef foundDict;
	status = SecItemCopyMatching((__bridge CFDictionaryRef)searchDictionary, &foundDict);
	
	if (status == noErr) {
		attributesDictionary = (__bridge_transfer NSDictionary *)foundDict;
		foundValue = [attributesDictionary objectForKey:(__bridge id)kSecValueData];
		if (foundValue) {
			foundPassword = [[NSString alloc] initWithData:foundValue encoding:NSUTF8StringEncoding];
		}
	}
	else {
		MPLog(@"Error finding value from keychain: %ld", status);
	}
	
	if (outKeychainItemRef) {
		*outKeychainItemRef = attributesDictionary;
	}
	
	return foundPassword;
}

- (void)removeValueFromKeychainUsingName:(NSString *)inName {
	NSString *serverName = [self.baseURL host];
	NSString *securityDomain = [self.authenticationURL host];
	
	NSMutableDictionary *searchDictionary = [NSMutableDictionary dictionaryWithObjectsAndKeys:
											 (__bridge id)kSecClassInternetPassword, (__bridge id)kSecClass,
											 securityDomain, (__bridge id)kSecAttrSecurityDomain,
											 serverName, (__bridge id)kSecAttrServer,
											 inName, (__bridge id)kSecAttrAccount,
											 nil];
	
	OSStatus success = SecItemDelete((__bridge CFDictionaryRef)searchDictionary);

	if (success == errSecNotAvailable) {
		[NSException raise:@"Keychain Not Available" format:@"Keychain Access Not Currently Available"];
	} else if (success == errSecParam) {
		[NSException raise:@"Keychain parameter error" format:@"One or more parameters passed to the function were not valid from %@", searchDictionary];
	} else if (success == errSecAllocate) {
		[NSException raise:@"Keychain memory error" format:@"Failed to allocate memory"];			
	}
		
}

@end

#endif //TARGET_OS_IPHONE
