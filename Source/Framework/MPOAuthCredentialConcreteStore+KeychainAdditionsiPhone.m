//
//  MPOAuthCredentialConcreteStore+TokenAdditionsiPhone.m
//  MPOAuthConnection
//
//  Created by Karl Adam on 08.12.13.
//  Copyright 2008 matrixPointer. All rights reserved.
//

#import "MPOAuthCredentialConcreteStore+KeychainAdditions.h"
#import <Security/Security.h>

#if TARGET_OS_IPHONE && (!TARGET_IPHONE_SIMULATOR || __IPHONE_3_0)

@interface MPOAuthCredentialConcreteStore (TokenAdditionsiPhone)
- (NSString *)findValueFromKeychainUsingName:(NSString *)inName returningItem:(NSDictionary **)outKeychainItemRef;
@end

@implementation MPOAuthCredentialConcreteStore (KeychainAdditions)

- (void)addToKeychainUsingName:(NSString *)inName andValue:(NSString *)inValue {
	NSString *serverName = [self.baseURL host];
	NSString *securityDomain = [self.authenticationURL host];
//	NSString *itemID = [NSString stringWithFormat:@"%@.oauth.%@", [[NSBundle mainBundle] bundleIdentifier], inName];
	NSDictionary *keychainItemAttributeDictionary = [NSDictionary dictionaryWithObjectsAndKeys:	(id)kSecClassInternetPassword, kSecClass,
																								securityDomain, kSecAttrSecurityDomain,
																								serverName, kSecAttrServer,
																								inName, kSecAttrAccount,
																								kSecAttrAuthenticationTypeDefault, kSecAttrAuthenticationType,
																								[NSNumber numberWithUnsignedLongLong:'oaut'], kSecAttrType,
																								[inValue dataUsingEncoding:NSUTF8StringEncoding], kSecValueData,
													 nil];
	
	
	// just try to add the item, checking for an existing item does not reliably work
	OSStatus success = SecItemAdd( (CFDictionaryRef)keychainItemAttributeDictionary, NULL);
	
	// the item already exists, let's update
	if (success == errSecDuplicateItem) {
		NSMutableDictionary *updateDictionary = [keychainItemAttributeDictionary mutableCopy];
		[updateDictionary removeObjectForKey:(id)kSecClass];
		
		SecItemUpdate((CFDictionaryRef)keychainItemAttributeDictionary, (CFDictionaryRef)updateDictionary);
		[updateDictionary release];
	}
	else if (success == errSecNotAvailable) {
		[NSException raise:@"Keychain Not Available" format:@"Keychain Access Not Currently Available"];
	}
}

- (NSString *)findValueFromKeychainUsingName:(NSString *)inName {
	return [self findValueFromKeychainUsingName:inName returningItem:NULL];
}

- (NSString *)findValueFromKeychainUsingName:(NSString *)inName returningItem:(NSDictionary **)outKeychainItemRef {
	NSString *foundPassword = nil;
	NSString *serverName = [self.baseURL host];
	NSString *securityDomain = [self.authenticationURL host];
	NSDictionary *attributesDictionary = nil;
	NSData *foundValue = nil;
	OSStatus status = noErr;
//	NSString *itemID = [NSString stringWithFormat:@"%@.oauth.%@", [[NSBundle mainBundle] bundleIdentifier], inName];
	
	NSMutableDictionary *searchDictionary = [NSMutableDictionary dictionaryWithObjectsAndKeys:(id)kSecClassInternetPassword, (id)kSecClass,
																							  securityDomain, (id)kSecAttrSecurityDomain,
																							  serverName, (id)kSecAttrServer,
																							  inName, (id)kSecAttrAccount,
																							  (id)kSecMatchLimitOne, (id)kSecMatchLimit,
																							  (id)kCFBooleanTrue, (id)kSecReturnData,
																							  (id)kCFBooleanTrue, (id)kSecReturnAttributes,
																							  (id)kCFBooleanTrue, (id)kSecReturnPersistentRef,
											 nil];

	status = SecItemCopyMatching((CFDictionaryRef)searchDictionary, (CFTypeRef *)&attributesDictionary);		
	foundValue = [attributesDictionary objectForKey:(id)kSecValueData];
	if (outKeychainItemRef) {
		*outKeychainItemRef = attributesDictionary;
	}
	
	if (status == noErr) {
		[attributesDictionary autorelease];
		if (foundValue) {
			foundPassword = [[NSString alloc] initWithData:foundValue encoding:NSUTF8StringEncoding];
		}
	}
	
	return [foundPassword autorelease];
}

- (void)removeValueFromKeychainUsingName:(NSString *)inName {
	NSString *serverName = [self.baseURL host];
	NSString *securityDomain = [self.authenticationURL host];
	
	NSMutableDictionary *searchDictionary = [NSMutableDictionary dictionaryWithObjectsAndKeys:	(id)kSecClassInternetPassword, (id)kSecClass,
																								 securityDomain, (id)kSecAttrSecurityDomain,
																								 serverName, (id)kSecAttrServer,
																								 inName, (id)kSecAttrAccount,
																								 nil];
	
	OSStatus success = SecItemDelete((CFDictionaryRef)searchDictionary);

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
