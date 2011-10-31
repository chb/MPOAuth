//
//  MPOAuthCredentialConcreteStore+TokenAdditionsMac.m
//  MPOAuthConnection
//
//  Created by Karl Adam on 08.12.13.
//  Copyright 2008 matrixPointer. All rights reserved.
//

#import "MPOAuthCredentialConcreteStore+KeychainAdditions.h"
#import <Security/Security.h>

#if !TARGET_OS_IPHONE

@interface MPOAuthCredentialConcreteStore (KeychainAdditionsMac)

- (NSString *)findValueFromKeychainUsingName:(NSString *)inName returningItem:(SecKeychainItemRef *)outKeychainItemRef;

@end


@implementation MPOAuthCredentialConcreteStore (KeychainAdditions)

- (void)addToKeychainUsingName:(NSString *)inName andValue:(NSString *)inValue {
	NSString *serverName = [self.baseURL host];
	NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
	bundleID = bundleID ? bundleID : @"org.unknown";						// the test bundle does not get an id??
	NSString *securityDomain = [self.authenticationURL host];
	NSString *uniqueName = [NSString stringWithFormat:@"%@.%@", bundleID, inName];
	SecKeychainItemRef existingKeychainItem = NULL;
	
	if ([self findValueFromKeychainUsingName:inName returningItem:&existingKeychainItem]) {
		// This is MUCH easier than updating the item attributes/data
		SecKeychainItemDelete(existingKeychainItem);
	}
	
	OSStatus status = SecKeychainAddInternetPassword(NULL /* default keychain */,
								   [serverName length], [serverName UTF8String],
								   [securityDomain length], [securityDomain UTF8String],
								   [uniqueName length], [uniqueName UTF8String],	/* account name */
								   0, NULL,	/* path */
								   0,
								   'oaut'	/* OAuth, not an official OSType code */,
								   kSecAuthenticationTypeDefault,
								   [inValue length], [inValue UTF8String],
								   NULL);
	if (errSecSuccess != status) {
		CFStringRef errStr = SecCopyErrorMessageString(status, NULL);
		NSLog(@"Failed to add item to keychain: %@", (__bridge NSString *)errStr);
		CFRelease(errStr);
	}
}

- (NSString *)findValueFromKeychainUsingName:(NSString *)inName {
	return [self findValueFromKeychainUsingName:inName returningItem:NULL];
}

- (NSString *)findValueFromKeychainUsingName:(NSString *)inName returningItem:(SecKeychainItemRef *)outKeychainItemRef {
	NSString *foundPassword = nil;
	NSString *serverName = [self.baseURL host];
	NSString *securityDomain = [self.authenticationURL host];
	NSString *bundleID = [[NSBundle mainBundle] bundleIdentifier];
	bundleID = bundleID ? bundleID : @"org.unknown";						// the test bundle does not get an id??
	NSString *uniqueName = [NSString stringWithFormat:@"%@.%@", bundleID, inName];
	
	UInt32 passwordLength = 0;
	const char *passwordString = NULL;
	
	OSStatus status = SecKeychainFindInternetPassword(NULL	/* default keychain */,
													  [serverName length], [serverName UTF8String],
													  [securityDomain length], [securityDomain UTF8String],
													  [uniqueName length], [uniqueName UTF8String],
													  0, NULL,	/* path */
													  0,
													  kSecProtocolTypeAny,
													  kSecAuthenticationTypeAny,
													  (UInt32 *)&passwordLength,
													  (void **)&passwordString,
													  outKeychainItemRef);
	if (status == noErr && passwordLength) {
		NSData *passwordStringData = [NSData dataWithBytes:passwordString length:passwordLength];
		foundPassword = [[NSString alloc] initWithData:passwordStringData encoding:NSUTF8StringEncoding];
	}
	
	if (passwordString) {
		(void)SecKeychainItemFreeContent(NULL, (void *)passwordString);
	}
	
	return foundPassword;
}

- (void)removeValueFromKeychainUsingName:(NSString *)inName {
	SecKeychainItemRef aKeychainItem = NULL;
	
	[self findValueFromKeychainUsingName:inName returningItem:&aKeychainItem];
	
	if (aKeychainItem) {
		SecKeychainItemDelete(aKeychainItem);
	}
}

@end

#endif
