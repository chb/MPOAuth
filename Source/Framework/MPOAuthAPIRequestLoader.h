//
//  MPOAuthAPIRequestLoader.h
//  MPOAuthConnection
//
//  Created by Karl Adam on 08.12.05.
//  Copyright 2008 matrixPointer. All rights reserved.
//

#import <Foundation/Foundation.h>

extern NSString * const MPOAuthNotificationRequestTokenReceived;
extern NSString * const MPOAuthNotificationRequestTokenRejected;
extern NSString * const MPOAuthNotificationAccessTokenReceived;
extern NSString * const MPOAuthNotificationAccessTokenRejected;
extern NSString * const MPOAuthNotificationAccessTokenRefreshed;
extern NSString * const MPOAuthNotificationErrorHasOccurred;

@protocol MPOAuthCredentialStore;
@protocol MPOAuthParameterFactory;

@class MPOAuthAPI;
@class MPOAuthURLRequest;
@class MPOAuthURLResponse;
@class MPOAuthCredentialConcreteStore;
@class MPOAuthAPIRequestLoader;


@protocol MPOAuthAPIRequestLoaderDelegate <NSObject>

- (void)loader:(MPOAuthAPIRequestLoader *)inLoader didReceiveData:(NSData *)inData;
- (void)loader:(MPOAuthAPIRequestLoader *)inLoader didFailWithError:(NSError *)error;

@end


@interface MPOAuthAPIRequestLoader : NSObject {
	MPOAuthCredentialConcreteStore	*_credentials;
	NSMutableData					*_dataBuffer;
	NSString						*_dataAsString;
	NSError							*_error;
}

@property (nonatomic, readwrite, strong) MPOAuthAPI *api;
@property (nonatomic, readwrite, strong) id <MPOAuthCredentialStore, MPOAuthParameterFactory> credentials;
@property (nonatomic, readwrite, strong) MPOAuthURLRequest *oauthRequest;
@property (nonatomic, readwrite, strong) MPOAuthURLResponse *oauthResponse;
@property (nonatomic, readwrite, unsafe_unretained) id <MPOAuthAPIRequestLoaderDelegate> delegate;
@property (nonatomic, readonly, strong) NSData *data;
@property (nonatomic, readonly, strong) NSString *responseString;

- (id)initWithURL:(NSURL *)inURL;
- (id)initWithRequest:(MPOAuthURLRequest *)inRequest;

- (void)loadSynchronously:(BOOL)inSynchronous;

@end

