//
//  MPOWSLRDDiscoverer.h
//  MPWebServices
//
//  Created by Karl Adam on 09.03.30.
//  Copyright 2009 matrixPointer. All rights reserved.
//

#import <Foundation/Foundation.h>

@protocol MPWSLRDDiscovererDelegate;

typedef enum {
	MPWSLRDDiscovererStateRequestingURI				= 0,
	MPWSLRDDiscovererStateSearchingForLinkElements	= 1,
	MPWSLRDDiscovererStateSearchingForLinkHeaders	= 2,
	MPWSLRDDiscovererStateRequestingHostMeta		= 3,
	MPWSLRDDiscovererStateSearchingHostMeta			= 4,
	MPWSLRDDiscovererStateResourceLocated			= 5,
	MPWSLRDDiscovererStateLookupFailured			= 6
} MPWSLRDDiscovererState;


@interface MPWSLRDDiscoverer : NSObject

@property (nonatomic, readonly, unsafe_unretained) id <MPWSLRDDiscovererDelegate> delegate;
@property (nonatomic, readonly, assign) MPWSLRDDiscovererState discoveryState;

- (void)locateResourceOfType:(NSString *)inMimeType fromURL:(NSURL *)inURL;

@end


@protocol MPWSLRDDiscovererDelegate

- (void)locatedResourceOfType:(NSString *)inMimeType fromURL:(NSURL *)inEndpointURL atLocation:(NSURL *)inResourceURL;

@end
