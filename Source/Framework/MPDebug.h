//
//  MPDebug.h
//  MPOAuthConnection
//
//  Created by Karl Adam on 09.02.06.
//  Copyright 2009 matrixPointer. All rights reserved.
//

#ifdef MPOAUTH_DEBUG
	#define MPLog(fmt, ...) NSLog((@"%s (line %d) " fmt), __PRETTY_FUNCTION__, __LINE__, ##__VA_ARGS__);
#else
	#define MPLog(...) 
#endif
