//
//  RootViewController.h
//  MPOAuthMobile
//
//  Created by Karl Adam on 08.12.14.
//  Copyright matrixPointer 2008. All rights reserved.
//

#import <UIKit/UIKit.h>

@class MPOAuthAPI;

@interface RootViewController : UIViewController 

@property (nonatomic, strong) MPOAuthAPI *oauthAPI;
@property (nonatomic, strong) IBOutlet UITextField *methodInput;
@property (nonatomic, strong) IBOutlet UITextField *parametersInput;
@property (nonatomic, strong) IBOutlet UITextField *textOutput;

- (IBAction)clearCredentials;
- (IBAction)reauthenticate;

@end
