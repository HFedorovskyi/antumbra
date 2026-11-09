#import <Foundation/Foundation.h>
#import <Preferences/PSListController.h>
#import <Preferences/PSSpecifier.h>

@interface SHDWAboutListController : PSListController
- (NSString *)aboutDeveloper:(id)sender;
- (NSString *)aboutCoreAuthor:(id)sender;
- (NSString *)aboutTranslator:(id)sender;
- (NSString *)aboutInstalledVersion:(id)sender;

- (void)openGitHub:(id)sender;
- (void)openUpstream:(id)sender;
- (void)resetSettings:(id)sender;
@end
