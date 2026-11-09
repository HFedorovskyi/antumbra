#ifndef SHDW_PANE_LOG_H
#define SHDW_PANE_LOG_H

#import <Foundation/Foundation.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

static inline NSString *SHDWPaneLogPath(void) {
  static NSString *path;
  static dispatch_once_t once;
  dispatch_once(&once, ^{
    NSString *dir =
        [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Caches"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir
                              withIntermediateDirectories:YES
                                               attributes:nil
                                                    error:NULL];
    path = [dir stringByAppendingPathComponent:@"shdw_pane.log"];
  });
  return path;
}

static inline void SHDWPaneLog(NSString *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
  va_end(ap);
  NSString *line = [NSString
      stringWithFormat:@"%.3f pid=%d %@\n", [NSDate date].timeIntervalSince1970,
                       getpid(), msg];
  FILE *f = fopen(SHDWPaneLogPath().fileSystemRepresentation, "a");
  if (f) {
    fputs(line.UTF8String, f);
    fclose(f);
  }
}

#endif
