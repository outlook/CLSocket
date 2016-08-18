/*
 The MIT License (MIT)
 Copyright (c) 2016 Microsoft Inc.

 Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#import "ViewController.h"
@import CLSocket;

@interface ViewController () <CLSocketDelegate>
@property (nonatomic, strong) CLSocket *socket;
@property (nonatomic, strong) NSMutableData *rxBuffer;
@end

@implementation ViewController

- (void)viewDidLoad
{
  [super viewDidLoad];
  
  self.socket = [[CLSocket alloc] init];
  self.socket.delegate = self;
  self.socket.useTLS = YES;
  
  NSError *err;
  if (![self.socket connectToHost:@"www.google.com" onPort:443 error:&err])
  {
    NSLog(@"failed to connect: %@", err);
    return;
  }
  
  [self.socket writeData:[@"GET / HTTP/1.1\r\n\r\n" dataUsingEncoding:NSUTF8StringEncoding]];
  
  self.rxBuffer = [NSMutableData data];
}

- (void)dispatchIncomingMessages
{
  NSString *responseData = [[NSString alloc] initWithData:self.rxBuffer encoding:NSUTF8StringEncoding];
  NSLog(@"got data: %@", responseData);
}

#pragma mark - CLSocketDelegate

- (void)socketDidConnect:(CLSocket *)socket
{
  NSLog(@"Socket connected");
  
}

- (void)socketDidDisconnect:(CLSocket *)sock withError:(NSError *)err
{
  NSLog(@"Socket didDisconnect: err=%@", err);
  self.rxBuffer = nil;
}

- (void)socketDidReadData:(NSData *)data
{
  NSAssert(self.rxBuffer, @"Invalid state");
  
  [self.rxBuffer appendData:data];
  [self dispatchIncomingMessages];
}

- (void)socket:(CLSocket *)sock didReceiveTrust:(SecTrustRef)trust completionHandler:(void (^)(BOOL shouldTrustPeer))completionHandler
{
  NSLog(@"socket:didReceiveTrust:");

  dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{

    // Perform standard system trust evaluation.
    // For more details, see https://developer.apple.com/library/mac/technotes/tn2232/_index.html

    SecTrustResultType result;
    BOOL isTrusted = NO;
    OSStatus status = SecTrustEvaluate(trust, &result);
    if (status == errSecSuccess &&
        (result == kSecTrustResultProceed || result == kSecTrustResultUnspecified)) {
      isTrusted = YES;
    } else {
      NSLog(@"Error: server trust failed certificate check: status=%d result=%u", (int)status, (unsigned)result);
      isTrusted = NO;
    }
    completionHandler(isTrusted);
  });
}

@end
