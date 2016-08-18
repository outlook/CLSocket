/*
 The MIT License (MIT)
 Copyright (c) 2016 Microsoft Inc.

 Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

@import CFNetwork;
#import <sys/errno.h>
#import "CLSocket.h"


#define LogNetVerbose NSLog
#define LogNetInfo NSLog
#define LogNetWarn NSLog
#define LogNetError NSLog

NSString *CLSocketErrorDomain = @"CLSocketErrorDomain";


typedef NS_ENUM(NSUInteger, CLSocketState) {
  CLSocketStateDisconnected,  /// socket is disconnected
  CLSocketStateConnecting,    /// socket is connecting
  CLSocketStateSecuring,      /// socket is connected but the TLS trust needs evaluation
  CLSocketStateConnected,     /// socket is connected and the TLS trust has been validated
};


@interface CLSocket () <NSStreamDelegate>

@property (nonatomic, assign) CLSocketState state;

@property (nonatomic, strong) NSTimer *connectTimer;

@property (nonatomic, strong) NSInputStream *inputStream;
@property (nonatomic, assign) BOOL inputHasBytesAvailable; // needed to avoid blocking when we call -read:

@property (nonatomic, strong) NSOutputStream *outputStream;
@property (nonatomic, assign) NSInteger writeBufferOffset;
@property (nonatomic, assign) BOOL writeBufferExhausted;
@property (nonatomic, strong) NSMutableArray <NSData*> *buffersWaitingToBeWritten;

@property (nonatomic, assign) NSInteger numStreamsFullyOpen;

/// A flag which gets turned ON when we make the async call to the delegate
/// to evaluate the TLS trust and turned OFF when the async call returns
/// or the socket state is reset.
/// TODO [kl] instead of having this separate boolean flag, it might be preferrable
/// to model this as a sub-state of `CLSocketStateSecuring`
@property (nonatomic, assign) BOOL waitingForTrustEvaluationResult;

@end


@implementation CLSocket

- (instancetype)init
{
  self = [super init];
  self.state = CLSocketStateDisconnected;
  self.useTLS = YES;
  return self;
}

- (void)dealloc
{
  [self.connectTimer invalidate];
  [self destroyStreams];
}

- (void)destroyStreams
{
  [self.inputStream close];
  [self.outputStream close];
  
  [self.inputStream removeFromRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
  [self.outputStream removeFromRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
  
  self.inputStream = nil;
  self.outputStream = nil;
}

- (void)setState:(CLSocketState)state
{
  if (_state == state)
    return;

  switch (state) {
    case CLSocketStateDisconnected:
      NSAssert(_state == CLSocketStateConnecting || _state == CLSocketStateSecuring || _state == CLSocketStateConnected, @"bad disconnect transition");
      LogNetVerbose(@"Transitioned to DISCONNECTED state");
      break;

    case CLSocketStateConnecting:
      NSAssert(_state == CLSocketStateDisconnected, @"bad connecting transition");
      LogNetVerbose(@"Transitioned to CONNECTING state");
      break;
    
    case CLSocketStateSecuring:
      NSAssert(_state == CLSocketStateConnecting, @"bad securing transition");
      LogNetVerbose(@"Transitioned to SECURING state");
      break;
      
    case CLSocketStateConnected:
      if (self.useTLS)
        NSAssert(_state == CLSocketStateSecuring, @"bad connected transition");
      else
        NSAssert(_state == CLSocketStateConnecting, @"bad connected transition (TLS bypass)");
      LogNetVerbose(@"Transitioned to CONNECTED state");
      break;
  }
  
  _state = state;
}

#pragma mark - Connect/Disconnect

- (BOOL)connectToHost:(NSString *)hostname onPort:(NSInteger)port error:(NSError **)errPtr
{
  self.buffersWaitingToBeWritten = [NSMutableArray array];
  self.writeBufferOffset = 0;
  self.writeBufferExhausted = YES;
  self.numStreamsFullyOpen = 0;
  self.inputHasBytesAvailable = NO;
  self.waitingForTrustEvaluationResult = NO;
  
  CFStringRef host = (__bridge CFStringRef)hostname;
  
  // create the bi-directional socket streams
  CFReadStreamRef cfReadStream;
  CFWriteStreamRef cfWriteStream;
  CFStreamCreatePairWithSocketToHost(NULL, host, (UInt32)port, &cfReadStream, &cfWriteStream);
  self.inputStream = (__bridge_transfer NSInputStream*)cfReadStream;
  self.outputStream = (__bridge_transfer NSOutputStream*)cfWriteStream;
  
  // handle failure
  if (!self.inputStream || !self.outputStream)
  {
    if (errPtr)
      *errPtr = [NSError errorWithDomain:CLSocketErrorDomain code:CLSocketErrorOther userInfo:nil];
    return NO;
  }
  
  [self.inputStream setDelegate:self];
  [self.outputStream setDelegate:self];
  [self.inputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
  [self.outputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
  
  // Configure TLS
  if (self.useTLS)
  {
    LogNetVerbose(@"using TLS");
    [self.inputStream setProperty:NSStreamSocketSecurityLevelNegotiatedSSL forKey:NSStreamSocketSecurityLevelKey];
    [self.outputStream setProperty:NSStreamSocketSecurityLevelNegotiatedSSL forKey:NSStreamSocketSecurityLevelKey];
    
    // Disable the standard TLS trust evaluation: we will manually do it after the stream is activated
    // see Apple Tech Note 2232: https://developer.apple.com/library/ios/technotes/tn2232
    CFDictionaryRef sslSettings = (__bridge CFDictionaryRef)@{(__bridge NSString*)kCFStreamSSLValidatesCertificateChain : @NO};
    CFReadStreamSetProperty(cfReadStream, kCFStreamPropertySSLSettings, sslSettings);
    CFWriteStreamSetProperty(cfWriteStream, kCFStreamPropertySSLSettings, sslSettings);
  }
  else
  {
    LogNetVerbose(@"TLS bypassed");
    // Normally we always want TLS on, but when running the localhost configuration
    // it's necessary to be able to disable TLS.
  }
  
  [self.inputStream open];
  [self.outputStream open];
  
  self.connectTimer = [NSTimer scheduledTimerWithTimeInterval:30.0 target:self selector:@selector(connectTimedOut:) userInfo:nil repeats:NO];
  
  self.state = CLSocketStateConnecting;
  return YES;
}

- (void)setConnectTimer:(NSTimer *)connectTimer
{
  if (_connectTimer)
  {
    [_connectTimer invalidate];
    _connectTimer = connectTimer;
  }
}

- (void)connectTimedOut:(NSTimer *)timer
{
  if (self.state == CLSocketStateConnecting || self.state == CLSocketStateSecuring)
  {
    LogNetVerbose(@"connect timed out");
    NSError *error = [NSError errorWithDomain:CLSocketErrorDomain code:CLSocketErrorTimeout userInfo:nil];
    [self disconnectWithError:error];
  }
}

- (BOOL)isDisconnected
{
  return self.state == CLSocketStateDisconnected;
}

- (void)disconnect
{
  LogNetVerbose(@"locally-initiated disconnect");
  // the client initiated the disconnect
  NSDictionary *userInfo = nil;
  NSError *error = [NSError errorWithDomain:CLSocketErrorDomain code:CLSocketErrorNone userInfo:userInfo];
  [self disconnectWithError:error];
}

- (void)disconnectWithError:(NSError *)error
{
  if (self.state == CLSocketStateDisconnected)
  {
    LogNetVerbose(@"early return from -disconnectWithError:");
    return;
  }
  
  LogNetVerbose(@"disconnect with err %@: %@", @(error.code), [error localizedDescription]);

  [self destroyStreams];
  
  self.buffersWaitingToBeWritten = nil;
  self.writeBufferExhausted = YES;
  self.writeBufferOffset = 0;
  self.numStreamsFullyOpen = 0;
  self.inputHasBytesAvailable = NO;
  self.waitingForTrustEvaluationResult = NO;
  
  if (!error)
  {
    NSDictionary *userInfo = nil;
    error = [NSError errorWithDomain:CLSocketErrorDomain code:CLSocketErrorOther userInfo:userInfo];
  }
  
  self.state = CLSocketStateDisconnected;
  [self.delegate socketDidDisconnect:self withError:error];
}

#pragma mark - Write

- (void)writeData:(NSData *)data
{
  NSAssert(self.state == CLSocketStateConnecting || self.state == CLSocketStateSecuring || self.state == CLSocketStateConnected, @"invalid state");
  LogNetVerbose(@"writeData:");
  
  [self.buffersWaitingToBeWritten addObject:data];
  
  if (self.writeBufferExhausted)
    [self writeToSocket];
}

- (void)writeToSocket
{
  if ( ! (self.outputStream.streamStatus == NSStreamStatusOpen
          || self.outputStream.streamStatus == NSStreamStatusWriting))
  {
    LogNetVerbose(@"writeToSocket: output stream is not yet ready");
    return;
  }
  
  // (1) Get the current buffer
  NSData *buffer = self.buffersWaitingToBeWritten.firstObject;
  if (!buffer)
  {
    LogNetVerbose(@"exhausted the write buffer");
    self.writeBufferExhausted = YES;
    return;
  }
  self.writeBufferExhausted = NO;
  
  // (2) Advance to the position in the buffer from which to write the next chunk
  uint8_t *rawBytes = (uint8_t*)buffer.bytes;
  rawBytes += self.writeBufferOffset;
  
  // (3) Write a chunk
  const NSInteger maxChunkLength = 2048;
  NSInteger numBytesRemainingInTheBuffer = buffer.length - self.writeBufferOffset;
  NSInteger chunkLength = MIN(numBytesRemainingInTheBuffer, maxChunkLength);
  NSInteger numBytesWritten = [self.outputStream write:rawBytes maxLength:chunkLength];
  
  // (4) Check for write error
  if (numBytesWritten == -1)
  {
    [self handleWriteError:self.outputStream.streamError];
    return;
  }
  
  // (5) Move the buffer pointer past the chunk that we just wrote.
  //     If the pointer moves past the end of the buffer,
  //     remove the buffer from the queue and reset the pointer to zero.
  if (numBytesWritten < numBytesRemainingInTheBuffer)
  {
    self.writeBufferOffset += numBytesWritten;
  }
  else
  {
    LogNetVerbose(@"advancing to the next queued buffer");
    self.writeBufferOffset = 0;
    [self.buffersWaitingToBeWritten removeObjectAtIndex:0];
  }
}

- (void)handleWriteError:(NSError *)error
{
  // Determine if the error should be logged as a warning or a "real" error
  NSError *normalizedError;
  BOOL isBrokenPipe = ([error.domain isEqualToString:NSPOSIXErrorDomain]
                       && error.code == EPIPE);
  if (isBrokenPipe)
  {
    // Treat broken pipe as a warning since it is very common on iOS after process suspension
    LogNetWarn(@"write failed, broken pipe");
    normalizedError = [NSError errorWithDomain:CLSocketErrorDomain code:CLSocketErrorClosed userInfo:nil];
  }
  else
  {
    // All other errors are "real" errors and must be logged accordingly
    LogNetError(@"write failed, error=%@", error);
    normalizedError = error;
  }
  
  // Finish the disconnect process
  [self disconnectWithError:normalizedError];
}

#pragma mark - Read

- (void)readFromSocket
{
  if (!self.inputHasBytesAvailable)
  {
    LogNetVerbose(@"readFromSocket: early return to avoid blocking");
    return;
  }
  
  const NSUInteger rawLength = 2048;
  uint8_t rawBytes[rawLength];
  
  NSInteger numBytesRead = [self.inputStream read:rawBytes maxLength:rawLength];
  self.inputHasBytesAvailable = NO;
  if (numBytesRead < 0)
  {
    LogNetError(@"read failed, error=%@", self.inputStream.streamError);
  }
  else if (numBytesRead == 0)
  {
    LogNetVerbose(@"read reached the end of the buffer");
    NSError *error = [NSError errorWithDomain:CLSocketErrorDomain code:CLSocketErrorClosed userInfo:nil];
    [self disconnectWithError:error];
  }
  else
  {
    LogNetVerbose(@"read %@ bytes", @(numBytesRead));
    NSData *data = [NSData dataWithBytes:rawBytes length:numBytesRead];
    [self.delegate socketDidReadData:data];
  }
}

- (void)evaluateTrust:(NSStream *)stream
{
  LogNetVerbose(@"evaluating trust for stream %@", stream);
  NSParameterAssert(stream != NULL);
  __block SecTrustRef trust =
    (stream == self.inputStream)
      ? (SecTrustRef)CFReadStreamCopyProperty((__bridge CFReadStreamRef)self.inputStream, kCFStreamPropertySSLPeerTrust)
      : (SecTrustRef)CFWriteStreamCopyProperty((__bridge CFWriteStreamRef)self.outputStream, kCFStreamPropertySSLPeerTrust);
  
  if (trust == NULL)
  {
    LogNetError(@"Failed to get the TLS trust");
    NSError *error = [NSError errorWithDomain:CLSocketErrorDomain code:CLSocketErrorInsecure userInfo:nil];
    [self disconnectWithError:error];
    return;
  }
  
  self.waitingForTrustEvaluationResult = YES;
  
  [self.delegate socket:self didReceiveTrust:trust completionHandler:^(BOOL shouldTrustPeer) {
    dispatch_async(dispatch_get_main_queue(), ^{
      
      CFRelease(trust);
      trust = NULL;
      
      if (!self.waitingForTrustEvaluationResult)
      {
        LogNetInfo(@"The socket is no longer waiting for the result of trust evaluation; ignoring the result");
        return;
      }
      
      self.waitingForTrustEvaluationResult = NO;
      
      if (!shouldTrustPeer)
      {
        LogNetError(@"TLS trust evaluation failed");
        NSError *error = [NSError errorWithDomain:CLSocketErrorDomain code:CLSocketErrorInsecure userInfo:nil];
        [self disconnectWithError:error];
      }
      else
      {
        LogNetVerbose(@"Socket is secure and fully connected");
        [self.connectTimer invalidate];
        self.connectTimer = nil;
        self.state = CLSocketStateConnected;
        [self.delegate socketDidConnect:self];
        
        // Ensure that any pending data is processed now
        [self writeToSocket];
        [self readFromSocket];
      }
    });
  }];
}

#pragma mark - NSStreamDelegate

- (void)stream:(NSStream * _Nonnull)theStream handleEvent:(NSStreamEvent)streamEvent
{
  NSAssert([NSThread isMainThread], @"must be scheduled on the main thread");
  NSString *whichStream = theStream == self.inputStream ? @"INPUT" : @"OUTPUT";
  
  switch (streamEvent) {
    case NSStreamEventOpenCompleted: {
      LogNetVerbose(@"%@ stream opened", whichStream);
      self.numStreamsFullyOpen++;
      if (self.numStreamsFullyOpen == 2)
      {
        if (self.useTLS)
        {
          LogNetVerbose(@"socket is connected: but not yet fully secured");
          self.state = CLSocketStateSecuring;
        }
        else
        {
          LogNetVerbose(@"socket is connected (TLS bypassed)");
          self.state = CLSocketStateConnected;
        }
      }
    } break;
      
    case NSStreamEventHasBytesAvailable: {
      NSAssert(theStream == self.inputStream, @"unexpected stream ready to read");
      LogNetVerbose(@"%@ stream has bytes available", whichStream);
      self.inputHasBytesAvailable = YES;
      
      if (self.state == CLSocketStateSecuring && !self.waitingForTrustEvaluationResult)
        [self evaluateTrust:theStream];
      
      if (self.state == CLSocketStateConnected)
        [self readFromSocket];
    } break;
    
    case NSStreamEventHasSpaceAvailable: {
      NSAssert(theStream == self.outputStream, @"unexpected stream ready to write");
      LogNetVerbose(@"%@ stream has space available", whichStream);
      if (self.state == CLSocketStateSecuring && !self.waitingForTrustEvaluationResult)
        [self evaluateTrust:theStream];
      
      if (self.state == CLSocketStateConnected)
        [self writeToSocket];
    } break;
      
    case NSStreamEventEndEncountered: {
      LogNetVerbose(@"%@ stream end", whichStream);
      NSError *error = [NSError errorWithDomain:CLSocketErrorDomain code:CLSocketErrorClosed userInfo:nil];
      [self disconnectWithError:error];
    } break;
    
    case NSStreamEventErrorOccurred: {
      LogNetWarn(@"%@ stream error", whichStream);
      [self disconnectWithError:theStream.streamError];
    } break;
    
    case NSStreamEventNone:
      break;
  }
}

@end
