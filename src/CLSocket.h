/*
The MIT License (MIT)
Copyright (c) 2016 Microsoft Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

@import Foundation;

//! Project version number for CLSocket.
FOUNDATION_EXPORT double CLSocketVersionNumber;

//! Project version string for CLSocket.
FOUNDATION_EXPORT const unsigned char CLSocketVersionString[];

@class CLSocket;

extern NSString *CLSocketErrorDomain;

typedef NS_ENUM(NSUInteger, CLSocketError) {
  
  /// No error. For instance, if the app asks CLSocket to disconnect, CLSocket will
  /// use this "error" code as the parameter to the did-disconnect delegate method.
  CLSocketErrorNone = 0,
  
  /// The socket failed to connect within the allotted timeout
  CLSocketErrorTimeout,
  
  /// The socket is no longer open
  CLSocketErrorClosed,
  
  /// The socket failed to create a secure TLS connection to the origin server.
  CLSocketErrorInsecure,
  
  /// The socket encountered some other/unknown error
  CLSocketErrorOther,
};


@protocol CLSocketDelegate <NSObject>

- (void)socket:(CLSocket *)socket didReceiveTrust:(SecTrustRef)trust completionHandler:(void (^)(BOOL shouldTrustPeer))completionHandler;

- (void)socketDidConnect:(CLSocket *)socket;

- (void)socketDidDisconnect:(CLSocket *)socket withError:(NSError *)error;

- (void)socketDidReadData:(NSData *)data;

@end


@interface CLSocket : NSObject

@property (nonatomic, readwrite, weak) id<CLSocketDelegate> delegate;
@property (nonatomic, readonly, assign) BOOL isDisconnected;
@property (nonatomic, readwrite) BOOL useTLS; /// default is YES

- (BOOL)connectToHost:(NSString *)hostname onPort:(NSInteger)port error:(NSError **)errPtr;

- (void)disconnect;

- (void)writeData:(NSData *)data;

@end
