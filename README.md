# CLSocket

A simple alternative to GCDAsyncSocket for TCP *client* connections.

## Overview

The main advantage over GCDAsyncSocket is that it uses higher-level socket API (CFSocketStream) which provides improved dual-stack IPv6 support.

A demo app is included that demonstrates how to use it as an HTTP client (you wouldn't normally use this library as an HTTP client, but it is a simple, familiar concept).

## Known Limitations:

While CLSocket supports TLS, it *only* supports manual trust evaluation.
