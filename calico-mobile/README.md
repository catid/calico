## Calico Portable Build
#### Strong, Fast, and Portable Authenticated Encryption

See the full documentation at [https://github.com/catid/calico](https://github.com/catid/calico).

#### Quick Setup

To quickly evaluate Calico for your application, just include the files in this
folder and use the API described in "calico.h".

To best incorporate Calico, edit the Makefile to build for your target and link
the static library to your application.

Optimized builds can be 2.5x faster by taking advantage of SIMD operations
available on the processor, so for large-scale applications it may be worth
the time to get the normal builds working rather than taking the shortcut
offered by this version of the code.

#### XCode/iOS

Just add the files to your project and #import "calico.h".

#### Android

Just add the files to your Android.mk and #include "calico.h".

