This is a part of custom SHARP device flashing tools.

https://blog.tewi.love/?p=135

Cross compile for Windows:
1. Install mingw-w64 and cross compile openssl, libusb-1.0.
2. CC=i686-w64-mingw32-gcc CFLAGS="-I/opt/mingw/openssl-1.0.2h/include -I/opt/mingw/libusb-1.0/include" LDFLAGS="-L/opt/mingw/openssl-1.0.2h/lib -L/opt/mingw/libusb-1.0/lib" ./configure --enable-static --host=i686-w64-mingw32-
