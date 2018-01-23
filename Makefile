DYLIBS=bfdecrypt.dylib
BINARY_NAME=bfinject4realz
BFINJECT_SRC=bfinject4realz.mm
LORGNETTE_SRC=lorgnette.m
OBJS=$(addsuffix .o,$(basename $(BFINJECT_SRC))) \
	$(addsuffix .o,$(basename $(LORGNETTE_SRC))) 

SDK=$(shell xcodebuild -showsdks| grep iphoneos | awk '{print $$4}')
SDK_PATH=$(shell xcrun --sdk $(SDK) --show-sdk-path)

CC=$(shell xcrun --sdk $(SDK) --find clang)
CXX=$(shell xcrun --sdk $(SDK) --find clang++)
LD=$(CXX)
INCLUDES=-I $(SDK_PATH)/usr/include
ARCHS=-arch arm64

IOS_FLAGS=-isysroot $(SDK_PATH) -miphoneos-version-min=11.0
CFLAGS=$(IOS_FLAGS) -g $(ARCHS) $(INCLUDES) -Wdeprecated-declarations
CXXFLAGS=$(IOS_FLAGS) -g $(ARCHS) $(INCLUDES) -Wdeprecated-declarations

FRAMEWORKS=-framework CoreFoundation -framework IOKit -framework Foundation -framework JavaScriptCore -framework UIKit -framework Security -framework CFNetwork -framework CoreGraphics
LIBS=-lobjc -L$(SDK_PATH)/usr/lib -lz -lsqlite3 -lxml2 -lz -ldl -lSystem #$(SDK_PATH)/usr/lib/libstdc++.tbd 
LDFLAGS=$(IOS_FLAGS) $(ARCHS) $(FRAMEWORKS) $(LIBS)  -ObjC -all_load
MAKE=$(shell xcrun --sdk $(SDK) --find make)

DEVELOPERID=$(shell security find-identity -v -p codesigning | grep "iPhone Developer:" |awk '{print $$2}')

all: $(BINARY_NAME) finish
	
$(BINARY_NAME): $(OBJS)
	$(LD) $(LDFLAGS) $^ -o $@

finish:
	tar cf bfinject.tar bfinject bfinject4realz dylibs/

%.o: %.mm $(DEPS)
	$(CXX) -c $(CXXFLAGS) $< -o $@

%.o: %.c $(DEPS)
	$(CC) -c $(CFLAGS) $< -o $@

webroot.o: webroot.c

clean:
	rm -f $(OBJS) 2>&1 > /dev/null
	rm -f $(BINARY_NAME) 2>&1 > /dev/null
	
