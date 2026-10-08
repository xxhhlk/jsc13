ARCHS = arm64 arm64e
TARGET = iphone:clang:14.5:13.0
DEBUG = 0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = jsc13
jsc13_FILES = Tweak.x
jsc13_FRAMEWORKS = Foundation
jsc13_LIBRARIES = substrate

include $(THEOS_MAKE_PATH)/tweak.mk
