#############################################################################
# Name:                                                                     #
#   host.mak                                                                #
#                                                                           #
# Description:                                                              #
#   Linux Host side skeleton y4tk sample makefile                           # 
#                                                                           #
# Usage:                                                                    #
#   make -f host.mak DEBUG=[y/n]                                            #
#   Example:  make -f host.mak DEBUG=y (to debug the host-side application) #
#                                                                           #
# Prerequisites:                                                            # 
#   Several environment variables must be set to use this makefile          #
#   They are described below                                                #
#                                                                           #
#   Y4TK_FS_ROOT  - must be set to root of y4tk                             #
#                                                                           #
#############################################################################

# Verify that Y4TK_FS_ROOT is set before attempting to compile
ifndef Y4TK_FS_ROOT
$(error Error. Environment variable Y4TK_FS_ROOT must be defined)
endif

# Simple sanity check to see if Y4TK_FS_ROOT is reasonably set
VALID_Y4TK_FS_ROOT=$(shell if test -e \
                           $(Y4TK_FS_ROOT)/samples/makefiles/toolkit_host_checks.inc ; \
                           then echo y ; fi)

# Abort if the Y4TK_FS_ROOT value does not point to a toolkit installation
ifneq ($(VALID_Y4TK_FS_ROOT),y)
$(error Error. Y4TK_FS_ROOT is set to $(Y4TK_FS_ROOT), but this \
        does not appear to be a valid toolkit root)
endif

#inference rules
all: check_prereqs sampleHostApp

# Include common build definitions and rules
include $(Y4TK_FS_ROOT)/samples/makefiles/toolkit_samples.inc

# Include another set of sanity checks 
include $(Y4TK_FS_ROOT)/samples/makefiles/toolkit_host_checks.inc

# Specify user-specific host includes
HOST_USER_INCLUDES=-I $(Y4TK_FS_ROOT)/samples/toolkit/skeleton/include \
                   -I$(Y4TK_FS_ROOT)/samples/toolkit/skeleton/host

# Objects to make 
HOST_OBJS = skelhost.o skelmenu.o hostUtils.o  \
       adptHost.o modHost.o rngHost.o hshHost.o sharedUtils.o     \
       desHost.o limHost.o pkaHost.o util.o aesHost.o

util.o : ../../../rte/shared/util.c   
	$(HOST_COMPILE)

skelhost.o : ../skelhost.c   
	$(HOST_COMPILE)

skelmenu.o : ../skelmenu.c ../skelmenu.h  
	$(HOST_COMPILE)

sharedUtils.o : ../../utils/sharedUtils.c
	$(HOST_COMPILE)

desHost.o : ../desHost.c
	$(HOST_COMPILE)

hshHost.o : ../hshHost.c 
	$(HOST_COMPILE)

limHost.o : ../limHost.c 
	$(HOST_COMPILE)

modHost.o : ../modHost.c
	$(HOST_COMPILE)

pkaHost.o : ../pkaHost.c
	$(HOST_COMPILE)

adptHost.o : ../adptHost.c
	$(HOST_COMPILE)

aesHost.o : ../aesHost.c
	$(HOST_COMPILE)

rngHost.o : ../rngHost.c
	$(HOST_COMPILE)

hostUtils.o : ../../utils/hostUtils.c
	$(HOST_COMPILE)

sampleHostApp : $(HOST_OBJS)
	$(HOST_LINK)

clean:
	$(HOST_CLEAN)
