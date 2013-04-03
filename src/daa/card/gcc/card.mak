#############################################################################
# Name:                                                                     #
#   card.mak                                                                #
#                                                                           #
# Description:                                                              #
#   Makefile for card side code for skeleton y4tk sample                    #
#                                                                           #
# Usage:                                                                    #
#   make -f card.mak DEBUG=[y/n]                                            #
#   Example:  make -f card.mak DEBUG=y (to debug the card-side application) #
#                                                                           #
# Prerequisites:                                                            # 
#   Several environment variables must be set to use this makefile          #
#   They are described below                                                #
#                                                                           #
#   Y4TK_FS_ROOT  - must be set to root of y4tk                             #
#   CROSS         - must point to the root directory for the cross compiler #
#   GCC_NAME      - must be set to the prefix of the cross gcc              # 
#                                                                           #
# Note: Card side applications can not be compiled with native              #
#       (host side) gcc -- gcc must have been specially configured and      #
#                          built to target a PPC405 environment             #
#############################################################################
include $(Y4TK_FS_ROOT)/samples/makefiles/toolkit_samples.inc

# inference rules
all: sampleCardApp

# user-specific includes
CARD_USER_INCLUDES=-I../../include
# objects to make
CARD_OBJS=skelxc.o model.o sharedUtils.o rngserv.o adptserv.o hshserv.o \
     limserv.o desserv.o pkaserv.o aesserv.o
# Specify our own link options
CARD_USER_LINK_OPTIONS=-lpthread

skelxc.o : ../skelxc.c 
	$(CARD_COMPILE)

sharedUtils.o : ../../utils/sharedUtils.c
	$(CARD_COMPILE)

adptserv.o : ../../adptserv/adptserv.c
	$(CARD_COMPILE)

model.o : ../../model/model.c
	$(CARD_COMPILE)

rngserv.o : ../../rngserv/rngserv.c 
	$(CARD_COMPILE)

aesserv.o : ../../aesserv/aesserv.c 
	$(CARD_COMPILE)

hshserv.o : ../../hshserv/hshserv.c
	$(CARD_COMPILE)

limserv.o : ../../limserv/limserv.c
	$(CARD_COMPILE)

desserv.o : ../../desserv/desserv.c
	$(CARD_COMPILE)

pkaserv.o : ../../pkaserv/pkaserv.c
	$(CARD_COMPILE)

sampleCardApp : $(CARD_OBJS)
	$(CARD_LINK)

clean: 
	$(CARD_CLEAN)
