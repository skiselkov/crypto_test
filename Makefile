#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://opensource.org/licenses/CDDL-1.0
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

UTSBASE	= /code/illumos-gate/usr/src/uts

MODULE		= crypto_test
OBJECTS		= crypto_test.o
LINTS		= $(OBJECTS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_CRYPTO_DIR)/$(MODULE)
ROOTLINK	= $(ROOT_MISC_DIR)/$(MODULE)

include $(UTSBASE)/intel/Makefile.intel

ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOTLINK)

LDFLAGS += -dy
# -Ncrypto/cmac

.KEEP_STATE:

def:		$(DEF_DEPS)
all:		$(ALL_DEPS)
clean:		$(CLEAN_DEPS)
clobber:	$(CLOBBER_DEPS)
lint:		$(LINT_DEPS)
modlintlib:	$(MODLINTLIB_DEPS)
clean.lint:	$(CLEAN_LINT_DEPS)
install:	$(INSTALL_DEPS)

$(ROOTLINK):	$(ROOT_MISC_DIR) $(ROOTMODULE)
	-$(RM) $@; ln $(ROOTMODULE) $@

#
#	Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ

CTFMERGE	= true
