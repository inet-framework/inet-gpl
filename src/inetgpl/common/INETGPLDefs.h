//
// Copyright (C) 2004 OpenSim Ltd.
//
// SPDX-License-Identifier: GPL-3.0-or-later
//

#ifndef __INETGPL_INETDEFS_H
#define __INETGPL_INETDEFS_H

// precompiled headers must be included first
#ifdef NDEBUG
#include "inetgpl/common/precompiled_release.h"
#else
#include "inetgpl/common/precompiled_debug.h"
#endif

#include "inet/common/INETDefs.h"

#if INET_VERSION < 0x0404
#  error At least INET version 4.4 required
#endif

// important INET_WITH_* macros defined by OMNET
#include "inetgpl/opp_defines.h"

// feature defines generated based on the actual feature enablement
#include "inetgpl/features.h"

//
// General definitions.
//

namespace inetgpl {
using namespace omnetpp;
using namespace inet;
} // namespace inet

#if defined(INETGPL_EXPORT)
#define INETGPL_API          OPP_DLLEXPORT
#elif defined(INETGPL_IMPORT)
#define INETGPL_API          OPP_DLLIMPORT
#else // if defined(INETGPL_EXPORT)
#define INETGPL_API
#endif // if defined(INETGPL_EXPORT)

#endif

