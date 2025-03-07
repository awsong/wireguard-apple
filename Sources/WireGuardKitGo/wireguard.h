/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2018-2023 WireGuard LLC. All Rights Reserved.
 */

#ifndef WIREGUARD_H
#define WIREGUARD_H

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

typedef void(*logger_fn_t)(void *context, int level, const char *msg);
extern void wgSetLogger(void *context, logger_fn_t logger_fn);
//extern int wgTurnOn(const char *settings, int32_t tun_fd);

typedef void (*cb)(void*, const char*, const char*);
static void helper(cb f, void *userData, const char *x, const char *y) { f(userData,x,y); }
extern int wgTurnOn(cb ff, void* userData, const char* settings, int32_t tunFd);

extern void wgTurnOff(int handle);
extern int64_t wgSetConfig(int handle, const char *settings);
extern char *wgGetConfig(int handle);
extern void wgBumpSockets(int handle);
extern void wgDisableSomeRoamingForBrokenMobileSemantics(int handle);
extern const char *wgVersion();

#endif
