/*
 * linux/can/bcm.h
 *
 * Definitions for CAN Broadcast Manager (BCM)
 *
 * Author: Oliver Hartkopp <oliver.hartkopp@volkswagen.de>
 * Copyright (c) 2002-2007 Volkswagen Group Electronic Research
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Volkswagen nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * Alternatively, provided that this notice is retained in full, this
 * software may be distributed under the terms of the GNU General
 * Public License ("GPL") version 2, in which case the provisions of the
 * GPL apply INSTEAD OF those given above.
 *
 * The provided data structures and external interfaces from this code
 * are not restricted to be used by modules with a GPL compatible license.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#ifndef _UAPI_CAN_BCM_H
#define _UAPI_CAN_BCM_H

#include <linux/types.h>
#include <linux/can.h>

struct bcm_msg_head {
	__u32 opcode;
	__u32 flags;
	__u32 count;
	struct timeval ival1, ival2;
	canid_t can_id;
	__u32 nframes;
	struct can_frame frames[0];
};

enum {
	TX_SETUP = 1,	
	TX_DELETE,	
	TX_READ,	
	TX_SEND,	
	RX_SETUP,	
	RX_DELETE,	
	RX_READ,	
	TX_STATUS,	
	TX_EXPIRED,	
	RX_STATUS,	
	RX_TIMEOUT,	
	RX_CHANGED	
};

#define SETTIMER            0x0001
#define STARTTIMER          0x0002
#define TX_COUNTEVT         0x0004
#define TX_ANNOUNCE         0x0008
#define TX_CP_CAN_ID        0x0010
#define RX_FILTER_ID        0x0020
#define RX_CHECK_DLC        0x0040
#define RX_NO_AUTOTIMER     0x0080
#define RX_ANNOUNCE_RESUME  0x0100
#define TX_RESET_MULTI_IDX  0x0200
#define RX_RTR_FRAME        0x0400

#endif 
