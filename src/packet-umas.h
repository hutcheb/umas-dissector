/* packet-mbtcp.h
 *
 * Routines for Modbus/TCP dissection
 * By Riaan Swart <rswart@cs.sun.ac.za>
 * Copyright 2001, Institute for Applied Computer Science
 *                      University of Stellenbosch
 *
 * See http://www.modbus.org/ for information on Modbus/TCP.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#define PORT_UMAS        502    /* Modbus/TCP located on port 502, with IANA registration */

 /* return codes of function classifying packets as query/response */
#define QUERY_PACKET            0
#define RESPONSE_PACKET         1

/* UMAS protocol function codes */
#define INIT_COMM                   0x01
#define READ_ID                     0x02
#define READ_PROJECT_INFO           0x03
#define READ_PLC_INFO               0x04
#define READ_CARD_INFO              0x06
#define REPEAT                      0x0A
#define TAKE_PLC_RESERVATION        0x10
#define RELEASE_PLC_RESERVATION     0x11
#define KEEP_ALIVE                  0x12
#define READ_MEMORY_BLOCK           0x20
#define READ_VARIABLES              0x22
#define WRITE_VARIABLES             0x23
#define READ_COILS_REGISTERS        0x24
#define WRITE_COILS_REGISTERS       0x25
#define DATA_DICTIONARY             0x26
#define INITIALIZE_UPLOAD           0x30
#define UPLOAD_BLOCK                0x31
#define END_STRATEGY_UPLOAD         0x32
#define INITIALIZE_DOWNLOAD         0x33
#define DOWNLOAD_BLOCK              0x34
#define END_STRATEGY_DOWNLOAD       0x35
#define READ_ETH_MASTER_DATA        0x39
#define START_PLC                   0x40
#define STOP_PLC                    0x41
#define MONITOR_PLC                 0x50
#define CHECK_PLC                   0x58
#define READ_IO_OBJECT              0x70
#define WRITE_IO_OBJECT             0x71
#define GET_STATUS_MODULE           0x73
#define RESPONSE_OK                 0xFE
#define RESPONSE_ERROR              0xFD

typedef struct {
    uint32_t req_frame_num;
    uint8_t function_code;
} umas_request_info_t;


typedef struct {
    int     packet_type;
    uint8_t pairing_key;      /* Set to zero if not available */
    uint8_t function_code;    /* Set to zero if not available */
} umas_data_t;

/* List contains request data  */
typedef struct {
    wmem_list_t* umas_request_frame_data;
} umas_conversation;

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
