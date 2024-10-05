/* packet-mbtcp.c
 * Routines for UMAS dissection
 * By Ben Hutcheson <ben.hutche@gmail.com>
 * Copyright 2024, Ben Hutcheson
 *
 *
 *****************************************************************************************************
 * Some Helpful Info might go here
 *****************************************************************************************************
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/crc16-tvb.h> /* For CRC verification */
#include <epan/proto_data.h>
#include <epan/tfs.h>
#include <wsutil/array.h>
#include "packet-tcp.h"
#include "packet-mbtcp.h"
#include "packet-umas.h"

void proto_register_umas(void);
void proto_reg_handoff_modbus(void);

/* Initialize the protocol and registered fields */
static int proto_umas;
extern int proto_modbus;

/* Initialize the subtree pointers */
static int ett_umas;
static int ett_umas_hdr;
static int ett_umas_read_variable_list;
static int ett_umas_read_variable_list_item;
static int ett_umas_write_variable_list;
static int ett_umas_write_variable_list_item;

static expert_field ei_umas_data_decode;

static dissector_handle_t umas_handle;

static dissector_table_t   umas_data_dissector_table;
static dissector_table_t   umas_dissector_table;

static range_t* global_umas_func_code; /* Port 502, by default */

typedef struct {
    uint8_t function_code;
    int     register_format;
    uint16_t reg_base;
    uint16_t num_reg;
    uint32_t req_frame_num;
    nstime_t req_time;
    bool request_found;
} modbus_pkt_info_t;

static const value_string function_code_vals[] = {
    { INIT_COMM,                "Initialize a UMAS communication" },
    { READ_ID,                  "Request a PLC ID" },
    { READ_PROJECT_INFO,        "Read Project Information" },
    { READ_PLC_INFO,            "Get internal PLC Info" },
    { READ_CARD_INFO,           "Get internal PLC SD-Card Info" },
    { REPEAT,                   "Sends back data sent to the PLC (used for synchronization)" },
    { TAKE_PLC_RESERVATION,     "Assign an owner to the PLC" },
    { RELEASE_PLC_RESERVATION,  "Release the reservation of a PLC" },
    { KEEP_ALIVE,               "Keep alive message (???)" },
    { READ_MEMORY_BLOCK,        "Read a memory block of the PLC" },
    { READ_VARIABLES,           "Read System bits, System Words and Strategy variables" },
    { WRITE_VARIABLES,          "Write System bits, System Words and Strategy variables" },
    { READ_COILS_REGISTERS,     "Read coils and holding registers from PLC" },
    { WRITE_COILS_REGISTERS,    "Write coils and holding registers into PLC" },
    { DATA_DICTIONARY,          "Read Data Dictionary Data, Variables and Data Types" },
    { INITIALIZE_UPLOAD,        "Initialize Strategy upload (copy from engineering PC to PLC)" },
    { UPLOAD_BLOCK,             "Upload (copy from engineering PC to PLC) a strategy block to the PLC" },
    { END_STRATEGY_UPLOAD,      "Finish strategy Upload (copy from engineering PC to PLC)" },
    { INITIALIZE_DOWNLOAD,      "Initialize Strategy download (copy from PLC to engineering PC)" },
    { DOWNLOAD_BLOCK,           "Download (copy from PLC to engineering PC) a strategy block" },
    { END_STRATEGY_DOWNLOAD,    "Finish strategy Download (copy from PLC to engineering PC)" },
    { READ_ETH_MASTER_DATA,     "Read Ethernet Master Data" },
    { STOP_PLC,                 "Stops the PLC" },
    { MONITOR_PLC,              "Monitors variables, Systems bits and words" },
    { CHECK_PLC,                "Check PLC Connection status" },
    { READ_IO_OBJECT,           "Read IO Object" },
    { WRITE_IO_OBJECT,          "Write IO Object" },
    { GET_STATUS_MODULE,        "Get Status Module" },
    { RESPONSE_OK,              "Response Meaning OK" },
    { RESPONSE_ERROR,           "Response Meaning Error" },
    { 0,                        NULL }
};

static const value_string memory_block_id_type[] = {
    { RAM_CPU,                "PLC RAM" },
    { SD_CARD,                "SD Card" },
    { 0,                      NULL }
};


typedef struct {
    uint8_t function_code;
    int     register_format;
    uint16_t reg_base;
    uint16_t num_reg;
    uint32_t req_frame_num;
    nstime_t req_time;
    bool request_found;
} umas_pkt_info_t;

static int
classify_umas_packet(packet_info *pinfo, uint8_t function_code)
{
    /* see if nature of packets can be derived from src/dst ports */
    /* if so, return as found */
    /*                        */
    /* XXX Update Oct 2012 - It can be difficult to determine if a packet is a query or response; some way to track  */
    /* the Modbus/TCP transaction ID for each pair of messages would allow for detection based on a new seq. number. */
    /* Otherwise, we can stick with this method; a configurable port option has been added to allow for usage of     */
    /* user ports either than the default of 502.                                                                    */
    if ( (function_code == 0xFE) || (function_code == 0xFD))
        return RESPONSE_PACKET;
    return QUERY_PACKET;
}

/* Dissect the Modbus Payload.  Called from either Modbus/TCP or Modbus RTU Dissector */
static int
dissect_umas_pdu_request(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data, uint8_t function_code, int offset, umas_request_info_t* pkt_info)
{
    char item_name[100];
    int i;
    int current_offset = 0;

    switch (function_code) {
    case INIT_COMM:
        proto_tree_add_item_new(tree, proto_registrar_get_byname("umas.init.sub_code"), tvb, offset, 1, ENC_LITTLE_ENDIAN);
        break;
    case READ_ID:
        // Nothing to Dissect
        break;
    case READ_PROJECT_INFO:
        proto_tree_add_item_new(tree, proto_registrar_get_byname("umas.project_info.sub_code"), tvb, offset, 1, ENC_LITTLE_ENDIAN);
        break;
    case READ_PLC_INFO:
        // Nothing to Dissect
        break;
    case READ_MEMORY_BLOCK:
        int* umas_read_block_block_number = wmem_alloc(wmem_file_scope(), sizeof * umas_read_block_block_number);
        int* umas_read_block_offset = wmem_alloc(wmem_file_scope(), sizeof * umas_read_block_offset);

        proto_tree_add_item_new(tree, proto_registrar_get_byname("umas.read_block.range"), tvb, offset, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item_ret_uint(tree, proto_registrar_get_id_byname("umas.read_block.block_no"), tvb, offset + 1, 2, ENC_LITTLE_ENDIAN, umas_read_block_block_number);
        proto_tree_add_item_ret_uint(tree, proto_registrar_get_id_byname("umas.read_block.offset"), tvb, offset + 3, 2, ENC_LITTLE_ENDIAN, umas_read_block_offset);
        proto_tree_add_item_new(tree, proto_registrar_get_byname("umas.read_block.no_bytes"), tvb, offset + 7, 2, ENC_LITTLE_ENDIAN);

        pkt_info->block_no = *umas_read_block_block_number;
        pkt_info->offset = *umas_read_block_offset;
        break;
    case READ_VARIABLES:
        int* umas_read_variable_count = wmem_alloc(wmem_file_scope(), sizeof * umas_read_variable_count);
                        
        proto_tree_add_item_new(tree, proto_registrar_get_byname("umas.read_variable.crc"), tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item_ret_uint(tree, proto_registrar_get_id_byname("umas.read_variable.count"), tvb, offset + 4, 1, ENC_LITTLE_ENDIAN, umas_read_variable_count);
                
        proto_tree* variable_list_tree = proto_tree_add_subtree(tree, tvb, offset + 5, *umas_read_variable_count, ett_umas_read_variable_list, NULL, "Variable List");

        uint8_t umas_read_variable_dummy;
        proto_tree* variable_list_item_tree;
        
        uint16_t umas_read_variable_list_block_number;
        uint16_t umas_read_variable_list_base_offset;
        uint8_t umas_read_variable_list_offset;
        

        
        current_offset = offset + 5;
        for (i = 0; i < *umas_read_variable_count; ++i) {
            uint8_t umas_read_variable_list_buffer = tvb_get_uint8(tvb, current_offset);
            uint8_t umas_read_variable_list_is_array = umas_read_variable_list_buffer & 0xF0;
            uint8_t umas_read_variable_list_data_type_size = umas_read_variable_list_buffer & 0x0F;
            uint16_t umas_read_variable_list_block_number = tvb_get_uint16(tvb, current_offset + 1, ENC_LITTLE_ENDIAN);
            uint16_t umas_read_variable_list_base_offset = tvb_get_uint16(tvb, current_offset + 4, ENC_LITTLE_ENDIAN);
            uint8_t umas_read_variable_list_offset = tvb_get_uint8(tvb, current_offset + 6);

            int packet_size = 7;
            if (umas_read_variable_list_is_array != 0) {
                packet_size = 9;
            }
            sprintf(item_name, "Address %d,%d - Symbol %s", umas_read_variable_list_block_number, umas_read_variable_list_base_offset + umas_read_variable_list_offset, "TODO:- Tag Name Please");
            variable_list_item_tree = proto_tree_add_subtree(variable_list_tree, tvb, current_offset, packet_size, ett_umas_read_variable_list_item, NULL, item_name);

            proto_tree_add_uint(variable_list_item_tree, proto_registrar_get_id_byname("umas.read_variable.list.is_array"), tvb, current_offset, 1, umas_read_variable_list_is_array);
            proto_tree_add_uint(variable_list_item_tree, proto_registrar_get_id_byname("umas.read_variable.list.data_type_size_index"), tvb, current_offset, 1, umas_read_variable_list_data_type_size);
            proto_tree_add_uint(variable_list_item_tree, proto_registrar_get_id_byname("umas.read_variable.list.block_no"), tvb, current_offset + 1, 2, umas_read_variable_list_block_number);
            proto_tree_add_uint(variable_list_item_tree, proto_registrar_get_id_byname("umas.read_variable.list.base_offset"), tvb, current_offset + 4, 2, umas_read_variable_list_base_offset);
            proto_tree_add_uint(variable_list_item_tree, proto_registrar_get_id_byname("umas.read_variable.list.offset"), tvb, current_offset + 6, 1, umas_read_variable_list_offset);
                       
            if (umas_read_variable_list_is_array != 0) {
                proto_tree_add_item_new(variable_list_item_tree, proto_registrar_get_byname("umas.read_variable.list.array_length"), tvb, current_offset + 7, 2, ENC_LITTLE_ENDIAN);
            }
            current_offset += packet_size;
        }
        break;
    case WRITE_VARIABLES:
        int* umas_write_variable_count = wmem_alloc(wmem_file_scope(), sizeof * umas_write_variable_count);

        proto_tree_add_item_new(tree, proto_registrar_get_byname("umas.write_variable.crc"), tvb, offset, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item_ret_uint(tree, proto_registrar_get_id_byname("umas.write_variable.count"), tvb, offset + 4, 1, ENC_LITTLE_ENDIAN, umas_write_variable_count);

        proto_tree* write_variable_list_tree = proto_tree_add_subtree(tree, tvb, offset + 5, *umas_write_variable_count, ett_umas_write_variable_list, NULL, "Variable List");

        uint8_t umas_write_variable_dummy;
        proto_tree* write_variable_list_item_tree;

        uint16_t umas_write_variable_list_block_number;
        uint16_t umas_write_variable_list_base_offset;
        uint8_t umas_write_variable_list_offset;


        current_offset = offset + 5;
        for (i = 0; i < *umas_write_variable_count; ++i) {
            uint8_t umas_write_variable_list_buffer = tvb_get_uint8(tvb, current_offset);
            uint8_t umas_write_variable_list_is_array = umas_write_variable_list_buffer & 0xF0;
            uint8_t umas_write_variable_list_data_type_size = umas_write_variable_list_buffer & 0x0F;
            uint16_t umas_write_variable_list_block_number = tvb_get_uint16(tvb, current_offset + 1, ENC_LITTLE_ENDIAN);
            uint16_t umas_write_variable_list_base_offset = tvb_get_uint16(tvb, current_offset + 3, ENC_LITTLE_ENDIAN);
            uint8_t umas_write_variable_list_offset = tvb_get_uint8(tvb, current_offset + 5);
            

            int packet_size = 7;
            sprintf(item_name, "Address %d,%d - Symbol %s", umas_write_variable_list_block_number, umas_write_variable_list_base_offset + umas_write_variable_list_offset, "TODO:- Tag Name Please");
            write_variable_list_item_tree = proto_tree_add_subtree(write_variable_list_tree, tvb, current_offset, packet_size, ett_umas_write_variable_list_item, NULL, item_name);

            proto_tree_add_uint(write_variable_list_item_tree, proto_registrar_get_id_byname("umas.write_variable.list.is_array"), tvb, current_offset, 1, umas_write_variable_list_is_array);
            proto_tree_add_uint(write_variable_list_item_tree, proto_registrar_get_id_byname("umas.write_variable.list.data_type_size_index"), tvb, current_offset, 1, umas_write_variable_list_data_type_size);
            proto_tree_add_uint(write_variable_list_item_tree, proto_registrar_get_id_byname("umas.write_variable.list.block_no"), tvb, current_offset + 1, 2, umas_write_variable_list_block_number);
            proto_tree_add_uint(write_variable_list_item_tree, proto_registrar_get_id_byname("umas.write_variable.list.base_offset"), tvb, current_offset + 3, 2, umas_write_variable_list_base_offset);
            proto_tree_add_uint(write_variable_list_item_tree, proto_registrar_get_id_byname("umas.write_variable.list.offset"), tvb, current_offset + 5, 2, umas_write_variable_list_offset);
            proto_tree_add_item(write_variable_list_item_tree, proto_registrar_get_id_byname("umas.write_variable.list.data"), tvb, current_offset + 7, umas_write_variable_list_data_type_size, ENC_NA);
                        
            current_offset += packet_size + umas_write_variable_list_data_type_size;
        }
        break;
    case DATA_DICTIONARY:
        uint16_t umas_data_dictionary_record_type = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
        uint16_t umas_data_dictionary_hardware_id = tvb_get_uint32(tvb, offset + 3, ENC_LITTLE_ENDIAN);
        uint16_t umas_data_dictionary_block_number = tvb_get_uint16(tvb, offset + 7, ENC_LITTLE_ENDIAN);
        
        pkt_info->record_type = umas_data_dictionary_record_type;
        pkt_info->block_no = umas_data_dictionary_block_number;
        
        proto_tree_add_uint(tree, proto_registrar_get_id_byname("umas.data_dictionary.record_type"), tvb, offset, 2, umas_data_dictionary_record_type);
        proto_tree_add_item_new(tree, proto_registrar_get_byname("umas.data_dictionary.index"), tvb, offset + 2, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_uint(tree, proto_registrar_get_id_byname("umas.data_dictionary.hardware_id"), tvb, offset + 3, 4, umas_data_dictionary_hardware_id);
        proto_tree_add_uint(tree, proto_registrar_get_id_byname("umas.data_dictionary.block_no"), tvb, offset + 7, 2, umas_data_dictionary_block_number);

        if (umas_data_dictionary_block_number == 0xFFFF) {
            uint16_t umas_data_dictionary_offset = tvb_get_uint16(tvb, offset + 8, ENC_LITTLE_ENDIAN);
            pkt_info->offset = umas_data_dictionary_offset;
            proto_tree_add_uint(tree, proto_registrar_get_id_byname("umas.data_dictionary.offset"), tvb, offset + 9, 2, umas_data_dictionary_offset);
        }
        break;
    default:
        break;
    };
    return tvb_captured_length(tvb);
}

/* Dissect the Modbus Payload.  Called from either Modbus/TCP or Modbus RTU Dissector */
static int
dissect_umas_pdu_response(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data, uint8_t function_code, int offset, umas_request_info_t*  pkt_info)
{
    int i = 0;

    switch (function_code) {
    case INIT_COMM:
        uint16_t max_frame_size = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
        uint16_t firmware_version = tvb_get_uint16(tvb, offset + 2, ENC_LITTLE_ENDIAN);
        uint32_t internal_code = tvb_get_uint32(tvb, offset + 8, ENC_LITTLE_ENDIAN);
        uint8_t hostname_length = tvb_get_uint8(tvb, offset + 12);
        const char* hostname = (char*)tvb_get_string_enc(wmem_file_scope(), tvb, offset + 13, hostname_length, ENC_UTF_8);

        proto_tree_add_uint(tree, proto_registrar_get_id_byname("umas.init_comms.max_frame_size"), tvb, offset, 2, max_frame_size);
        proto_tree_add_uint(tree, proto_registrar_get_id_byname("umas.init_comms.firmware_version"), tvb, offset + 2, 2, firmware_version);
        proto_tree_add_uint(tree, proto_registrar_get_id_byname("umas.init_comms.internal_code"), tvb, offset + 8, 4, internal_code);
        proto_tree_add_uint(tree, proto_registrar_get_id_byname("umas.init_comms.hostname_length"), tvb, offset + 12, 1, hostname_length);
        proto_tree_add_string(tree, proto_registrar_get_id_byname("umas.init_comms.hostname"), tvb, offset + 13, hostname_length, hostname);

        break;
    case READ_ID:
        uint16_t umas_read_id_range = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN);
        uint32_t umas_read_id_ident = tvb_get_uint32(tvb, offset + 2, ENC_LITTLE_ENDIAN);
        uint16_t umas_read_id_model = tvb_get_uint16(tvb, offset + 6, ENC_LITTLE_ENDIAN);
        uint16_t umas_read_id_com_version = tvb_get_uint16(tvb, offset + 8, ENC_LITTLE_ENDIAN);
        uint16_t umas_read_id_com_patch = tvb_get_uint16(tvb, offset + 10, ENC_LITTLE_ENDIAN);
        uint16_t umas_read_id_int_version = tvb_get_uint16(tvb, offset + 12, ENC_LITTLE_ENDIAN);
        uint16_t umas_read_id_hardware_version = tvb_get_uint16(tvb, offset + 14, ENC_LITTLE_ENDIAN);
        uint32_t umas_read_id_crash_code = tvb_get_uint32(tvb, offset + 16, ENC_LITTLE_ENDIAN);
        uint8_t umas_read_id_hostname_length = tvb_get_uint8(tvb, offset + 22);
        const char* umas_read_id_hostname = (char*)tvb_get_string_enc(wmem_file_scope(), tvb, offset + 23, umas_read_id_hostname_length, ENC_UTF_8);
        uint8_t umas_read_id_number_of_memory_banks = tvb_get_uint8(tvb, offset + 23 + umas_read_id_hostname_length);

        proto_tree_add_uint(tree, proto_registrar_get_id_byname("umas.read_id.range"), tvb, offset, 2, umas_read_id_range);
        proto_tree_add_uint(tree, proto_registrar_get_id_byname("umas.read_id.id"), tvb, offset + 2, 4, umas_read_id_ident);

        proto_tree_add_uint(tree, proto_registrar_get_id_byname("umas.read_id.model"), tvb, offset + 6, 2, umas_read_id_model);
        proto_tree_add_uint(tree, proto_registrar_get_id_byname("umas.read_id.com_version"), tvb, offset + 8, 2, umas_read_id_com_version);
        proto_tree_add_uint(tree, proto_registrar_get_id_byname("umas.read_id.com_patch"), tvb, offset + 10, 2, umas_read_id_com_patch);
        proto_tree_add_uint(tree, proto_registrar_get_id_byname("umas.read_id.int_version"), tvb, offset + 12, 2, umas_read_id_int_version);

        proto_tree_add_uint(tree, proto_registrar_get_id_byname("umas.read_id.hardware_version"), tvb, offset + 14, 2, umas_read_id_hardware_version);
        proto_tree_add_uint(tree, proto_registrar_get_id_byname("umas.read_id.crash_code"), tvb, offset + 16, 4, umas_read_id_crash_code);
        proto_tree_add_uint(tree, proto_registrar_get_id_byname("umas.read_id.hostname_length"), tvb, offset + 22, 1, umas_read_id_hostname_length);
        proto_tree_add_string(tree, proto_registrar_get_id_byname("umas.read_id.hostname"), tvb, offset + 23, umas_read_id_hostname_length, umas_read_id_hostname);

        proto_tree_add_uint(tree, proto_registrar_get_id_byname("umas.read_id.no_memory_bank"), tvb, offset + 23 + umas_read_id_hostname_length, 1, umas_read_id_number_of_memory_banks);
        proto_tree* block_list_tree = proto_tree_add_subtree(tree, tvb, offset + 23 + umas_read_id_hostname_length + 1, umas_read_id_number_of_memory_banks * 4, ett_umas_read_variable_list, NULL, "Block List");


        int block_start_offset = offset + 23 + umas_read_id_hostname_length + 1;
        uint8_t umas_memory_block_id_block_type;
        uint8_t umas_memory_block_id_folio;
        uint16_t umas_memory_block_id_status;
        uint32_t umas_memory_block_id_memory_length;
        proto_tree* block_list_item_tree;

        char item_name[100];
        
        int current_offset = offset + 5;
        for (i = 0; i < umas_read_id_number_of_memory_banks; ++i) {
            umas_memory_block_id_block_type = tvb_get_uint8(tvb, block_start_offset);
            umas_memory_block_id_folio = tvb_get_uint8(tvb, block_start_offset + 1);
            umas_memory_block_id_status = tvb_get_uint16(tvb, block_start_offset + 2, ENC_LITTLE_ENDIAN);
            umas_memory_block_id_memory_length = tvb_get_uint32(tvb, block_start_offset + 4, ENC_LITTLE_ENDIAN);

            sprintf(item_name, "Type:- %s, Folio:- %d, Status:- %d, Length:- %d", val_to_str(umas_memory_block_id_block_type, memory_block_id_type, "UNKNOWN"), umas_memory_block_id_folio, umas_memory_block_id_status, umas_memory_block_id_memory_length);
            block_list_item_tree = proto_tree_add_subtree(block_list_tree, tvb, block_start_offset, 8, ett_umas_read_variable_list_item, NULL, item_name);

            proto_tree_add_uint(block_list_item_tree, proto_registrar_get_id_byname("umas.read_id.no_memory_bank"), tvb, block_start_offset, 1, umas_memory_block_id_block_type);
            proto_tree_add_uint(block_list_item_tree, proto_registrar_get_id_byname("umas.read_id.folio"), tvb, block_start_offset + 1, 1, umas_memory_block_id_folio);
            proto_tree_add_uint(block_list_item_tree, proto_registrar_get_id_byname("umas.read_id.status"), tvb, block_start_offset + 2, 2, umas_memory_block_id_status);
            proto_tree_add_uint(block_list_item_tree, proto_registrar_get_id_byname("umas.read_id.memory_length"), tvb, block_start_offset + 4, 4, umas_memory_block_id_memory_length);

            block_start_offset += 8;
        }
        break;
    case READ_MEMORY_BLOCK:
        uint8_t umas_read_memory_range = tvb_get_uint8(tvb, offset);
        uint16_t umas_read_memory_length = tvb_get_uint16(tvb, offset + 1, ENC_LITTLE_ENDIAN);

        uint16_t block_no = pkt_info->block_no;
        uint16_t block_offset = pkt_info->offset;


        proto_tree_add_uint(tree, proto_registrar_get_id_byname("umas.read_memory_block.range"), tvb, offset, 1, umas_read_memory_range);
        proto_tree_add_uint(tree, proto_registrar_get_id_byname("umas.read_memory_block.length"), tvb, offset + 1, 2, umas_read_memory_length);

        proto_tree_add_uint(tree, proto_registrar_get_id_byname("umas.read_memory_block.block_no"), tvb, offset, 0, block_no);
        proto_tree_add_uint(tree, proto_registrar_get_id_byname("umas.read_memory_block.offset"), tvb, offset, 0, block_offset);
        break;
    case DATA_DICTIONARY:
        proto_tree_add_item_new(tree, proto_registrar_get_byname("umas.data_dictionary.next_address"), tvb, offset, 2, ENC_LITTLE_ENDIAN);

        uint16_t umas_data_dictionary_record_type = pkt_info->record_type;
        uint16_t umas_data_dictionary_block_number = pkt_info->block_no;
        uint16_t umas_data_dictionary_block_offset = pkt_info->offset;

        proto_tree_add_uint(tree, proto_registrar_get_id_byname("umas.data_dictionary.record_type"), tvb, offset, 0, umas_data_dictionary_record_type);
        proto_tree_add_uint(tree, proto_registrar_get_id_byname("umas.data_dictionary.block_no"), tvb, offset, 0, umas_data_dictionary_block_number);
        proto_tree_add_uint(tree, proto_registrar_get_id_byname("umas.data_dictionary.offset"), tvb, offset, 0, umas_data_dictionary_block_offset);
        int* umas_data_dictionary_no_records;
        proto_tree* umas_data_dictionary_list_item_tree;
        uint16_t umas_data_dictionary_data_size;
        uint8_t umas_data_dictionary_class_identifier;
        uint8_t umas_data_dictionary_data_type;
        int* umas_data_dictionary_string_length;
        const uint8_t* umas_data_dictionary_data_type_name;
        int new_offset;

        switch (umas_data_dictionary_record_type) {
        case 0xDD02:
            // DFB Child List
            if (umas_data_dictionary_block_number != 0xFFFF) {
                proto_tree* dfb_element_list_tree = proto_tree_add_subtree(tree, tvb, offset + 4, -1, ett_umas_read_variable_list, NULL, "DFB Element List");
                umas_data_dictionary_no_records = wmem_alloc(wmem_file_scope(), sizeof * umas_data_dictionary_no_records);
                proto_tree_add_item_ret_uint(dfb_element_list_tree, proto_registrar_get_id_byname("umas.data_dictionary.no_of_records"), tvb, offset + 5, 2, ENC_LITTLE_ENDIAN, umas_data_dictionary_no_records);
                new_offset = offset + 7;
                for (i = 0; i < *umas_data_dictionary_no_records; ++i) {
                    umas_data_dictionary_data_type = tvb_get_uint16(tvb, new_offset, ENC_LITTLE_ENDIAN);
                    uint16_t umas_data_dictionary_offset = tvb_get_uint16(tvb, new_offset + 2, ENC_LITTLE_ENDIAN);

                    umas_data_dictionary_string_length = wmem_alloc(wmem_file_scope(), sizeof * umas_data_dictionary_string_length);
                    umas_data_dictionary_data_type_name = tvb_get_stringz_enc(wmem_file_scope(), tvb, new_offset + 8, umas_data_dictionary_string_length, ENC_UTF_8);

                    sprintf(item_name, "%d, %s", umas_data_dictionary_data_type, umas_data_dictionary_data_type_name);
                    umas_data_dictionary_list_item_tree = proto_tree_add_subtree(dfb_element_list_tree, tvb, new_offset, 0, ett_umas_read_variable_list_item, NULL, item_name);

                    proto_tree_add_uint(umas_data_dictionary_list_item_tree, proto_registrar_get_id_byname("umas.data_dictionary.data_type"), tvb, new_offset, 2, umas_data_dictionary_data_type);
                    proto_tree_add_uint(umas_data_dictionary_list_item_tree, proto_registrar_get_id_byname("umas.data_dictionary.rel_offset"), tvb, new_offset + 2, 2, umas_data_dictionary_offset);
                    proto_tree_add_uint(umas_data_dictionary_list_item_tree, proto_registrar_get_id_byname("umas.data_dictionary.length"), tvb, new_offset, 0, *umas_data_dictionary_string_length);

                    proto_tree_add_string(umas_data_dictionary_list_item_tree, proto_registrar_get_id_byname("umas.data_dictionary.name"), tvb, new_offset + 8, *umas_data_dictionary_string_length, umas_data_dictionary_data_type_name);
                    new_offset += 8 + *umas_data_dictionary_string_length;
                }
            }
            else {
                // Variable List
                proto_tree* dfb_element_list_tree = proto_tree_add_subtree(tree, tvb, offset + 4, -1, ett_umas_read_variable_list, NULL, "Variable List");
                umas_data_dictionary_no_records = wmem_alloc(wmem_file_scope(), sizeof * umas_data_dictionary_no_records);
                proto_tree_add_item_ret_uint(dfb_element_list_tree, proto_registrar_get_id_byname("umas.data_dictionary.no_of_records"), tvb, offset + 5, 2, ENC_LITTLE_ENDIAN, umas_data_dictionary_no_records);
                new_offset = offset + 7;
                for (i = 0; i < *umas_data_dictionary_no_records; ++i) {
                    umas_data_dictionary_data_type = tvb_get_uint16(tvb, new_offset, ENC_LITTLE_ENDIAN);
                    uint16_t umas_data_dictionary_offset = tvb_get_uint16(tvb, new_offset + 2, ENC_LITTLE_ENDIAN);

                    umas_data_dictionary_string_length = wmem_alloc(wmem_file_scope(), sizeof * umas_data_dictionary_string_length);
                    umas_data_dictionary_data_type_name = tvb_get_stringz_enc(wmem_file_scope(), tvb, new_offset + 10, umas_data_dictionary_string_length, ENC_UTF_8);

                    sprintf(item_name, "%d, %s", umas_data_dictionary_data_type, umas_data_dictionary_data_type_name);
                    umas_data_dictionary_list_item_tree = proto_tree_add_subtree(dfb_element_list_tree, tvb, new_offset, 0, ett_umas_read_variable_list_item, NULL, item_name);

                    proto_tree_add_uint(umas_data_dictionary_list_item_tree, proto_registrar_get_id_byname("umas.data_dictionary.data_type"), tvb, new_offset, 2, umas_data_dictionary_data_type);
                    proto_tree_add_uint(umas_data_dictionary_list_item_tree, proto_registrar_get_id_byname("umas.data_dictionary.block_no"), tvb, new_offset + 2, 2, umas_data_dictionary_offset);
                    proto_tree_add_item_new(umas_data_dictionary_list_item_tree, proto_registrar_get_byname("umas.data_dictionary.address"), tvb, new_offset + 4, 2, ENC_LITTLE_ENDIAN);
                    proto_tree_add_uint(umas_data_dictionary_list_item_tree, proto_registrar_get_id_byname("umas.data_dictionary.length"), tvb, new_offset, 0, *umas_data_dictionary_string_length);

                    proto_tree_add_string(umas_data_dictionary_list_item_tree, proto_registrar_get_id_byname("umas.data_dictionary.name"), tvb, new_offset + 10, *umas_data_dictionary_string_length, umas_data_dictionary_data_type_name);
                    new_offset += 10 + *umas_data_dictionary_string_length;
                }
            }

            break;
        case 0xDD03:
            proto_tree* data_type_list_tree = proto_tree_add_subtree(tree, tvb, offset + 4, -1, ett_umas_read_variable_list, NULL, "Data Type List");
            umas_data_dictionary_no_records = wmem_alloc(wmem_file_scope(), sizeof *umas_data_dictionary_no_records);
            proto_tree_add_item_ret_uint(data_type_list_tree, proto_registrar_get_id_byname("umas.data_dictionary.no_of_records"), tvb, offset + 4, 2, ENC_LITTLE_ENDIAN, umas_data_dictionary_no_records);
            new_offset = offset + 6;
            for (i = 0; i < *umas_data_dictionary_no_records; ++i) {
                umas_data_dictionary_data_size = tvb_get_uint16(tvb, new_offset, ENC_LITTLE_ENDIAN);
                umas_data_dictionary_class_identifier = tvb_get_uint8(tvb, new_offset + 4);
                umas_data_dictionary_data_type = tvb_get_uint8(tvb, new_offset + 5);
                umas_data_dictionary_string_length = wmem_alloc(wmem_file_scope(), sizeof *umas_data_dictionary_string_length);
                umas_data_dictionary_data_type_name = tvb_get_stringz_enc(wmem_file_scope(), tvb, new_offset + 7, umas_data_dictionary_string_length, ENC_UTF_8);

                sprintf(item_name, "%d, %s", umas_data_dictionary_data_type, umas_data_dictionary_data_type_name);
                umas_data_dictionary_list_item_tree = proto_tree_add_subtree(data_type_list_tree, tvb, new_offset, 0, ett_umas_read_variable_list_item, NULL, item_name);

                proto_tree_add_uint(umas_data_dictionary_list_item_tree, proto_registrar_get_id_byname("umas.data_dictionary.data_size"), tvb, new_offset, 2, umas_data_dictionary_data_size);
                proto_tree_add_uint(umas_data_dictionary_list_item_tree, proto_registrar_get_id_byname("umas.data_dictionary.class_identifier"), tvb, new_offset + 4, 1, umas_data_dictionary_class_identifier);
                proto_tree_add_uint(umas_data_dictionary_list_item_tree, proto_registrar_get_id_byname("umas.data_dictionary.data_type"), tvb, new_offset + 5, 1, umas_data_dictionary_data_type);
                proto_tree_add_uint(umas_data_dictionary_list_item_tree, proto_registrar_get_id_byname("umas.data_dictionary.length"), tvb, new_offset, 0, *umas_data_dictionary_string_length);

                proto_tree_add_string(umas_data_dictionary_list_item_tree, proto_registrar_get_id_byname("umas.data_dictionary.name"), tvb, new_offset + 7, *umas_data_dictionary_string_length, umas_data_dictionary_data_type_name);
                new_offset += 7 + *umas_data_dictionary_string_length;
            }
            break;
        }
    default:
        break;
    };
    return tvb_captured_length(tvb);
}

/* Dissect the Modbus Payload.  Called from either Modbus/TCP or Modbus RTU Dissector */
static int
dissect_umas(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    proto_item*     mi;
    proto_tree*     umas_tree;
    proto_tree*     mod_tree;
    modbus_pkt_info_t* modbus_data;

    umas_data_t     umas_data;

    int             offset;

    uint8_t         pairing_key, function_code, request_function_code;
    const char*     pkt_type_str = "";
    const char*     err_str = "";
    const char*     func_string;

    umas_request_info_t* pkt_info;

    offset = 0;

    /* Make entries in Protocol column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UMAS");
    col_clear(pinfo->cinfo, COL_INFO);
    
    /* Create protocol tree */
    mod_tree = proto_tree_get_parent_tree(tree);
    
    mi = proto_tree_add_item(mod_tree, proto_umas, tvb, offset, 2, ENC_NA);
    umas_tree = proto_item_add_subtree(mi, ett_umas);

    pairing_key = tvb_get_uint8(tvb, 0);
    function_code = tvb_get_uint8(tvb, 1);

    /* Get the Modbus Packet Data so that we can get the req_frame_number */
    modbus_data = (modbus_pkt_info_t*)p_get_proto_data(wmem_file_scope(), pinfo, proto_modbus, 0);
    
    
    /* "Request" or "Response" */
    umas_data.packet_type = classify_umas_packet(pinfo, function_code);
    /* Transaction ID is available only in Modbus TCP */
    umas_data.pairing_key = pairing_key;
    umas_data.function_code = function_code;

    /* Add items to protocol tree specific to Modbus RTU */
    proto_tree_add_uint(umas_tree, proto_registrar_get_id_byname("umas.pairing_key"), tvb, offset, 1, pairing_key);
    proto_tree_add_uint(umas_tree, proto_registrar_get_id_byname("umas.func_code"), tvb, offset + 1, 1, function_code);

    /* Populate conversation instance */
    conversation_t* conversation = NULL;
    umas_conversation* umas_conv_data = NULL;
    if (!pinfo->fd->visited) {
        /* Find a conversation, create a new if no one exists */
        conversation = find_or_create_conversation(pinfo);
        umas_conv_data = (umas_conversation*) conversation_get_proto_data(conversation, proto_umas);

        /* Allocate Memory and replace conversation data */
        if (umas_conv_data == NULL) {
            umas_conv_data = wmem_new(wmem_file_scope(), umas_conversation);
            umas_conv_data->umas_request_frame_data = wmem_list_new(wmem_file_scope());
            conversation_add_proto_data(conversation, proto_umas, (void*)umas_conv_data);
        }

        if (umas_data.packet_type == QUERY_PACKET) {
            request_function_code = 0;
            umas_request_info_t* frame_data = wmem_new0(wmem_file_scope(), umas_request_info_t);
            frame_data->req_frame_num = pinfo->num;
            frame_data->function_code = umas_data.function_code;
            wmem_list_prepend(umas_conv_data->umas_request_frame_data, frame_data);
            p_add_proto_data(wmem_file_scope(), pinfo, proto_umas, REQUEST_INFO, frame_data);
            pkt_info = frame_data;
        }
        else if (umas_data.packet_type == RESPONSE_PACKET) {
            umas_request_info_t* request_data;
            bool request_found = false;

            request_function_code = 0;

            wmem_list_frame_t* frame = wmem_list_head(umas_conv_data->umas_request_frame_data);
            /* Step backward through all logged instances of request frames, looking for a request frame number that
            occurred immediately prior to current frame number that has a matching function code,
            unit-id and transaction identifier */
            while (frame && !request_found) {
                request_data = (umas_request_info_t*)wmem_list_frame_data(frame);
                
                if (modbus_data->req_frame_num == request_data->req_frame_num) {
                    pkt_info = request_data;
                    p_add_proto_data(wmem_file_scope(), pinfo, proto_umas, REQUEST_INFO, request_data);
                    request_found = true;
                }
                frame = wmem_list_frame_next(frame);
            }
        }
    }
    else {
        pkt_info = (umas_request_info_t*) p_get_proto_data(wmem_file_scope(), pinfo, proto_umas, REQUEST_INFO);
    }
    
    switch (umas_data.function_code) {
    case RESPONSE_OK:
        pkt_type_str = "Response";
        func_string = val_to_str(pkt_info->function_code, function_code_vals, "Unknown function (%d)");
        dissect_umas_pdu_response(tvb, pinfo, umas_tree, data, pkt_info->function_code, offset + 2, pkt_info);
        break;
    case RESPONSE_ERROR:
        pkt_type_str = "Error";
        func_string = val_to_str(pkt_info->function_code, function_code_vals, "Unknown function (%d)");
    default:
        pkt_type_str = "Query";
        func_string = val_to_str(pkt_info->function_code, function_code_vals, "Unknown function (%d)");
        dissect_umas_pdu_request(tvb, pinfo, umas_tree, data, function_code, offset + 2, pkt_info);
        break;
    }

    if (strlen(err_str) > 0) {
        col_add_fstr(pinfo->cinfo, COL_INFO,
            "%8s: Func: %3u; %s. %s",
            pkt_type_str, function_code, func_string, err_str);
    }
    else {
        col_add_fstr(pinfo->cinfo, COL_INFO,
            "%8s: Func: %3u; %s.",
            pkt_type_str, function_code, func_string);
    }

    return tvb_captured_length(tvb);
}


/* Register the protocol with Wireshark */
void
proto_register_umas(void)
{  
    module_t *umas_module;
    expert_module_t* expert_umas;

    static int dummy_int = 0;

    static int hf_ids[100];
        
    /* Modbus/TCP header fields */
    static hf_register_info umas_hf[] = {
        { &hf_ids[0],
            { "Pairing Key", "umas.pairing_key",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[1],
            { "Function Code", "umas.func_code",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[2],
            { "Sub. Code", "umas.init.sub_code",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[3],
            { "Sub. Code", "umas.project_info.sub_code",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[4],
            { "Range", "umas.read_block.range",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[5],
            { "Block Number", "umas.read_block.block_no",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[6],
            { "Offset", "umas.read_block.offset",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[7],
            { "Number Of Bytes", "umas.read_block.no_bytes",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[8],
            { "Record Type", "umas.data_dictionary.record_type",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[9],
            { "Record Index", "umas.data_dictionary.record_index",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[10],
            { "Hardware ID", "umas.data_dictionary.hardware_id",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[11],
            { "Block Number", "umas.data_dictionary.block_no",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[12],
            { "Offset", "umas.data_dictionary.offset",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[13],
            { "Calculated CRC", "umas.read_variable.crc",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[14],
            { "Count", "umas.read_variable.count",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[15],
            { "Is Array", "umas.read_variable.list.is_array",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[16],
            { "Data Type Size Index", "umas.read_variable.list.data_type_size_index",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[17],
            { "Block No.", "umas.read_variable.list.block_no",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[18],
            { "Base Offset", "umas.read_variable.list.base_offset",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[19],
            { "Offset", "umas.read_variable.list.offset",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[20],
            { "Array Length", "umas.read_variable.list.array_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[21],
            { "Max. Frame Size", "umas.init_comms.max_frame_size",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[22],
            { "Firmware Version", "umas.init_comms.firmware_version",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[23],
            { "Internal Code", "umas.init_comms.internal_code",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[24],
            { "Hostname Length", "umas.init_comms.hostname_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[25],
            { "Hostname", "umas.init_comms.hostname",
            FT_STRING, BASE_STR_WSP, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[26],
            { "Range", "umas.read_id.range",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[27],
            { "Id.", "umas.read_id.id",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[28],
            { "Model", "umas.read_id.model",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[29],
            { "Com Version", "umas.read_id.com_version",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[30],
            { "Com Patch", "umas.read_id.com_patch",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[31],
            { "Int Version", "umas.read_id.int_version",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[32],
            { "Hardware Version", "umas.read_id.hardware_version",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[33],
            { "Crash Code", "umas.read_id.crash_code",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[34],
            { "Hostname Length", "umas.read_id.hostname_length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[35],
            { "Hostname", "umas.read_id.hostname",
            FT_STRING, BASE_STR_WSP, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[36],
            { "Block Type", "umas.read_id.block_type",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[37],
            { "Folio", "umas.read_id.folio",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[38],
            { "Status", "umas.read_id.status",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[39],
            { "Memory Length", "umas.read_id.memory_length",
            FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[40],
            { "Memory Bank Count", "umas.read_id.no_memory_bank",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[41],
            { "Range", "umas.read_memory_block.range",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[42],
            { "Length", "umas.read_memory_block.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[43],
            { "Data",  "umas.read_memory_block.data",
            FT_BYTES,  BASE_NONE, NULL,    0x0, NULL, HFILL }
        },
        { &hf_ids[44],
            { "Range", "umas.data_dictionary.range",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[45],
            { "Next Address", "umas.data_dictionary.next_address",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[46],
            { "No. Of Records", "umas.data_dictionary.no_of_records",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[47],
            { "Data Type Size", "umas.data_dictionary.data_size",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[48],
            { "Class Identifier", "umas.data_dictionary.class_identifier",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[49],
            { "Data Type", "umas.data_dictionary.data_type",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[50],
            { "Length", "umas.data_dictionary.length",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[51],
            { "Name", "umas.data_dictionary.name",
            FT_STRING, BASE_STR_WSP, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[52],
            { "Range", "umas.read_memory_block.block_no",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[53],
            { "Range", "umas.read_memory_block.offset",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[54],
            { "Relative Offset", "umas.data_dictionary.rel_offset",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[55],
            { "Index", "umas.data_dictionary.index",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[56],
            { "Address", "umas.data_dictionary.address",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[57],
            { "Calculated CRC", "umas.write_variable.crc",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[58],
            { "Count", "umas.write_variable.count",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[59],
            { "Is Array", "umas.write_variable.list.is_array",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[60],
            { "Data Type Size Index", "umas.write_variable.list.data_type_size_index",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[61],
            { "Block No.", "umas.write_variable.list.block_no",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[62],
            { "Base Offset", "umas.write_variable.list.base_offset",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[63],
            { "Offset", "umas.write_variable.list.offset",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[64],
            { "Array Length", "umas.write_variable.list.array_length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ids[65],
            { "Data",  "umas.write_variable.list.data",
            FT_BYTES,  BASE_NONE, NULL,    0x0, NULL, HFILL }
        },
        { &hf_ids[66],
            { "Block No.", "umas.data_dictionary.block_no",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
    };
    
    /* Setup protocol subtree array */
    static int* ett[] = {
        &ett_umas,
        &ett_umas_read_variable_list,
        &ett_umas_read_variable_list_item,
        &ett_umas_write_variable_list,
        &ett_umas_write_variable_list_item
    };

    /* Register the protocol name and description */
    proto_umas = proto_register_protocol("UMAS", "UMAS", "umas");

    /* Registering protocol to be called by another dissector */
    umas_handle = register_dissector("umas", dissect_umas, proto_umas);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_umas, umas_hf, array_length(umas_hf));
    proto_register_subtree_array(ett, array_length(ett));
}

//static void
//apply_umas_prefs(void)
//{
    /* Modbus/RTU uses the port preference to determine request/response */
//    global_umas_func_code = prefs_get_range_value("modbus", "modbus.func_code");
//}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
 */
void
proto_reg_handoff_umas(void)
{
    dissector_handle_t umas_handle = create_dissector_handle(dissect_umas, proto_umas);
    dissector_add_uint("modbus.func_code", 90, umas_handle);
}

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
