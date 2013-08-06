#include "config.h"

#include <epan/packet.h>

#define NSDP_PORT 63322
#define NSDP_PROTO_NAME "NSDP"

static dissector_handle_t data_handle;

static int proto_nsdp = -1;
static int hf_nsdp_version = -1;
static int hf_nsdp_packet_type = -1;
static int hf_nsdp_reserved_1 = -1;
static int hf_nsdp_self_mac = -1;
static int hf_nsdp_remote_mac = -1;
static int hf_nsdp_reserved_2 = -1;
static int hf_nsdp_seq = -1;
static int hf_nsdp_sign = -1;
static int hf_nsdp_reserved_3 = -1;
// TLVs
static int hf_nsdp_tlv_type = -1;
static int hf_nsdp_tlv_length = -1;
static int hf_nsdp_tlv_value = -1;
static int hf_nsdp_tlv_value_string = -1;
static int hf_nsdp_tlv_eth = -1;
static int ett_nsdp = -1;
static int ett_nsdp_tlv = -1;

static const char * tlv_types[] = {
"", // 0
"Model", // 1
"", // 1
"", // 3
"MAC", // 4
"", // 5
"IP Address", // 6
"Subnet mask", // 7
"Gateway", // 8
"", // 9
"Password", // 10
"", // 11
"", // 12
"FW Version", // 13
"", // 14
"" // 15
};

static void
dissect_nsdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static void
dissect_nsdp_data(tvbuff_t *tvb, proto_tree *tree, int len, int offset);

void
proto_register_nsdp(void)
{
    static hf_register_info hf[] = {
        { &hf_nsdp_version,
            { "Version","nsdp.version",FT_UINT8,
                BASE_DEC,NULL,0x0,NULL,HFILL}
        },
        { &hf_nsdp_packet_type,
            { "Packet type","nsdp.packet_type",FT_UINT8,
                BASE_DEC,NULL,0x0,NULL,HFILL}
        },
        { &hf_nsdp_reserved_1,
            { "Reserved","nsdp.reserved1",FT_BYTES,
                BASE_NONE,NULL,0x0,NULL,HFILL}
        },
        { &hf_nsdp_self_mac,
            { "Self MAC", "nsdp.local.ether", FT_ETHER, BASE_NONE, NULL, 0x0,
            "Self Hardware Address", HFILL }
        },
        { &hf_nsdp_remote_mac,
            { "Remote MAC", "nsdp.remote.ether", FT_ETHER, BASE_NONE, NULL, 0x0,
            "Remote Hardware Address", HFILL }
        },
        { &hf_nsdp_reserved_2,
            { "Reserved","nsdp.reserved_2",FT_BYTES,
                BASE_NONE,NULL,0x0,NULL,HFILL}
        },
        { &hf_nsdp_seq,
            { "Sequence","nsdp.seq",FT_UINT16,
                BASE_HEX,NULL,0x0,NULL,HFILL}
        },
        { &hf_nsdp_sign,
            { "Signature","nsdp.signature",FT_STRINGZ,
                BASE_NONE,NULL,0x0,NULL,HFILL}
        },
        { &hf_nsdp_reserved_3,
            { "Reserved","nsdp.reserved_3",FT_BYTES,
                BASE_NONE,NULL,0x0,NULL,HFILL}
        },
        // TLV identifiers
        { &hf_nsdp_tlv_type,
            { "Type","nsdp.tlv.type",FT_UINT16,
                BASE_HEX,NULL,0x0,NULL,HFILL}
        },
        { &hf_nsdp_tlv_length,
            { "Length","nsdp.tlv.length",FT_UINT16,
                BASE_DEC,NULL,0x0,NULL,HFILL}
        },
        { &hf_nsdp_tlv_value,
            { "Value","nsdp.tlv.value",FT_BYTES,
                BASE_NONE,NULL,0x0,NULL,HFILL}
        },
        { &hf_nsdp_tlv_value_string,
            { "String value","nsdp.tlv.value.string",FT_STRINGZ,
                BASE_NONE,NULL,0x0,NULL,HFILL}
        },
        { &hf_nsdp_tlv_eth,
            { "MAC", "nsdp.tlv.value.ether", FT_ETHER, BASE_NONE, NULL, 0x0,
            "Hardware Address", HFILL }
        }
    };

    static gint *ett[] = {
        &ett_nsdp,
        &ett_nsdp_tlv
    };

    proto_nsdp = proto_register_protocol (
        "NSDP Protocol", /* name       */
        NSDP_PROTO_NAME,      /* short name */
        "nsdp"       /* abbrev     */
        );
    proto_register_subtree_array(
        ett,
        array_length(ett)
    );
    proto_register_field_array(proto_nsdp,hf,array_length(hf));

}

void
proto_reg_handoff_nsdp(void)
{
    static dissector_handle_t nsdp_handle;

    nsdp_handle = create_dissector_handle(dissect_nsdp, proto_nsdp);
    dissector_add_uint("udp.port", NSDP_PORT, nsdp_handle);

    data_handle = find_dissector("data");
}

static void
dissect_nsdp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    gint offset = 0;
    proto_item *ti = NULL;
    proto_item *nsdp_tree = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, NSDP_PROTO_NAME);

    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo,COL_INFO);
    if (tree) {
        ti = proto_tree_add_item(tree, proto_nsdp, tvb, offset, -1, ENC_NA);
        nsdp_tree = proto_item_add_subtree(ti, ett_nsdp);
        proto_tree_add_item(nsdp_tree, hf_nsdp_version, tvb, offset, 1, ENC_NA); offset += 1;
        proto_tree_add_item(nsdp_tree, hf_nsdp_packet_type, tvb, offset, 1, ENC_NA); offset += 1;
        proto_tree_add_item(nsdp_tree, hf_nsdp_reserved_1, tvb, offset, 6, ENC_NA); offset += 6;
        proto_tree_add_item(nsdp_tree, hf_nsdp_self_mac, tvb, offset, 6, ENC_NA); offset += 6;
        proto_tree_add_item(nsdp_tree, hf_nsdp_remote_mac, tvb, offset, 6, ENC_NA); offset += 6;
        proto_tree_add_item(nsdp_tree, hf_nsdp_reserved_2, tvb, offset, 2, ENC_NA); offset += 2;
        proto_tree_add_item(nsdp_tree, hf_nsdp_seq, tvb, offset, 2, ENC_NA); offset += 2;
        proto_tree_add_item(nsdp_tree, hf_nsdp_sign, tvb, offset, 4, ENC_NA); offset += 4;
        proto_tree_add_item(nsdp_tree, hf_nsdp_reserved_3, tvb, offset, 4, ENC_NA); offset += 4;

        /* If any bytes remain, send it to the generic data dissector */
        dissect_nsdp_data(tvb, nsdp_tree, tvb_reported_length_remaining(tvb, offset), offset);
//        tvb = tvb_new_subset_remaining(tvb, offset);
//        call_dissector(data_handle, tvb, pinfo, nsdp_data_tree);
    }
}

static void
dissect_nsdp_data(tvbuff_t *tvb, proto_tree *tree, int len, int offset) {
    guint16 l = 0;
    guint16 t = 0;
    proto_item *tlv_item = NULL;
    proto_item *tlv_tree = NULL;
    const guchar *ip_addr;
    const guchar *hw_addr;

    while(len > 0) {
        // Get Type field
        t = tvb_get_ntohs(tvb, offset);
        // Get Length field
        l = tvb_get_ntohs(tvb, offset + 2);
        // Format subtree item text from type field
        switch(t) {
        case 0x0001:
        case 0x0004:
        case 0x0006:
        case 0x0007:
        case 0x0008:
        case 0x000d:
        case 0x000a:
            tlv_item = proto_tree_add_text(tree, tvb, offset, l, "%s", tlv_types[t]);
        break;
        case 0x7400:
            tlv_item = proto_tree_add_text(tree, tvb, offset, l, "TLV: type=%s(0x%.4x) length=%u", "End of options", t, l);
        break;
        default:
            tlv_item = proto_tree_add_text(tree, tvb, offset, l, "TLV: type=0x%.4x  length=%u", t, l);
        }

        tlv_tree = proto_item_add_subtree(tlv_item, ett_nsdp_tlv);
        proto_tree_add_item(tlv_tree, hf_nsdp_tlv_type, tvb, offset, 2, ENC_NA); offset += 2;
        proto_tree_add_item(tlv_tree, hf_nsdp_tlv_length, tvb, offset, 2, ENC_NA); offset += 2;
        if (l > 0) {
            // Format value from type field
            switch(t) {
            case 0x0001:
            case 0x000a:
            case 0x000d:
                proto_tree_add_item(tlv_tree, hf_nsdp_tlv_value_string, tvb, offset, l, ENC_NA);
            break;
            case 0x0004:
                hw_addr = tvb_get_ptr(tvb, offset, 6);
                proto_tree_add_ether(tlv_tree, hf_nsdp_tlv_eth, tvb, 0, 6, hw_addr);
            break;
            case 0x0006:
            case 0x0007:
            case 0x0008:
                ip_addr = tvb_get_ptr(tvb, offset, 4);
                proto_tree_add_text(tlv_tree, tvb, offset, l, "IP Address value: %s", ip_to_str(ip_addr));
            break;
            default:
                proto_tree_add_item(tlv_tree, hf_nsdp_tlv_value, tvb, offset, l, ENC_NA);
            }
             offset += l;
        }
        len = tvb_reported_length_remaining(tvb, offset);
    }
}
