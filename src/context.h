#pragma once

typedef enum { COIN_KIND_BITCOIN_TESTNET, COIN_KIND_BITCOIN } coin_kind_t;

typedef struct {
    // new app
    unsigned long bip32_pubkey_version;

    // legacy
    unsigned short bip44_coin_type;
    unsigned short bip44_coin_type2;
    unsigned short p2pkh_version;
    unsigned short p2sh_version;
    unsigned char family;
    // unsigned char* iconsuffix;// will use the icon provided on the stack (maybe)
    char coinid[14];     // used coind id for message signature prefix
    char name[16];       // for ux displays
    char name_short[6];  // for unit in ux displays
    char native_segwit_prefix_val[5];
    const char* native_segwit_prefix;  // null if no segwit prefix
    coin_kind_t kind;
    unsigned int flags;
} global_context_t;