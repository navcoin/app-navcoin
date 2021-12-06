/*****************************************************************************
 *   Ledger App Bitcoin.
 *   (c) 2021 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

#include <stdint.h>  // uint*_t
#include <string.h>  // memset, explicit_bzero

#include <assert.h>

#include "os.h"
#include "ux.h"

#include "globals.h"
#include "io.h"
#include "sw.h"
#include "ui/menu.h"
#include "boilerplate/apdu_parser.h"
#include "boilerplate/constants.h"
#include "boilerplate/dispatcher.h"

#include "commands.h"

#include "main.h"

#ifdef HAVE_BOLOS_APP_STACK_CANARY
extern unsigned int app_stack_canary;
#endif

uint8_t G_io_seproxyhal_spi_buffer[IO_SEPROXYHAL_BUFFER_SIZE_B];
ux_state_t G_ux;
bolos_ux_params_t G_ux_params;

command_state_t G_command_state;
dispatcher_context_t G_dispatcher_context;

global_context_t *G_coin_config;

// clang-format off
const command_descriptor_t COMMAND_DESCRIPTORS[] = {
    {
        .cla = CLA_APP,
        .ins = GET_EXTENDED_PUBKEY,
        .handler = (command_handler_t)handler_get_extended_pubkey
    },
    {
        .cla = CLA_APP,
        .ins = GET_WALLET_ADDRESS,
        .handler = (command_handler_t)handler_get_wallet_address
    },
    {
        .cla = CLA_APP,
        .ins = REGISTER_WALLET,
        .handler = (command_handler_t)handler_register_wallet
    },
    {
        .cla = CLA_APP,
        .ins = SIGN_PSBT,
        .handler = (command_handler_t)handler_sign_psbt
    },
    {
        .cla = CLA_APP,
        .ins = GET_MASTER_FINGERPRINT,
        .handler = (command_handler_t)handler_get_master_fingerprint
    },
};
// clang-format on

void init_coin_config(global_context_t *coin_config) {
    memset(coin_config, 0, sizeof(global_context_t));

    // new app
    coin_config->bip32_pubkey_version = BIP32_PUBKEY_VERSION;

    // legacy
    coin_config->bip44_coin_type = BIP44_COIN_TYPE;
    coin_config->bip44_coin_type2 = BIP44_COIN_TYPE_2;
    coin_config->p2pkh_version = COIN_P2PKH_VERSION;
    coin_config->p2sh_version = COIN_P2SH_VERSION;
    coin_config->family = COIN_FAMILY;

    _Static_assert(sizeof(COIN_COINID) <= sizeof(coin_config->coinid), "COIN_COINID too large");
    strcpy(coin_config->coinid, COIN_COINID);

    _Static_assert(sizeof(COIN_COINID_NAME) <= sizeof(coin_config->name),
                   "COIN_COINID_NAME too large");

    strcpy(coin_config->name, COIN_COINID_NAME);
    // we assume in display.c that the ticker size is at most 5 characters (+ null)
    _Static_assert(sizeof(COIN_COINID_SHORT) <= 6, "COIN_COINID_SHORT too large");
    _Static_assert(sizeof(COIN_COINID_SHORT) <= sizeof(coin_config->name_short),
                   "COIN_COINID_SHORT too large");
    strcpy(coin_config->name_short, COIN_COINID_SHORT);
    _Static_assert(
        sizeof(COIN_NATIVE_SEGWIT_PREFIX) <= sizeof(coin_config->native_segwit_prefix_val),
        "COIN_NATIVE_SEGWIT_PREFIX too large");
    strcpy(coin_config->native_segwit_prefix_val, COIN_NATIVE_SEGWIT_PREFIX);
    coin_config->native_segwit_prefix = coin_config->native_segwit_prefix_val;
    coin_config->kind = COIN_KIND;
}

void app_main() {
    for (;;) {
        // Length of APDU command received in G_io_apdu_buffer
        int input_len = 0;
        // Structured APDU command
        command_t cmd;

        // Reset length of APDU response
        G_output_len = 0;

        // Receive command bytes in G_io_apdu_buffer

        input_len = io_exchange(CHANNEL_APDU | IO_ASYNCH_REPLY, 0);

        if (input_len < 0) {
            PRINTF("=> io_exchange error\n");
            return;
        }

        explicit_bzero(&G_command_state, sizeof(G_command_state));

        // Reset structured APDU command
        memset(&cmd, 0, sizeof(cmd));
        // Parse APDU command from G_io_apdu_buffer
        if (!apdu_parser(&cmd, G_io_apdu_buffer, input_len)) {
            PRINTF("=> /!\\ BAD LENGTH: %.*H\n", input_len, G_io_apdu_buffer);
            io_send_sw(SW_WRONG_DATA_LENGTH);
            return;
        }

        PRINTF("=> CLA=%02X | INS=%02X | P1=%02X | P2=%02X | Lc=%02X | CData=",
               cmd.cla,
               cmd.ins,
               cmd.p1,
               cmd.p2,
               cmd.lc);
        for (int i = 0; i < cmd.lc; i++) {
            PRINTF("%02X", cmd.data[i]);
        }
        PRINTF("\n");

        // Dispatch structured APDU command to handler
        apdu_dispatcher(COMMAND_DESCRIPTORS,
                        sizeof(COMMAND_DESCRIPTORS) / sizeof(COMMAND_DESCRIPTORS[0]),
                        (machine_context_t *) &G_command_state,
                        sizeof(G_command_state),
                        ui_menu_main,
                        &cmd);
    }
}

/**
 * Exit the application and go back to the dashboard.
 */
void app_exit() {
    BEGIN_TRY_L(exit) {
        TRY_L(exit) {
            os_sched_exit(-1);
        }
        FINALLY_L(exit) {
        }
    }
    END_TRY_L(exit);
}

/**
 * Handle APDU command received and send back APDU response using handlers.
 */
void coin_main(global_context_t *coin_config) {
    PRINT_STACK_POINTER();

    // assumptions on the length of data structures

    _Static_assert(sizeof(cx_sha256_t) <= 108, "cx_sha256_t too large");
    _Static_assert(sizeof(policy_map_key_info_t) <= 148, "policy_map_key_info_t too large");

    global_context_t config;
    if (coin_config == NULL) {
        init_coin_config(&config);
        G_coin_config = &config;
    } else {
        G_coin_config = coin_config;
    }

#if defined(HAVE_PRINT_STACK_POINTER) && defined(HAVE_BOLOS_APP_STACK_CANARY)
    PRINTF("STACK CANARY ADDRESS: %08x\n", &app_stack_canary);
#endif

#ifdef HAVE_SEMIHOSTED_PRINTF
    PRINTF("APDU State size: %d\n", sizeof(command_state_t));
#endif

    // Reset dispatcher state
    explicit_bzero(&G_dispatcher_context, sizeof(G_dispatcher_context));

    memset(G_io_apdu_buffer, 0, 255);  // paranoia

    // Process the incoming APDUs

    for (;;) {
        UX_INIT();
        BEGIN_TRY {
            TRY {
                io_seproxyhal_init();

#ifdef TARGET_NANOX
                // grab the current plane mode setting
                G_io_app.plane_mode = os_setting_get(OS_SETTING_PLANEMODE, NULL, 0);
#endif  // TARGET_NANOX

                USB_power(0);
                USB_power(1);

                ui_menu_main();

#ifdef HAVE_BLE
                BLE_power(0, NULL);
                BLE_power(1, "Nano X");
#endif  // HAVE_BLE

                app_main();
            }
            CATCH(EXCEPTION_IO_RESET) {
                // reset IO and UX
                CLOSE_TRY;
                continue;
            }
            CATCH_ALL {
                CLOSE_TRY;
                break;
            }
            FINALLY {
            }
        }
        END_TRY;
    }
    app_exit();
}

__attribute__((section(".boot"))) int main() {
    __asm volatile("cpsie i");

    // ensure exception will work as planned
    os_boot();

    io_reset_timeouts();

    coin_main(NULL);
    return 0;
}
