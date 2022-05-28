# ****************************************************************************
#    Ledger App for Bitcoin
#    (c) 2021 Ledger SAS.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ****************************************************************************

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.defines

# TODO: compile with the right path restrictions
# APP_LOAD_PARAMS  = --curve secp256k1
APP_LOAD_PARAMS  = $(COMMON_LOAD_PARAMS)
APP_PATH = ""

APPVERSION_M = 2
APPVERSION_N = 0
APPVERSION_P = 5
APPVERSION   = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"


APP_STACK_SIZE = 1500

# simplify for tests
ifndef COIN
COIN=bitcoin_testnet
endif

# Custom NanoS linking script to overlap legacy globals and new globals
ifeq ($(TARGET_NAME),TARGET_NANOS)
SCRIPT_LD:=$(CURDIR)/script-nanos.ld
endif

# Flags: BOLOS_SETTINGS, GLOBAL_PIN, DERIVE_MASTER
# Dependency to Bitcoin app (for altcoins)
APP_LOAD_FLAGS=--appFlags 0xa50 --dep Bitcoin:$(APPVERSION)

# All but bitcoin app use dependency onto the bitcoin app/lib
DEFINES_LIB = USE_LIB_BITCOIN

ifeq ($(COIN),bitcoin_testnet)

# we're not using the lib :)
DEFINES_LIB=
APP_LOAD_FLAGS=--appFlags 0xa50

# Bitcoin testnet (can also be used for signet)
DEFINES   += BIP32_PUBKEY_VERSION=0x043587CF
DEFINES   += BIP44_COIN_TYPE=1
DEFINES   += BIP44_COIN_TYPE_2=1
DEFINES   += COIN_P2PKH_VERSION=111
DEFINES   += COIN_P2SH_VERSION=196
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"tb\"
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"Bitcoin\"
DEFINES   += COIN_COINID_HEADER=\"BITCOIN\"
DEFINES   += COIN_COINID_NAME=\"Bitcoin\"
DEFINES   += COIN_COINID_SHORT=\"TEST\"
DEFINES   += COIN_KIND=COIN_KIND_BITCOIN_TESTNET
DEFINES   += COIN_FLAGS=FLAG_SEGWIT_CHANGE_SUPPORT
APPNAME = "Bitcoin Test"

else ifeq ($(COIN),bitcoin)

# we're not using the lib :)
DEFINES_LIB=
APP_LOAD_FLAGS=--appFlags 0xa50

# Bitcoin mainnet
DEFINES   += BIP32_PUBKEY_VERSION=0x0488B21E
DEFINES   += BIP44_COIN_TYPE=0
DEFINES   += BIP44_COIN_TYPE_2=0
DEFINES   += COIN_P2PKH_VERSION=0
DEFINES   += COIN_P2SH_VERSION=5
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"bc\"
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"Bitcoin\"
DEFINES   += COIN_COINID_HEADER=\"BITCOIN\"
DEFINES   += COIN_COINID_NAME=\"Bitcoin\\x20Testnet\"
DEFINES   += COIN_COINID_SHORT=\"BTC\"
DEFINES   += COIN_KIND=COIN_KIND_BITCOIN
DEFINES   += COIN_FLAGS=FLAG_SEGWIT_CHANGE_SUPPORT

APPNAME = "Bitcoin"

else ifeq ($(COIN),bitcoin_testnet_lib)
# Bitcoin testnet, but using the library mechanism
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
DEFINES   += BIP44_COIN_TYPE=1
DEFINES   += BIP44_COIN_TYPE_2=1
DEFINES   += COIN_P2PKH_VERSION=111
DEFINES   += COIN_P2SH_VERSION=196
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"Bitcoin\"
DEFINES   += COIN_COINID_HEADER=\"BITCOIN\"
DEFINES   += COIN_COINID_NAME=\"Bitcoin\\x20Testnet\"
DEFINES   += COIN_COINID_SHORT=\"TEST\"
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"tb\"
DEFINES   += COIN_KIND=COIN_KIND_BITCOIN_TESTNET
DEFINES   += COIN_FLAGS=FLAG_SEGWIT_CHANGE_SUPPORT

APPNAME ="Bitcoin Test (legacy)"

APP_LOAD_PARAMS += --path $(APP_PATH)

else ifeq ($(COIN),bitcoin_lite)

# we're not using the lib :)
DEFINES_LIB=
APP_LOAD_FLAGS=--appFlags 0xa50

DEFINES   += DISABLE_LEGACY_SUPPORT

# Bitcoin mainnet, no legacy support
DEFINES   += BIP32_PUBKEY_VERSION=0x0488B21E
DEFINES   += BIP44_COIN_TYPE=0
DEFINES   += BIP44_COIN_TYPE_2=0
DEFINES   += COIN_P2PKH_VERSION=0
DEFINES   += COIN_P2SH_VERSION=5
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"bc\"
DEFINES   += COIN_COINID_SHORT=\"BTC\"

APPNAME = "Bitcoin (Lite)"

else ifeq ($(COIN),bitcoin_testnet_lite)

# we're not using the lib :)
DEFINES_LIB=
APP_LOAD_FLAGS=--appFlags 0xa50

DEFINES   += DISABLE_LEGACY_SUPPORT

# Bitcoin testnet, no legacy support
DEFINES   += BIP32_PUBKEY_VERSION=0x043587CF
DEFINES   += BIP44_COIN_TYPE=1
DEFINES   += BIP44_COIN_TYPE_2=1
DEFINES   += COIN_P2PKH_VERSION=111
DEFINES   += COIN_P2SH_VERSION=196
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"tb\"
DEFINES   += COIN_COINID_SHORT=\"TEST\"
APPNAME = "Bitcoin Test (Lite)"

else ifeq ($(COIN),bitcoin_regtest)
# This target can be used to compile a version of the app that uses regtest addresses

# we're not using the lib :)
DEFINES_LIB=
APP_LOAD_FLAGS=--appFlags 0xa50

# Bitcoin regtest test network
DEFINES   += BIP32_PUBKEY_VERSION=0x043587CF
DEFINES   += BIP44_COIN_TYPE=1
DEFINES   += BIP44_COIN_TYPE_2=1
DEFINES   += COIN_P2PKH_VERSION=111
DEFINES   += COIN_P2SH_VERSION=196
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"bcrt\"
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"Bitcoin\"
DEFINES   += COIN_COINID_HEADER=\"BITCOIN\"
DEFINES   += COIN_COINID_NAME=\"Bitcoin\"
DEFINES   += COIN_COINID_SHORT=\"TEST\"
DEFINES   += COIN_KIND=COIN_KIND_BITCOIN_TESTNET
DEFINES   += COIN_FLAGS=FLAG_SEGWIT_CHANGE_SUPPORT
APPNAME = "Bitcoin Regtest"
else ifeq ($(COIN),bitcoin_cash)
# Bitcoin cash
# Initial fork from Bitcoin, public key access is authorized. Signature is different thanks to the forkId
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
DEFINES   += BIP44_COIN_TYPE=145
DEFINES   += BIP44_COIN_TYPE_2=0
DEFINES   += COIN_P2PKH_VERSION=0
DEFINES   += COIN_P2SH_VERSION=5
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"Bitcoin\"
DEFINES   += COIN_COINID_HEADER=\"BITCOINCASH\"
DEFINES   += COIN_COINID_NAME=\"BitcoinCash\"
DEFINES   += COIN_COINID_SHORT=\"BCH\"
DEFINES   += COIN_KIND=COIN_KIND_BITCOIN_CASH
DEFINES   += COIN_FORKID=0
APPNAME ="Bitcoin Cash"
APP_LOAD_PARAMS += --path $(APP_PATH)
else ifeq ($(COIN),bitcoin_gold)
# Bitcoin Gold
# Initial fork from Bitcoin, public key access is authorized. Signature is different thanks to the forkId
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
DEFINES   += BIP44_COIN_TYPE=156
DEFINES   += BIP44_COIN_TYPE_2=0
DEFINES   += COIN_P2PKH_VERSION=38
DEFINES   += COIN_P2SH_VERSION=23
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"Bitcoin\\x20Gold\"
DEFINES   += COIN_COINID_HEADER=\"BITCOINGOLD\"
DEFINES   += COIN_COINID_NAME=\"BitcoinGold\"
DEFINES   += COIN_COINID_SHORT=\"BTG\"
DEFINES   += COIN_KIND=COIN_KIND_BITCOIN_GOLD
DEFINES   += COIN_FLAGS=FLAG_SEGWIT_CHANGE_SUPPORT
DEFINES   += COIN_FORKID=79
APPNAME ="Bitcoin Gold"
APP_LOAD_PARAMS += --path $(APP_PATH)
else ifeq ($(COIN),litecoin)
# Litecoin
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
DEFINES   += BIP44_COIN_TYPE=2
DEFINES   += BIP44_COIN_TYPE_2=2
DEFINES   += COIN_P2PKH_VERSION=48
DEFINES   += COIN_P2SH_VERSION=50
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"Litecoin\"
DEFINES   += COIN_COINID_HEADER=\"LITECOIN\"
DEFINES   += COIN_COINID_NAME=\"Litecoin\"
DEFINES   += COIN_COINID_SHORT=\"LTC\"
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"ltc\"
DEFINES   += COIN_KIND=COIN_KIND_LITECOIN
DEFINES   += COIN_FLAGS=FLAG_SEGWIT_CHANGE_SUPPORT
APPNAME ="Litecoin"
APP_LOAD_PARAMS += --path $(APP_PATH)
else ifeq ($(COIN),dogecoin)
# Doge
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
DEFINES   += BIP44_COIN_TYPE=3
DEFINES   += BIP44_COIN_TYPE_2=3
DEFINES   += COIN_P2PKH_VERSION=30
DEFINES   += COIN_P2SH_VERSION=22
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"Dogecoin\"
DEFINES   += COIN_COINID_HEADER=\"DOGECOIN\"
DEFINES   += COIN_COINID_NAME=\"Dogecoin\"
DEFINES   += COIN_COINID_SHORT=\"DOGE\"
DEFINES   += COIN_KIND=COIN_KIND_DOGE
APPNAME ="Dogecoin"
APP_LOAD_PARAMS += --path $(APP_PATH)
else ifeq ($(COIN),dash)
# Dash
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
DEFINES   += BIP44_COIN_TYPE=5
DEFINES   += BIP44_COIN_TYPE_2=5
DEFINES   += COIN_P2PKH_VERSION=76
DEFINES   += COIN_P2SH_VERSION=16
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"DarkCoin\"
DEFINES   += COIN_COINID_HEADER=\"DASH\"
DEFINES   += COIN_COINID_NAME=\"Dash\"
DEFINES   += COIN_COINID_SHORT=\"DASH\"
DEFINES   += COIN_KIND=COIN_KIND_DASH
APPNAME ="Dash"
APP_LOAD_PARAMS += --path $(APP_PATH)
else ifeq ($(COIN),zcash)
# Zcash
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
DEFINES   += BIP44_COIN_TYPE=133
DEFINES   += BIP44_COIN_TYPE_2=133
DEFINES   += COIN_P2PKH_VERSION=7352
DEFINES   += COIN_P2SH_VERSION=7357
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"Zcash\"
DEFINES   += COIN_COINID_HEADER=\"ZCASH\"
DEFINES   += COIN_COINID_NAME=\"Zcash\"
DEFINES   += COIN_COINID_SHORT=\"ZEC\"
DEFINES   += COIN_KIND=COIN_KIND_ZCASH
# Switch to Canopy over Heartwood
DEFINES   += COIN_CONSENSUS_BRANCH_ID=0xE9FF75A6
APPNAME ="Zcash"
APP_LOAD_PARAMS += --path $(APP_PATH)
else ifeq ($(COIN),horizen)
# Horizen
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
DEFINES   += BIP44_COIN_TYPE=121
DEFINES   += BIP44_COIN_TYPE_2=121
DEFINES   += COIN_P2PKH_VERSION=8329
DEFINES   += COIN_P2SH_VERSION=8342
DEFINES   += COIN_FAMILY=4
DEFINES   += COIN_COINID=\"Horizen\"
DEFINES   += COIN_COINID_HEADER=\"HORIZEN\"
DEFINES   += COIN_COINID_NAME=\"Horizen\"
DEFINES   += COINID=$(COIN)
DEFINES   += COIN_COINID_SHORT=\"ZEN\"
DEFINES   += COIN_KIND=COIN_KIND_HORIZEN
APPNAME ="Horizen"
APP_LOAD_PARAMS += --path $(APP_PATH)
else ifeq ($(COIN),komodo)
# Komodo
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
DEFINES   += BIP44_COIN_TYPE=141
DEFINES   += BIP44_COIN_TYPE_2=141
DEFINES   += COIN_P2PKH_VERSION=60
DEFINES   += COIN_P2SH_VERSION=85
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"Komodo\"
DEFINES   += COIN_COINID_HEADER=\"KOMODO\"
DEFINES   += COIN_COINID_NAME=\"Komodo\"
DEFINES   += COIN_COINID_SHORT=\"KMD\"
DEFINES   += COIN_KIND=COIN_KIND_KOMODO
APPNAME ="Komodo"
APP_LOAD_PARAMS += --path $(APP_PATH)
else ifeq ($(COIN),stratis)
# Stratis
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
DEFINES   += BIP44_COIN_TYPE=105105
DEFINES   += BIP44_COIN_TYPE_2=105105
DEFINES   += COIN_P2PKH_VERSION=75
DEFINES   += COIN_P2SH_VERSION=140
DEFINES   += COIN_FAMILY=2
DEFINES   += COIN_COINID=\"Stratis\"
DEFINES   += COIN_COINID_HEADER=\"STRATIS\"
DEFINES   += COIN_COINID_NAME=\"Stratis\"
DEFINES   += COIN_COINID_SHORT=\"STRAX\"
DEFINES   += COIN_KIND=COIN_KIND_STRATIS
DEFINES   += COIN_FLAGS=FLAG_PEERCOIN_SUPPORT
APPNAME ="Stratis"
APP_LOAD_PARAMS += --path $(APP_PATH)
else ifeq ($(COIN),xrhodium)
#Xrhodium
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
DEFINES   += BIP44_COIN_TYPE=10291
DEFINES   += BIP44_COIN_TYPE_2=10291
DEFINES   += BIP44_COIN_TYPE_2=10291
DEFINES   += COIN_P2PKH_VERSION=61
DEFINES   += COIN_P2SH_VERSION=123
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"xrhodium\"
DEFINES   += COIN_COINID_HEADER=\"XRHODIUM\"
DEFINES   += COIN_COINID_NAME=\"xRhodium\"
DEFINES   += COIN_COINID_SHORT=\"XRC\"
DEFINES   += COIN_KIND=COIN_KIND_XRHODIUM
APPNAME ="xRhodium"
APP_LOAD_PARAMS += --path $(APP_PATH)
else ifeq ($(COIN),peercoin)
# Peercoin
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
DEFINES   += BIP44_COIN_TYPE=6
DEFINES   += BIP44_COIN_TYPE_2=6
DEFINES   += COIN_P2PKH_VERSION=55
DEFINES   += COIN_P2SH_VERSION=117
DEFINES   += COIN_FAMILY=2
DEFINES   += COIN_COINID=\"PPCoin\"
DEFINES   += COIN_COINID_HEADER=\"PEERCOIN\"
DEFINES   += COIN_COINID_NAME=\"Peercoin\"
DEFINES   += COIN_COINID_SHORT=\"PPC\"
DEFINES   += COIN_KIND=COIN_KIND_PEERCOIN
DEFINES   += COIN_FLAGS=FLAG_PEERCOIN_UNITS\|FLAG_PEERCOIN_SUPPORT
APPNAME ="Peercoin"
APP_LOAD_PARAMS += --path $(APP_PATH)
else ifeq ($(COIN),pivx)
# PivX
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
# 77 was used in the Chrome apps
DEFINES   += BIP44_COIN_TYPE=119
DEFINES   += BIP44_COIN_TYPE_2=77
DEFINES   += COIN_P2PKH_VERSION=30
DEFINES   += COIN_P2SH_VERSION=13
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"DarkNet\"
DEFINES   += COIN_COINID_HEADER=\"PIVX\"
DEFINES   += COIN_COINID_NAME=\"PivX\"
DEFINES   += COIN_COINID_SHORT=\"PIVX\"
DEFINES   += COIN_KIND=COIN_KIND_PIVX
APPNAME ="PivX"
APP_LOAD_PARAMS += --path $(APP_PATH)
else ifeq ($(COIN),stealth)
# Stealth
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
DEFINES   += BIP44_COIN_TYPE=125
DEFINES   += BIP44_COIN_TYPE_2=125
DEFINES   += COIN_P2PKH_VERSION=62
DEFINES   += COIN_P2SH_VERSION=85
DEFINES   += COIN_FAMILY=4
DEFINES   += COIN_COINID=\"Stealth\"
DEFINES   += COIN_COINID_HEADER=\"STEALTH\"
DEFINES   += COIN_COINID_NAME=\"Stealth\"
DEFINES   += COIN_COINID_SHORT=\"XST\"
DEFINES   += COIN_KIND=COIN_KIND_STEALTH
DEFINES   += COIN_FLAGS=FLAG_PEERCOIN_UNITS\|FLAG_PEERCOIN_SUPPORT
APPNAME ="Stealth"
APP_LOAD_PARAMS += --path $(APP_PATH)
else ifeq ($(COIN),viacoin)
# Viacoin
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
DEFINES   += BIP44_COIN_TYPE=14
DEFINES   += BIP44_COIN_TYPE_2=14
DEFINES   += COIN_P2PKH_VERSION=71
DEFINES   += COIN_P2SH_VERSION=33
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"Viacoin\"
DEFINES   += COIN_COINID_HEADER=\"VIACOIN\"
DEFINES   += COIN_COINID_NAME=\"Viacoin\"
DEFINES   += COIN_COINID_SHORT=\"VIA\"
DEFINES   += COIN_KIND=COIN_KIND_VIACOIN
DEFINES   += COIN_FLAGS=FLAG_SEGWIT_CHANGE_SUPPORT
APPNAME ="Viacoin"
APP_LOAD_PARAMS += --path $(APP_PATH)
else ifeq ($(COIN),vertcoin)
# Vertcoin
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
# 128 was used in the Chrome apps
DEFINES   += BIP44_COIN_TYPE=28
DEFINES   += BIP44_COIN_TYPE_2=128
DEFINES   += COIN_P2PKH_VERSION=71
DEFINES   += COIN_P2SH_VERSION=5
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"Vertcoin\"
DEFINES   += COIN_COINID_HEADER=\"VERTCOIN\"
DEFINES   += COIN_COINID_NAME=\"Vertcoin\"
DEFINES   += COIN_COINID_SHORT=\"VTC\"
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"vtc\"
DEFINES   += COIN_KIND=COIN_KIND_VERTCOIN
DEFINES   += COIN_FLAGS=FLAG_SEGWIT_CHANGE_SUPPORT
APPNAME ="Vertcoin"
APP_LOAD_PARAMS += --path $(APP_PATH)
else ifeq ($(COIN),digibyte)
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
DEFINES   += BIP44_COIN_TYPE=20
DEFINES   += BIP44_COIN_TYPE_2=20
DEFINES   += COIN_P2PKH_VERSION=30
DEFINES   += COIN_P2SH_VERSION=63
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"DigiByte\"
DEFINES   += COIN_COINID_HEADER=\"DIGIBYTE\"
DEFINES   += COIN_COLOR_HDR=0x2864AE
DEFINES   += COIN_COLOR_DB=0x94B2D7
DEFINES   += COIN_COINID_NAME=\"DigiByte\"
DEFINES   += COIN_COINID_SHORT=\"DGB\"
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"dgb\"
DEFINES   += COIN_KIND=COIN_KIND_DIGIBYTE
DEFINES   += COIN_FLAGS=FLAG_SEGWIT_CHANGE_SUPPORT
APPNAME ="Digibyte"
APP_LOAD_PARAMS += --path $(APP_PATH)
else ifeq ($(COIN),qtum)
# Qtum
# Qtum can run significantly different code paths, thus is locked by the OS
# using APP_LOAD_PARAMS instead of BIP44_COIN_TYPE
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
DEFINES   += BIP44_COIN_TYPE=0
DEFINES   += BIP44_COIN_TYPE_2=0
DEFINES   += COIN_P2PKH_VERSION=58
DEFINES   += COIN_P2SH_VERSION=50
DEFINES   += COIN_FAMILY=3
DEFINES   += COIN_COINID=\"Qtum\"
DEFINES   += COIN_COINID_HEADER=\"QTUM\"
DEFINES   += COIN_COINID_NAME=\"QTUM\"
DEFINES   += COIN_COINID_SHORT=\"QTUM\"
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"qc\"
DEFINES   += COIN_KIND=COIN_KIND_QTUM
DEFINES   += COIN_FLAGS=FLAG_SEGWIT_CHANGE_SUPPORT
APPNAME ="Qtum"
APP_LOAD_PARAMS += --path "44'/88'" --path "49'/88'" --path "0'/45342'" --path "20698'/3053'/12648430'"
else ifeq ($(COIN),firo)
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
DEFINES   += BIP44_COIN_TYPE=136
DEFINES   += BIP44_COIN_TYPE_2=136
DEFINES   += COIN_P2PKH_VERSION=82
DEFINES   += COIN_P2SH_VERSION=7
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"Zcoin\"
DEFINES   += COIN_COINID_HEADER=\"FIRO\"
DEFINES   += COIN_COINID_NAME=\"Firo\"
DEFINES   += COIN_COINID_SHORT=\"FIRO\"
DEFINES   += COIN_KIND=COIN_KIND_FIRO
APPNAME ="Firo"
APP_LOAD_PARAMS += --path $(APP_PATH)
else ifeq ($(COIN),bitcoin_private)
# Bitcoin Private
# Initial fork from Bitcoin, public key access is authorized. Signature is different thanks to the forkId
# Note : might need a third lock on ZClassic
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
DEFINES   += BIP44_COIN_TYPE=183
DEFINES   += BIP44_COIN_TYPE_2=0
DEFINES   += COIN_P2PKH_VERSION=4901
DEFINES   += COIN_P2SH_VERSION=5039
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"BPrivate\"
DEFINES   += COIN_COINID_HEADER=\"BITCOINPRIVATE\"
DEFINES   += COIN_COINID_NAME=\"BPrivate\"
DEFINES   += COIN_COINID_SHORT=\"BTCP\"
DEFINES   += COIN_KIND=COIN_KIND_BITCOIN_PRIVATE
DEFINES   += COIN_FORKID=42
APPNAME ="Bitcoin Private"
APP_LOAD_PARAMS += --path $(APP_PATH)
else ifeq ($(COIN),gamecredits)
# GameCredits
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
DEFINES   += BIP44_COIN_TYPE=101
DEFINES   += BIP44_COIN_TYPE_2=101
DEFINES   += COIN_P2PKH_VERSION=38
DEFINES   += COIN_P2SH_VERSION=62
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"GameCredits\"
DEFINES   += COIN_COINID_HEADER=\"GAMECREDITS\"
DEFINES   += COIN_COINID_NAME=\"GameCredits\"
DEFINES   += COIN_COINID_SHORT=\"GAME\"
DEFINES   += COIN_KIND=COIN_KIND_GAMECREDITS
DEFINES   += COIN_FLAGS=FLAG_SEGWIT_CHANGE_SUPPORT
APPNAME ="GameCredits"
APP_LOAD_PARAMS += --path $(APP_PATH)
else ifeq ($(COIN),zclassic)
# ZClassic
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
DEFINES   += BIP44_COIN_TYPE=147
DEFINES   += BIP44_COIN_TYPE_2=147
DEFINES   += COIN_P2PKH_VERSION=7352
DEFINES   += COIN_P2SH_VERSION=7357
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"ZClassic\"
DEFINES   += COIN_COINID_HEADER=\"ZCLASSIC\"
DEFINES   += COIN_COINID_NAME=\"ZClassic\"
DEFINES   += COIN_COINID_SHORT=\"ZCL\"
DEFINES   += COIN_KIND=COIN_KIND_ZCLASSIC
APPNAME ="ZClassic"
APP_LOAD_PARAMS += --path $(APP_PATH)
else ifeq ($(COIN),xsn)
# XSN mainnet
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
DEFINES   += BIP44_COIN_TYPE=384
DEFINES   += BIP44_COIN_TYPE_2=384
DEFINES   += COIN_P2PKH_VERSION=76
DEFINES   += COIN_P2SH_VERSION=16
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"XSN\"
DEFINES   += COIN_COINID_HEADER=\"XSN\"
DEFINES   += COIN_COINID_NAME=\"XSN\"
DEFINES   += COIN_COINID_SHORT=\"XSN\"
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"xc\"
DEFINES   += COIN_KIND=COIN_KIND_XSN
DEFINES   += COIN_FLAGS=FLAG_SEGWIT_CHANGE_SUPPORT
APPNAME ="XSN"
APP_LOAD_PARAMS += --path $(APP_PATH)
else ifeq ($(COIN),nix)
# NIX
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
DEFINES   += BIP44_COIN_TYPE=400
DEFINES   += BIP44_COIN_TYPE_2=400
DEFINES   += COIN_P2PKH_VERSION=38
DEFINES   += COIN_P2SH_VERSION=53
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"NIX\"
DEFINES   += COIN_COINID_HEADER=\"NIX\"
DEFINES   += COIN_COINID_NAME=\"NIX\"
DEFINES   += COIN_COINID_SHORT=\"NIX\"
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"nix\"
DEFINES   += COIN_KIND=COIN_KIND_NIX
DEFINES   += COIN_FLAGS=FLAG_SEGWIT_CHANGE_SUPPORT
APPNAME ="NIX"
APP_LOAD_PARAMS += --path $(APP_PATH)
else ifeq ($(COIN),lbry)
# LBRY
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
DEFINES   += BIP44_COIN_TYPE=140
DEFINES   += BIP44_COIN_TYPE_2=140
DEFINES   += COIN_P2PKH_VERSION=85
DEFINES   += COIN_P2SH_VERSION=122
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"LBRY\"
DEFINES   += COIN_COINID_HEADER=\"LBRY\"
DEFINES   += COIN_COINID_NAME=\"LBRY\"
DEFINES   += COIN_COINID_SHORT=\"LBC\"
DEFINES   += COIN_KIND=COIN_KIND_LBRY
APPNAME ="LBRY"
APP_LOAD_PARAMS += --path $(APP_PATH)
else ifeq ($(COIN),resistance)
# Resistance
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
DEFINES   += BIP44_COIN_TYPE=356
DEFINES   += BIP44_COIN_TYPE_2=356
DEFINES   += COIN_P2PKH_VERSION=7063
DEFINES   += COIN_P2SH_VERSION=7068
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"Res\"
DEFINES   += COIN_COINID_HEADER=\"RES\"
DEFINES   += COIN_COINID_NAME=\"Res\"
DEFINES   += COIN_COINID_SHORT=\"RES\"
DEFINES   += COIN_KIND=COIN_KIND_RESISTANCE
APPNAME ="Resistance"
APP_LOAD_PARAMS += --path $(APP_PATH)
else ifeq ($(COIN),ravencoin)
# Ravencoin
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
DEFINES   += BIP44_COIN_TYPE=175
DEFINES   += BIP44_COIN_TYPE_2=175
DEFINES   += COIN_P2PKH_VERSION=60
DEFINES   += COIN_P2SH_VERSION=122
DEFINES   += COIN_FAMILY=1
DEFINES   += COIN_COINID=\"Ravencoin\"
DEFINES   += COIN_COINID_HEADER=\"RAVENCOIN\"
DEFINES   += COIN_COINID_NAME=\"Ravencoin\"
DEFINES   += COIN_COINID_SHORT=\"RVN\"
DEFINES   += COIN_KIND=COIN_KIND_RAVENCOIN
APPNAME ="Ravencoin"
APP_LOAD_PARAMS += --path $(APP_PATH)
else ifeq ($(COIN),hydra_testnet)
# Hydra testnet
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
DEFINES   += BIP44_COIN_TYPE=0
DEFINES   += BIP44_COIN_TYPE_2=0
DEFINES   += COIN_P2PKH_VERSION=66
DEFINES   += COIN_P2SH_VERSION=128
DEFINES   += COIN_FAMILY=3
DEFINES   += COIN_COINID=\"Hydra\"
DEFINES   += COIN_COINID_HEADER=\"HYDRA\"
DEFINES   += COIN_COINID_NAME=\"HYDRA\"
DEFINES   += COIN_COINID_SHORT=\"HYDRA\"
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"hc\"
DEFINES   += COIN_KIND=COIN_KIND_HYDRA
DEFINES   += COIN_FLAGS=FLAG_SEGWIT_CHANGE_SUPPORT
APPNAME ="Hydra Test"
APP_LOAD_PARAMS += --path "44'/609'"
else ifeq ($(COIN),hydra)
# Hydra mainnet
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
DEFINES   += BIP44_COIN_TYPE=0
DEFINES   += BIP44_COIN_TYPE_2=0
DEFINES   += COIN_P2PKH_VERSION=40
DEFINES   += COIN_P2SH_VERSION=63
DEFINES   += COIN_FAMILY=3
DEFINES   += COIN_COINID=\"Hydra\"
DEFINES   += COIN_COINID_HEADER=\"HYDRA\"
DEFINES   += COIN_COINID_NAME=\"HYDRA\"
DEFINES   += COIN_COINID_SHORT=\"HYDRA\"
DEFINES   += COIN_NATIVE_SEGWIT_PREFIX=\"hc\"
DEFINES   += COIN_KIND=COIN_KIND_HYDRA
DEFINES   += COIN_FLAGS=FLAG_SEGWIT_CHANGE_SUPPORT
APPNAME ="Hydra"
APP_LOAD_PARAMS += --path "44'/609'"
else ifeq ($(COIN),navcoin)
# Navcoin
DEFINES   += BIP32_PUBKEY_VERSION=0x00000000 # unused
DEFINES   += BIP44_COIN_TYPE=0
DEFINES   += BIP44_COIN_TYPE_2=0
DEFINES   += COIN_P2PKH_VERSION=53
DEFINES   += COIN_P2SH_VERSION=85
DEFINES   += COIN_FAMILY=2
DEFINES   += COIN_COINID=\"Navcoin\"
DEFINES   += COIN_COINID_HEADER=\"NAVCOIN\"
DEFINES   += COIN_COINID_NAME=\"Navcoin\"
DEFINES   += COIN_COINID_SHORT=\"NAV\"
DEFINES   += COIN_KIND=COIN_KIND_NAV
APPNAME ="Navcoin"
APP_LOAD_PARAMS += --path $(APP_PATH)
else
ifeq ($(filter clean,$(MAKECMDGOALS)),)
$(error Unsupported COIN - use bitcoin_testnet, bitcoin, bitcoin_cash, bitcoin_gold, litecoin, dogecoin, dash, zcash, horizen, komodo, stratis, peercoin, pivx, viacoin, vertcoin, stealth, digibyte, qtum, bitcoin_private, firo, gamecredits, zclassic, xsn, nix, lbry, resistance, ravencoin, hydra, hydra_testnet, xrhodium, navcoin)
endif
endif

APP_LOAD_PARAMS += $(APP_LOAD_FLAGS)
DEFINES += $(DEFINES_LIB)

ifeq ($(TARGET_NAME),TARGET_NANOS)
ICONNAME=icons/nanos_app_$(COIN).gif
else
ICONNAME=icons/nanox_app_$(COIN).gif
endif

all: default

# TODO: double check if all those flags are still relevant/needed (was copied from legacy app-bitcoin)

DEFINES   += APPNAME=\"$(APPNAME)\"
DEFINES   += APPVERSION=\"$(APPVERSION)\"
DEFINES   += MAJOR_VERSION=$(APPVERSION_M) MINOR_VERSION=$(APPVERSION_N) PATCH_VERSION=$(APPVERSION_P)
DEFINES   += OS_IO_SEPROXYHAL
DEFINES   += HAVE_BAGL HAVE_SPRINTF HAVE_SNPRINTF_FORMAT_U
DEFINES   += HAVE_IO_USB HAVE_L4_USBLIB IO_USB_MAX_ENDPOINTS=4 IO_HID_EP_LENGTH=64 HAVE_USB_APDU
DEFINES   += LEDGER_MAJOR_VERSION=$(APPVERSION_M) LEDGER_MINOR_VERSION=$(APPVERSION_N) LEDGER_PATCH_VERSION=$(APPVERSION_P) TCS_LOADER_PATCH_VERSION=0
DEFINES   += HAVE_UX_FLOW

DEFINES   += HAVE_WEBUSB WEBUSB_URL_SIZE_B=0 WEBUSB_URL=""

DEFINES   += UNUSED\(x\)=\(void\)x
DEFINES   += APPVERSION=\"$(APPVERSION)\"

DEFINES   += HAVE_BOLOS_APP_STACK_CANARY


ifeq ($(TARGET_NAME),TARGET_NANOS)
DEFINES       += IO_SEPROXYHAL_BUFFER_SIZE_B=72
DEFINES       += HAVE_WALLET_ID_SDK
else
DEFINES       += IO_SEPROXYHAL_BUFFER_SIZE_B=300
DEFINES       += HAVE_BAGL BAGL_WIDTH=128 BAGL_HEIGHT=64
DEFINES       += HAVE_BAGL_ELLIPSIS # long label truncation feature
DEFINES       += HAVE_BAGL_FONT_OPEN_SANS_REGULAR_11PX
DEFINES       += HAVE_BAGL_FONT_OPEN_SANS_EXTRABOLD_11PX
DEFINES       += HAVE_BAGL_FONT_OPEN_SANS_LIGHT_16PX
endif

ifeq ($(TARGET_NAME),TARGET_NANOX)
DEFINES       += HAVE_BLE BLE_COMMAND_TIMEOUT_MS=2000
DEFINES       += HAVE_BLE_APDU # basic ledger apdu transport over BLE
endif

ifeq ($(TARGET_NAME),TARGET_NANOS)
    # enables optimizations using the shared 1K CXRAM region
    DEFINES   += USE_CXRAM_SECTION
endif

# debugging helper functions and macros
CFLAGS    += -include debug-helpers/debug.h

# DEFINES   += HAVE_PRINT_STACK_POINTER

ifndef DEBUG
        DEBUG = 0
endif

ifeq ($(DEBUG),0)
        DEFINES   += PRINTF\(...\)=
else
        ifeq ($(DEBUG),10)
                $(warning Using semihosted PRINTF. Only run with speculos!)
                DEFINES   += HAVE_PRINTF HAVE_SEMIHOSTED_PRINTF PRINTF=semihosted_printf
        else
                ifeq ($(TARGET_NAME),TARGET_NANOS)
                        DEFINES   += HAVE_PRINTF PRINTF=screen_printf
                else
                        DEFINES   += HAVE_PRINTF PRINTF=mcu_usb_printf
                endif
        endif
endif


# Needed to be able to include the definition of G_cx
INCLUDES_PATH += $(BOLOS_SDK)/lib_cxng/src


ifneq ($(BOLOS_ENV),)
$(info BOLOS_ENV=$(BOLOS_ENV))
CLANGPATH := $(BOLOS_ENV)/clang-arm-fropi/bin/
GCCPATH   := $(BOLOS_ENV)/gcc-arm-none-eabi-5_3-2016q1/bin/
else
$(info BOLOS_ENV is not set: falling back to CLANGPATH and GCCPATH)
endif
ifeq ($(CLANGPATH),)
$(info CLANGPATH is not set: clang will be used from PATH)
endif
ifeq ($(GCCPATH),)
$(info GCCPATH is not set: arm-none-eabi-* will be used from PATH)
endif

CC      := $(CLANGPATH)clang
CFLAGS  += -Oz
AS      := $(GCCPATH)arm-none-eabi-gcc
LD      := $(GCCPATH)arm-none-eabi-gcc
LDFLAGS += -O3 -Os
LDLIBS  += -lm -lgcc -lc

include $(BOLOS_SDK)/Makefile.glyphs

APP_SOURCE_PATH += src
SDK_SOURCE_PATH += lib_stusb lib_stusb_impl lib_ux

ifeq ($(TARGET_NAME),TARGET_NANOX)
    SDK_SOURCE_PATH += lib_blewbxx lib_blewbxx_impl
endif

load: all
	python3 -m ledgerblue.loadApp $(APP_LOAD_PARAMS)

load-offline: all
	python3 -m ledgerblue.loadApp $(APP_LOAD_PARAMS) --offline

delete:
	python3 -m ledgerblue.deleteApp $(COMMON_DELETE_PARAMS)

include $(BOLOS_SDK)/Makefile.rules

dep/%.d: %.c Makefile


# Temporary restriction until we a Resistance Nano X icon
ifeq ($(TARGET_NAME),TARGET_NANOS)
listvariants:
	@echo VARIANTS COIN bitcoin_testnet bitcoin bitcoin_cash bitcoin_gold litecoin dogecoin dash zcash horizen komodo stratis peercoin pivx viacoin vertcoin stealth digibyte qtum bitcoin_private firo gamecredits zclassic xsn nix lbry ravencoin resistance hydra hydra_testnet xrhodium navcoin
else
listvariants:
	@echo VARIANTS COIN bitcoin_testnet bitcoin bitcoin_cash bitcoin_gold litecoin dogecoin dash zcash horizen komodo stratis peercoin pivx viacoin vertcoin stealth digibyte qtum bitcoin_private firo gamecredits zclassic xsn nix lbry ravencoin hydra hydra_testnet xrhodium navcoin
endif


# Makes a detailed report of code and data size in debug/size-report.txt
# More useful for production builds with DEBUG=0
size-report: bin/app.elf
	arm-none-eabi-nm --print-size --size-sort --radix=d bin/app.elf >debug/size-report.txt
