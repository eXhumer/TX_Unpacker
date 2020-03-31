###############################################
# TX SX OS unpacker - by hexkyz and naehrwert #
###############################################

from Crypto.Cipher import AES
from Crypto.Util import Counter
import os, struct, binascii, json, pathlib

"""
typedef struct boot_dat_hdr
{
    unsigned char ident[0x10];
    unsigned char sha2_s2[0x20];
    unsigned int s2_dst;
    unsigned int s2_size;
    unsigned int s2_enc;
    unsigned char pad[0x10];
    unsigned int s3_size;
    unsigned char pad2[0x90];
    unsigned char sha2_hdr[0x20];
} boot_dat_hdr_t;
"""

def aes_ctr_dec(buf, key, iv):
    ctr = Counter.new(128, initial_value=int(binascii.hexlify(iv), 16))
    return AES.new(key, AES.MODE_CTR, counter=ctr).encrypt(buf)

def get_ver_int(boot_ver):
    if boot_ver[1] == 0x302E3156:                                       # TX BOOT V1.0
        return 100
    elif boot_ver[1] == 0x312E3156:                                     # TX BOOT V1.1
        return 110
    elif boot_ver[1] == 0x322E3156:                                     # TX BOOT V1.2
        return 120
    elif boot_ver[1] == 0x332E3156:                                     # TX BOOT V1.3
        return 130
    elif boot_ver[1] == 0x342E3156:                                     # TX BOOT V1.4
        return 140
    elif boot_ver[1] == 0x352E3156:                                     # TX BOOT V1.5
        return 150
    elif boot_ver[1] == 0x362E3156:                                     # TX BOOT V1.6
        return 160
    elif boot_ver[1] == 0x372E3156:                                     # TX BOOT V1.7
        return 170
    elif boot_ver[1] == 0x382E3156:                                     # TX BOOT V1.8
        return 180
    elif boot_ver[1] == 0x392E3156:                                     # TX BOOT V1.9
        return 190
    elif boot_ver[1] == 0x302E3256:                                     # TX BOOT V2.0
        return 200
    elif (boot_ver[1] == 0x312E) and (boot_ver[0] == 0x302E3256):       # TX BOOT V2.0.1
        return 201
    elif (boot_ver[1] == 0) and (boot_ver[0] == 0x312E3256):            # TX BOOT V2.1
        return 210
    elif (boot_ver[1] == 0) and (boot_ver[0] == 0x322E3256):            # TX BOOT V2.2
        return 220
    elif (boot_ver[1] == 0x312E) and (boot_ver[0] == 0x322E3256):       # TX BOOT V2.2.1
        return 221
    elif (boot_ver[1] == 0) and (boot_ver[0] == 0x332E3256):            # TX BOOT V2.3
        return 230
    elif (boot_ver[1] == 0) and (boot_ver[0] == 0x342E3256):            # TX BOOT V2.4
        return 240
    elif (boot_ver[1] == 0x312E) and (boot_ver[0] == 0x342E3256):       # TX BOOT V2.4.1
        return 241
    elif (boot_ver[1] == 0) and (boot_ver[0] == 0x352E3256):            # TX BOOT V2.5
        return 250
    elif (boot_ver[1] == 0x312E) and (boot_ver[0] == 0x352E3256):       # TX BOOT V2.5.1
        return 251
    elif (boot_ver[1] == 0x322E) and (boot_ver[0] == 0x352E3256):       # TX BOOT V2.5.2
        return 252
    elif (boot_ver[1] == 0x332E) and (boot_ver[0] == 0x352E3256):       # TX BOOT V2.5.3
        return 253
    elif (boot_ver[1] == 0) and (boot_ver[0] == 0x362E3256):            # TX BOOT V2.6
        return 260
    elif (boot_ver[1] == 0x312E) and (boot_ver[0] == 0x362E3256):       # TX BOOT V2.6.1
        return 261
    elif (boot_ver[1] == 0x322E) and (boot_ver[0] == 0x362E3256):       # TX BOOT V2.6.2
        return 262
    elif (boot_ver[1] == 0) and (boot_ver[0] == 0x372E3256):            # TX BOOT V2.7
        return 270
    elif (boot_ver[1] == 0x312E) and (boot_ver[0] == 0x372E3256):       # TX BOOT V2.7.1
        return 271
    elif (boot_ver[1] == 0) and (boot_ver[0] == 0x382E3256):            # TX BOOT V2.8
        return 280
    elif (boot_ver[1] == 0) and (boot_ver[0] == 0x392E3256):            # TX BOOT V2.9
        return 290
    elif (boot_ver[1] == 0x312E) and (boot_ver[0] == 0x392E3256):       # TX BOOT V2.9.1
        return 291
    elif (boot_ver[1] == 0x322E) and (boot_ver[0] == 0x392E3256):       # TX BOOT V2.9.2
        return 292
    elif (boot_ver[1] == 0x332E) and (boot_ver[0] == 0x392E3256):       # TX BOOT V2.9.3
        return 293
    elif (boot_ver[1] == 0x342E) and (boot_ver[0] == 0x392E3256):       # TX BOOT V2.9.4
        return 294
    else:
        return 0


def main():
    f = open("boot.dat", "rb")
    b = f.read()
    f.close()

    version = get_ver_int(struct.unpack("II", b[0x08:0x10]))
    s2_base, s2_size = struct.unpack("II", b[0x30:0x38])

    with open("keys.json", "r") as keys_file:
        sx_keys = json.load(keys_file)

    s2_key = binascii.unhexlify(sx_keys["s2_key"])
    s2_ctr = binascii.unhexlify(sx_keys["s2_ctr"])

    if str(version) in sx_keys.keys():
        arm64_key = binascii.unhexlify(sx_keys[str(version)]["arm64_key"])
        arm64_ctr = binascii.unhexlify(sx_keys[str(version)]["arm64_ctr"])
        arm64_off = sx_keys[str(version)]["arm64_off"]
        arm64_size = sx_keys[str(version)]["arm64_size"]
        arm64_base = sx_keys[str(version)]["arm64_base"]

        fb_key = binascii.unhexlify(sx_keys[str(version)]["fb_key"])
        fb_ctr = binascii.unhexlify(sx_keys[str(version)]["fb_ctr"])
        fb_off = sx_keys[str(version)]["fb_off"]
        fb_size = sx_keys[str(version)]["fb_size"]
        fb_base = sx_keys[str(version)]["fb_base"]

        payload80_key = binascii.unhexlify(sx_keys[str(version)]["payload80_key"])
        payload80_ctr = binascii.unhexlify(sx_keys[str(version)]["payload80_ctr"])
        payload80_off = sx_keys[str(version)]["payload80_off"]
        payload80_size = sx_keys[str(version)]["payload80_size"]
        payload80_base = sx_keys[str(version)]["payload80_base"]

        payload90_key = binascii.unhexlify(sx_keys[str(version)]["payload90_key"])
        payload90_ctr = binascii.unhexlify(sx_keys[str(version)]["payload90_ctr"])
        payload90_off = sx_keys[str(version)]["payload90_off"]
        payload90_size = sx_keys[str(version)]["payload90_size"]
        payload90_base = sx_keys[str(version)]["payload90_base"]

        payload98_key = binascii.unhexlify(sx_keys[str(version)]["payload98_key"])
        payload98_ctr = binascii.unhexlify(sx_keys[str(version)]["payload98_ctr"])
        payload98_off = sx_keys[str(version)]["payload98_off"]
        payload98_size = sx_keys[str(version)]["payload98_size"]
        payload98_base = sx_keys[str(version)]["payload98_base"]

        payloadA0_key = binascii.unhexlify(sx_keys[str(version)]["payloadA0_key"])
        payloadA0_ctr = binascii.unhexlify(sx_keys[str(version)]["payloadA0_ctr"])
        payloadA0_off = sx_keys[str(version)]["payloadA0_off"]
        payloadA0_size = sx_keys[str(version)]["payloadA0_size"]
        payloadA0_base = sx_keys[str(version)]["payloadA0_base"]

        bootloader_key = binascii.unhexlify(sx_keys[str(version)]["bootloader_key"])
        bootloader_ctr = binascii.unhexlify(sx_keys[str(version)]["bootloader_ctr"])
        bootloader_off = sx_keys[str(version)]["bootloader_off"]
        bootloader_size = sx_keys[str(version)]["bootloader_size"]
        bootloader_base = sx_keys[str(version)]["bootloader_base"]

        assets_key = binascii.unhexlify(sx_keys[str(version)]["assets_key"])
        assets_ctr = binascii.unhexlify(sx_keys[str(version)]["assets_ctr"])
        assets_off = sx_keys[str(version)]["assets_off"]
        assets_size = sx_keys[str(version)]["assets_size"]
        assets_base = sx_keys[str(version)]["assets_base"]

        fw_key = binascii.unhexlify(sx_keys[str(version)]["fw_key"])
        fw_ctr = binascii.unhexlify(sx_keys[str(version)]["fw_ctr"])
        fw_off = sx_keys[str(version)]["fw_off"]
        fw_size = sx_keys[str(version)]["fw_size"]
    else:
        raise Exception("Unknown version of SXOS.")

    root_dir = pathlib.Path("sxos/")
    version_dir = root_dir.joinpath(f"{str(version)}/")
    apps_dir = version_dir.joinpath("apps/")
    bootloader_dir = version_dir.joinpath("bootloader/")
    firmware_dir = version_dir.joinpath("firmware/")
    init_dir = version_dir.joinpath("init/")
    patcher_dir = version_dir.joinpath("patcher/")
    payload_dir = version_dir.joinpath("payloads/")

    root_dir.mkdir(parents=True, exist_ok=True)
    apps_dir.mkdir(parents=True, exist_ok=True)
    version_dir.mkdir(parents=True, exist_ok=True)
    bootloader_dir.mkdir(parents=True, exist_ok=True)
    firmware_dir.mkdir(parents=True, exist_ok=True)
    init_dir.mkdir(parents=True, exist_ok=True)
    patcher_dir.mkdir(parents=True, exist_ok=True)
    payload_dir.mkdir(parents=True, exist_ok=True)

    # Decrypt Stage2 IRAM payload
    f = open("{1}/stage2_{0:08X}.bin".format(s2_base, init_dir), "wb")
    f.write(aes_ctr_dec(b[0x100:0x100+s2_size], s2_key, s2_ctr))
    f.close()

    # Decrypt ARM64 memory training blob
    f = open("{1}/arm64_{0:08X}.bin".format(arm64_base, init_dir), "wb")
    f.write(aes_ctr_dec(b[arm64_off:arm64_off+arm64_size], arm64_key, arm64_ctr))
    f.close()

    # Decrypt initial framebuffer binary
    f = open("{1}/fb_{0:08X}.bin".format(fb_base, init_dir), "wb")
    f.write(aes_ctr_dec(b[fb_off:fb_off+fb_size], fb_key, fb_ctr))
    f.close()

    # Decrypt first layer's obfuscation payload
    f = open("{1}/payload_{0:08X}.bin".format(payload80_base, payload_dir), "wb")
    f.write(aes_ctr_dec(b[payload80_off:payload80_off+payload80_size], payload80_key, payload80_ctr))
    f.close()

    # Decrypt second layer's obfuscation payload
    f = open("{1}/payload_{0:08X}.bin".format(payload90_base, payload_dir), "wb")
    f.write(aes_ctr_dec(b[payload90_off:payload90_off+payload90_size], payload90_key, payload90_ctr))
    f.close()

    # Decrypt third layer's obfuscation payload
    f = open("{1}/payload_{0:08X}.bin".format(payload98_base, payload_dir), "wb")
    f.write(aes_ctr_dec(b[payload98_off:payload98_off+payload98_size], payload98_key, payload98_ctr))
    f.close()

    # Decrypt fourth layer's obfuscation payload
    f = open("{1}/payload_{0:08X}.bin".format(payloadA0_base, payload_dir), "wb")
    f.write(aes_ctr_dec(b[payloadA0_off:payloadA0_off+payloadA0_size], payloadA0_key, payloadA0_ctr))
    f.close()

    # Decrypt SX OS bootloader's code and assets
    f = open("{1}/bootloader_{0:08X}.bin".format(bootloader_base, bootloader_dir), "wb")
    f.write(aes_ctr_dec(b[bootloader_off:bootloader_off+bootloader_size], bootloader_key, bootloader_ctr))
    f.write(aes_ctr_dec(b[assets_off:assets_off+assets_size], assets_key, assets_ctr))
    f.close()

    # Open final firmware binary (encrypted)
    f = open("{0}/payload_A0000000.bin".format(payload_dir), "rb")
    d = f.read()
    f.close()

    # Decrypt final firmware binary
    f = open("{0}/payload_A0000000_dec.bin".format(payload_dir), "wb")
    f.write(aes_ctr_dec(d[fw_off:fw_off+fw_size], fw_key, fw_ctr))
    f.close()

    # Open final firmware binary (decrypted)
    f = open("{0}/payload_A0000000_dec.bin".format(payload_dir), "rb")
    d = f.read()
    f.close()

    if version < 120:                                           # Old layout
        patcher_size = struct.unpack("I", d[0x10:0x14])[0]
        patcher_off = struct.unpack("I", d[0x14:0x18])[0]
        patcher_base = struct.unpack("I", d[0x18:0x1C])[0]
        patcher_crc = struct.unpack("I", d[0x1C:0x20])[0]
        patcher_hash = struct.unpack("8I", d[0x50:0x70])
            
        # Parse and store the PK11 patcher
        f = open("{1}/patcher_{0:08X}.bin".format(patcher_base, patcher_dir), "wb")
        f.write(d[patcher_off:patcher_off+patcher_size])
        f.close()

        patcher_size = struct.unpack("I", d[0x20:0x24])[0]
        patcher_off = struct.unpack("I", d[0x24:0x28])[0]
        patcher_base = struct.unpack("I", d[0x28:0x2C])[0]
        patcher_crc = struct.unpack("I", d[0x2C:0x30])[0]
        patcher_hash = struct.unpack("8I", d[0x70:0x90])

        # Parse and store the KIP1/INI1 patcher
        f = open("{1}/patcher_{0:08X}.bin".format(patcher_base, patcher_dir), "wb")
        f.write(d[patcher_off:patcher_off+patcher_size])
        f.close()

        patcher_size = struct.unpack("I", d[0x30:0x34])[0]
        patcher_off = struct.unpack("I", d[0x34:0x38])[0]
        patcher_base = struct.unpack("I", d[0x38:0x3C])[0]
        patcher_crc = struct.unpack("I", d[0x3C:0x40])[0]
        patcher_hash = struct.unpack("8I", d[0x90:0xB0])
            
        # Parse and store the kernel patcher
        f = open("{1}/patcher_{0:08X}.bin".format(patcher_base, patcher_dir), "wb")
        f.write(d[patcher_off:patcher_off+patcher_size])
        f.close()
            
        kip_size = struct.unpack("I", d[0x40:0x44])[0]
        kip_off = struct.unpack("I", d[0x44:0x48])[0]
        kip_base = struct.unpack("I", d[0x48:0x4C])[0]
        kip_crc = struct.unpack("I", d[0x4C:0x50])[0]
        kip_hash = struct.unpack("8I", d[0xB0:0xD0])

        # Parse and store the Loader KIP1
        f = open("{1}/kip_{0:08X}.bin".format(kip_base, firmware_dir), "wb")
        f.write(d[kip_off:kip_off+kip_size])
        f.close()
    else:                                                       # New layout
        patcher_size = struct.unpack("I", d[0x00:0x04])[0]
        patcher_off = struct.unpack("I", d[0x04:0x08])[0]
        patcher_base = struct.unpack("I", d[0x08:0x0C])[0]
        patcher_crc = struct.unpack("I", d[0x0C:0x10])[0]
        patcher_hash = struct.unpack("8I", d[0x10:0x30])
            
        # Parse and store the PK11 patcher
        f = open("{1}/patcher_{0:08X}.bin".format(patcher_base, patcher_dir), "wb")
        f.write(d[patcher_off:patcher_off+patcher_size])
        f.close()

        patcher_size = struct.unpack("I", d[0x30:0x34])[0]
        patcher_off = struct.unpack("I", d[0x34:0x38])[0]
        patcher_base = struct.unpack("I", d[0x38:0x3C])[0]
        patcher_crc = struct.unpack("I", d[0x3C:0x40])[0]
        patcher_hash = struct.unpack("8I", d[0x40:0x60])

        # Parse and store the KIP1/INI1 patcher
        f = open("{1}/patcher_{0:08X}.bin".format(patcher_base, patcher_dir), "wb")
        f.write(d[patcher_off:patcher_off+patcher_size])
        f.close()

        patcher_size = struct.unpack("I", d[0x60:0x64])[0]
        patcher_off = struct.unpack("I", d[0x64:0x68])[0]
        patcher_base = struct.unpack("I", d[0x68:0x6C])[0]
        patcher_crc = struct.unpack("I", d[0x6C:0x70])[0]
        patcher_hash = struct.unpack("8I", d[0x70:0x90])
            
        # Parse and store the kernel patcher
        f = open("{1}/patcher_{0:08X}.bin".format(patcher_base, patcher_dir), "wb")
        f.write(d[patcher_off:patcher_off+patcher_size])
        f.close()
            
        kip_size = struct.unpack("I", d[0x90:0x94])[0]
        kip_off = struct.unpack("I", d[0x94:0x98])[0]
        kip_base = struct.unpack("I", d[0x98:0x9C])[0]
        kip_crc = struct.unpack("I", d[0x9C:0xA0])[0]
        kip_hash = struct.unpack("8I", d[0xA0:0xC0])

        # Parse and store the Loader KIP1
        f = open("{1}/kip_{0:08X}.bin".format(kip_base, firmware_dir), "wb")
        f.write(d[kip_off:kip_off+kip_size])
        f.close()
        
        kip_size = struct.unpack("I", d[0xC0:0xC4])[0]
        kip_off = struct.unpack("I", d[0xC4:0xC8])[0]
        kip_base = struct.unpack("I", d[0xC8:0xCC])[0]
        kip_crc = struct.unpack("I", d[0xCC:0xD0])[0]
        kip_hash = struct.unpack("8I", d[0xD0:0xF0])

        # Parse and store the sm KIP1
        f = open("{1}/kip_{0:08X}.bin".format(kip_base, firmware_dir), "wb")
        f.write(d[kip_off:kip_off+kip_size])
        f.close()
            
        # New KIP file in V1.3+
        if version >= 130:
            kip_size = struct.unpack("I", d[0xF0:0xF4])[0]
            kip_off = struct.unpack("I", d[0xF4:0xF8])[0]
            kip_base = struct.unpack("I", d[0xF8:0xFC])[0]
            kip_crc = struct.unpack("I", d[0xFC:0x100])[0]
            kip_hash = struct.unpack("8I", d[0x100:0x120])

            # Parse and store the fs.mitm KIP1
            f = open("{1}/kip_{0:08X}.bin".format(kip_base, firmware_dir), "wb")
            f.write(d[kip_off:kip_off+kip_size])
            f.close()
        
        # New KIP file in V2.9+
        if version >= 290:
            kip_size = struct.unpack("I", d[0x120:0x124])[0]
            kip_off = struct.unpack("I", d[0x124:0x128])[0]
            kip_base = struct.unpack("I", d[0x128:0x12C])[0]
            kip_crc = struct.unpack("I", d[0x12C:0x130])[0]
            kip_hash = struct.unpack("8I", d[0x130:0x150])

            # Parse and store the PM KIP1
            f = open("{1}/kip_{0:08X}.bin".format(kip_base, firmware_dir), "wb")
            f.write(d[kip_off:kip_off+kip_size])
            f.close()
            
    # New application files in V1.4+
    if version >= 140:
        app_region_off = struct.unpack("I", b[0x4C:0x50])[0]
        app_region_size = (len(b) - app_region_off)
        app_region = aes_ctr_dec(b[app_region_off:app_region_off+app_region_size], fw_key, fw_ctr)
        app_header_off = 0
        app_header_size = 0x310
        app_header = app_region[app_header_off:app_header_size]
        app_entry_count = struct.unpack("I", app_header[0x00:0x04])[0]
        app_entry_size = 0x30
        
        # Store the application region header
        f = open("{0}/app_header.bin".format(apps_dir), "wb")
        f.write(app_header)
        f.close()
        
        # Parse and store the applications
        for i in range(app_entry_count):
            app_magic = struct.unpack("2I", app_header[0x10 + i * app_entry_size:0x18 + i * app_entry_size])
            app_hash = struct.unpack("8I", app_header[0x18 + i * app_entry_size:0x38 + i * app_entry_size])
            app_off = struct.unpack("I", app_header[0x38 + i * app_entry_size:0x3C + i * app_entry_size])[0]
            app_size = struct.unpack("I", app_header[0x3C + i * app_entry_size:0x40 + i * app_entry_size])[0]
            
            # ROMMENU
            if ((app_magic[0] == 0x4D454E55) and (app_magic[1] == 0x00524F4D)):
                f = open("{0}/ROMMENU.bin".format(apps_dir), "wb")
                f.write(app_region[app_off:app_off+app_size])
                f.close()
                
            # HBMENU
            if ((app_magic[0] == 0x4D454E55) and (app_magic[1] == 0x00004842)):
                f = open("{0}/HBMENU.bin".format(apps_dir), "wb")
                f.write(app_region[app_off:app_off+app_size])
                f.close()
            
            # New application files in V2.9.2+
            if version >= 292:
                # MLBIN
                if ((app_magic[0] == 0x4C42494E) and (app_magic[1] == 0x0000004D)):
                    f = open("{0}/MLBIN.bin".format(apps_dir), "wb")
                    f.write(app_region[app_off:app_off+app_size])
                    f.close()
                
                # MLMETA
                if ((app_magic[0] == 0x4D455441) and (app_magic[1] == 0x00004D4C)):
                    f = open("{0}/MLMETA.bin".format(apps_dir), "wb")
                    f.write(app_region[app_off:app_off+app_size])
                    f.close()
                
                # HBLBIN
                if ((app_magic[0] == 0x4C42494E) and (app_magic[1] == 0x00004842)):
                    f = open("{0}/HBLBIN.bin".format(apps_dir), "wb")
                    f.write(app_region[app_off:app_off+app_size])
                    f.close()
                
                # HBLMETA
                if ((app_magic[0] == 0x4D455441) and (app_magic[1] == 0x0048424C)):
                    f = open("{0}/HBLMETA.bin".format(apps_dir), "wb")
                    f.write(app_region[app_off:app_off+app_size])
                    f.close()
                    
                # FTLBIN
                if ((app_magic[0] == 0x4C42494E) and (app_magic[1] == 0x00004654)):
                    f = open("{0}/FTLBIN.bin".format(apps_dir), "wb")
                    f.write(app_region[app_off:app_off+app_size])
                    f.close()
                
                # FTLMETA
                if ((app_magic[0] == 0x4D455441) and (app_magic[1] == 0x0046544C)):
                    f = open("{0}/FTLMETA.bin".format(apps_dir), "wb")
                    f.write(app_region[app_off:app_off+app_size])
                    f.close()
                
                # CREPBIN
                if ((app_magic[0] == 0x5042494E) and (app_magic[1] == 0x00435245)):
                    f = open("{0}/CREPBIN.bin".format(apps_dir), "wb")
                    f.write(app_region[app_off:app_off+app_size])
                    f.close()
                
                # CREPMETA
                if ((app_magic[0] == 0x4D455441) and (app_magic[1] == 0x43524550)):
                    f = open("{0}/CREPMETA.bin".format(apps_dir), "wb")
                    f.write(app_region[app_off:app_off+app_size])
                    f.close()
                
                # ECLBIN
                if ((app_magic[0] == 0x4C42494E) and (app_magic[1] == 0x00004543)):
                    f = open("{0}/ECLBIN.bin".format(apps_dir), "wb")
                    f.write(app_region[app_off:app_off+app_size])
                    f.close()
                
                # ECLMETA
                if ((app_magic[0] == 0x4D455441) and (app_magic[1] == 0x0045434C)):
                    f = open("{0}/ECLMETA.bin".format(apps_dir), "wb")
                    f.write(app_region[app_off:app_off+app_size])
                    f.close()

if __name__ == "__main__":
    main()