/*
 * This file is part of libaacs
 * Copyright (C) 2009-2010  Obliter0n
 * Copyright (C) 2009-2026  npzacs
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include "mk.h"

#include "util/attributes.h"
#include "aacs.h"

#include "crypto.h"
#include "mkb.h"
#include "file/keydbcfg.h"
#include "util/logging.h"
#include "util/macro.h"
#include "util/strutl.h"

#include <string.h>


/*
 * Validate processing key using media key verification data
 */

static int _validate_pk(const uint8_t *pk,
                        const uint8_t *cvalue, const uint8_t *uv, const uint8_t *vd,
                        uint8_t *mk)
{
    int a, crypto_err;
    uint8_t dec_vd[16];
    char str[40];

    BD_DEBUG(DBG_AACS, "Validate processing key %s...\n", str_print_hex(str, pk, 16));
    BD_DEBUG(DBG_AACS, " Using:\n");
    BD_DEBUG(DBG_AACS, "   UV: %s\n", str_print_hex(str, uv, 4));
    BD_DEBUG(DBG_AACS, "   cvalue: %s\n", str_print_hex(str, cvalue, 16));
    BD_DEBUG(DBG_AACS, "   Verification data: %s\n", str_print_hex(str, vd, 16));

    crypto_err = crypto_aes128d(pk, cvalue, mk);
    if (crypto_err) {
        LOG_CRYPTO_ERROR(DBG_AACS, "decrypting media key failed", crypto_err);
        return AACS_ERROR_UNKNOWN;
    }

    for (a = 0; a < 4; a++) {
        mk[a + 12] ^= uv[a];
    }

    crypto_err = crypto_aes128d(mk, vd, dec_vd);
    if (crypto_err) {
        LOG_CRYPTO_ERROR(DBG_AACS, "decrypting media key verification data failed", crypto_err);
        return AACS_ERROR_UNKNOWN;
    }
    if (!memcmp(dec_vd, "\x01\x23\x45\x67\x89\xAB\xCD\xEF", 8)) {
        BD_DEBUG(DBG_AACS, "Processing key %s is valid!\n", str_print_hex(str, pk, 16));
        return AACS_SUCCESS;
    }

    return AACS_ERROR_NO_PK;
}

/*
 * Derive media key using full set of device keys
 */

static uint32_t _calc_v_mask(uint32_t uv)
{
    uint32_t v_mask = 0xffffffff;

    while (!(uv & ~v_mask)) {
        v_mask <<= 1;
    }

    return v_mask;
}

static int _calc_pk(const uint8_t *dk, uint8_t *pk, uint32_t uv, uint32_t v_mask, uint32_t dev_key_v_mask)
{
    unsigned char left_child[16], right_child[16];
    int crypto_err;

    crypto_err = crypto_aesg3(dk, left_child, right_child, pk);
    if (crypto_err) {
        LOG_CRYPTO_ERROR(DBG_AACS, "PK derivation failed", crypto_err);
        return AACS_ERROR_UNKNOWN;
    }

    while (dev_key_v_mask != v_mask) {

        int i;
        for (i = 31; i >= 0; i--) {
            if (!(dev_key_v_mask & (1ul << i))) {
                break;
            }
        }

        uint8_t curr_key[16];
        if (i < 0 || !(uv & (1ul << i))) {
            memcpy(curr_key, left_child, 16);
        } else {
            memcpy(curr_key, right_child, 16);
        }

        crypto_err = crypto_aesg3(curr_key, left_child, right_child, pk);
        if (crypto_err) {
            LOG_CRYPTO_ERROR(DBG_AACS, "PK derivation failed", crypto_err);
            return AACS_ERROR_UNKNOWN;
        }

        dev_key_v_mask = ((int) dev_key_v_mask) >> 1;
    }

    char str[40];
    BD_DEBUG(DBG_AACS, "Processing key: %s\n",  str_print_hex(str, pk, 16));
    return AACS_SUCCESS;
}

static dk_list *_find_dk(dk_list *dkl, uint32_t *p_dev_key_v_mask, uint32_t uv, uint32_t u_mask)
{
    uint32_t device_number = dkl->node;
    uint32_t dev_key_uv, dev_key_u_mask, dev_key_v_mask;
    unsigned key_idx = 0;

    for (; dkl; dkl = dkl->next) {
        if (device_number != dkl->node) {
            /* wrong device */
            continue;
        }
        if (!dkl->uv) {
            continue;
        }
        key_idx++;
        dev_key_uv     = dkl->uv;
        dev_key_u_mask = 0xffffffff << dkl->u_mask_shift;
        dev_key_v_mask = _calc_v_mask(dev_key_uv);

        if ((u_mask == dev_key_u_mask) &&
            ((uv & dev_key_v_mask) == (dev_key_uv & dev_key_v_mask))) {
            break;
        }
    }

    if (!dkl) {
        BD_DEBUG(DBG_AACS | DBG_CRIT, "could not find applying device key (device 0x%x)\n", device_number);
    } else {
        char str[128];
        BD_DEBUG(DBG_AACS, "Applying device key is #%d %s\n", key_idx, str_print_hex(str, dkl->key, 16));
        BD_DEBUG(DBG_AACS, "  UV: 0x%08x  U mask: 0x%08x  V mask: 0x%08x\n", dev_key_uv, dev_key_u_mask, dev_key_v_mask);
        *p_dev_key_v_mask = dev_key_v_mask;
    }

    return dkl;
}

static int _calc_mk_dks(MKB *mkb, dk_list *dkl, uint8_t *mk)
{
    /* calculate processing key and media key using device keys */

    const uint8_t *uvs, *cvalues, *mk_dv;
    unsigned num_uvs;
    size_t len;
    char str[128];

    /* get mkb data */

    uvs     = mkb_subdiff_records(mkb, &len);
    cvalues = mkb_cvalues(mkb, &len);
    mk_dv   = mkb_mk_dv(mkb);

    if (!uvs || !cvalues || !mk_dv) {
        BD_DEBUG(DBG_AACS | DBG_CRIT, "Missing MKB records (uvs %p, cvalues %p, mk_dv %p)\n",
                 (const void*)uvs, (const void*)cvalues, (const void*)mk_dv);
        return AACS_ERROR_CORRUPTED_DISC;
    }

    num_uvs = len / 5;

    if (num_uvs < 1) {
        BD_DEBUG(DBG_AACS | DBG_CRIT, "No UVS detected - corrupted disc\n");
        return AACS_ERROR_CORRUPTED_DISC;
    }

    /* loop over all known devices */

    dk_list *dk_num;
    uint32_t device_number = (uint32_t)-1;

    for (dk_num = dkl; dk_num; dk_num = dk_num->next) {

        /* find next device */

        if (device_number == dk_num->node) {
            continue;
        }
        device_number = dk_num->node;

        /* find applying subset difference */

        unsigned uvs_idx;
        uint32_t u_mask, v_mask, uv;

        for (uvs_idx = 0; uvs_idx < num_uvs; uvs_idx++) {
            const uint8_t *p_uv = uvs + 1 + 5 * uvs_idx;
            uint8_t u_mask_shift = p_uv[-1];

            uv = MKINT_BE32(p_uv);
            if (!uv) {
                continue;
            }

            if (u_mask_shift & 0xc0) {
                BD_DEBUG(DBG_AACS | DBG_CRIT, "device 0x%x is revoked\n", device_number);
                uvs_idx = num_uvs;

            } else {

                u_mask = 0xffffffff << u_mask_shift;
                v_mask = _calc_v_mask(uv);

                if (((device_number & u_mask) == (uv & u_mask)) && ((device_number & v_mask) != (uv & v_mask))) {
                    break;
                }
            }
        }

        if (uvs_idx >= num_uvs) {
            BD_DEBUG(DBG_AACS | DBG_CRIT, "could not find applying subset-difference for device 0x%x\n", device_number);
            /* try next device */
            continue;
        }

        BD_DEBUG(DBG_AACS, "Applying subset-difference for device 0x%x is #%d:\n", device_number, uvs_idx);
        BD_DEBUG(DBG_AACS,"  UV: 0x%08x  U mask: 0x%08x  V mask: 0x%08x\n", uv, u_mask, v_mask);

        /* find applying device key */

        uint32_t dev_key_v_mask = 0;
        dk_list *dk;

        dk = _find_dk(dk_num, &dev_key_v_mask, uv, u_mask);
        if (!dk) {
            /* try next device */
            continue;
        }

        /* calculate processing key */

        uint8_t pk[16];
        if (_calc_pk(dk->key, pk, uv, v_mask, dev_key_v_mask) != AACS_SUCCESS) {
            /* try next device */
            continue;
        }

        /* calculate and verify media key */

        if ( _validate_pk(pk,
                          cvalues + uvs_idx * 16,
                          uvs + 1 + uvs_idx * 5,
                          mk_dv,
                          mk)
             == AACS_SUCCESS) {

            BD_DEBUG(DBG_AACS, "Media key: %s\n", str_print_hex(str, mk, 16));
            return AACS_SUCCESS;
        }

        BD_DEBUG(DBG_AACS | DBG_CRIT, "Processing key %s is invalid!\n", str_print_hex(str, pk, 16));

        /* try next device */
    }

    return AACS_ERROR_NO_DK;
}

/*
 * Calculate media key using a set of processing keys
 */

static int _calc_mk_pks(MKB *mkb, pk_list *pkl, uint8_t *mk)
{
    int a, num_uvs = 0;
    size_t len;
    const uint8_t *rec, *uvs, *mk_dv;

    mk_dv = mkb_mk_dv(mkb);
    if (!mk_dv) {
        BD_DEBUG(DBG_AACS | DBG_CRIT, "Missing MKB DV record\n");
        return AACS_ERROR_CORRUPTED_DISC;
    }

    BD_DEBUG(DBG_AACS, "Get UVS...\n");
    uvs = mkb_subdiff_records(mkb, &len);
    rec = uvs;
    while (rec < uvs + len) {
        if (rec[0] & 0xc0)
            break;
        rec += 5;
        num_uvs++;
    }

    BD_DEBUG(DBG_AACS, "Get cvalues...\n");
    rec = mkb_cvalues(mkb, &len);
    if (!rec) {
        BD_DEBUG(DBG_AACS | DBG_CRIT, "Missing MKB CVALUES record\n");
        return AACS_ERROR_CORRUPTED_DISC;
    }

    for (; pkl; pkl = pkl->next) {
        BD_DEBUG(DBG_AACS, "Trying processing key...\n");

        for (a = 0; a < num_uvs; a++) {
            if (AACS_SUCCESS == _validate_pk(pkl->key, rec + a * 16, uvs + 1 + a * 5, mk_dv, mk)) {

                char str[40];
                BD_DEBUG(DBG_AACS, "Media key: %s\n", str_print_hex(str, mk, 16));
                return AACS_SUCCESS;
            }
        }
    }

    BD_DEBUG(DBG_AACS | DBG_CRIT, "Error calculating media key. Missing right processing key ?\n");
    return AACS_ERROR_NO_PK;
}

/*
 * entry
 */

int mk_calculate(uint8_t *mk, MKB *mkb, pk_list *pkl, dk_list *dkl)
{
    int result = AACS_ERROR_NO_PK;

    /* try device keys first */
    if (dkl) {
        result = _calc_mk_dks(mkb, dkl, mk);
    }

    if (result != AACS_SUCCESS) {
        result = _calc_mk_pks(mkb, pkl, mk);
    }

    return result;
}
