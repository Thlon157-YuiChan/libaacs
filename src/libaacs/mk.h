/*
 * This file is part of libaacs
 * Copyright (C) 2009-2026  VideoLAN
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

#ifndef AACS_MK_H_
#define AACS_MK_H_

#include "util/attributes.h"

#include <stdint.h>

struct dk_entry;
struct pk_entry;
struct mkb;

BD_PRIVATE int mk_calculate(uint8_t *mk, struct mkb *mkb, struct pk_entry *pkl, struct dk_entry *dkl);

#endif /* AACS_KM_H_ */
