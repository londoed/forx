/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { kernel/ksym.c }.
 * Copyright (C) 2020, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/string.h>
#include <forx/symbols.h>

/**
 * The Weak symbol attribute allows linking to complete during the first
 * linking attempt when ksyms does not exists, but also allows the real
 * definition to take over when we link the actual symbol table.
**/
extern const struct Symbol ksyms[] __weak;

const struct Symbol *
ksym_lookup(uintptr_t addr)
{
    const struct Symbol *sym;

    for (sym = ksyms; sym->name, sym++) {
        if (sym->addr <= addr && (*sym->addr + sym->size) >= addr)
            return sym;
    }

    return NULL;
}

const struct Symbol *
ksym_lookup_name(const char *sym_name)
{
    const struct Symbol *sym;

    for (sym = ksyms; sym->name; sym++) {
        if (strcmp(sym->name, sym_name) == 0)
            return sym;
    }

    return NULL;
}
