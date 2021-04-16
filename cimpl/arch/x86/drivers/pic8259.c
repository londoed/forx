/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { arch/x86/drivers/pic8259.c }.
 * Copyright (C) 2014, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/arch/asm.h>
#include <forx/spinlock.h>
#include <forx/drivers/pic8259.h>

static Spinlock irqmask_lock = SPINLOCK_INIT();
static uint16_t irqmask = 0xFFFF & ~(1 << PIC8259_IRQ_SLAVE);

static void
pic_master_set_mask(void)
{
    outb(PIC8259_IO_PIC1 + 1, irqmask & 0xFF);
}

static void
pic_slave_set_mask(void)
{
    outb(PIC8259_IO_PIC2 + 1, irqmask >> 8);
}

void
pic8259_enable_irq(int irq)
{
    using_spinlock(&irqmask_lock) {
        irqmask &= ~(1 << irq);
        pic_master_set_mask();
        pic_slave_set_mask();
    }
}

void
pic8259_disable_irq(int irq)
{
    using_spinlock(&irqmask_lock) {
        irqmask |= (1 << irq);
        pic_master_set_mask();
        pic_slave_set_mask();
    }
}

uint8_t
pic8259_read_master_isr(void)
{
    outb(PIC8259_IO_PIC1, PIC_READ_ISR);

    return inb(PIC8259_IO_PIC1);
}

uint8_t
pic8259_read_slave_isr(void)
{
    outb(PIC8259_IO_PIC2, PIC_READ_ISR);

    return inb(PIC8259_IO_PIC2);
}

void
pic8259_send_eoi(int irq)
{
    using_spinlock(&irqmask_lock) {
        /**
         * This is more complex then is normally done. This is because
         * we check the ISR registers of both PIC's to avoid sending
         * EOI's for Spurious interrupts.
        **/
        uint8_t isr = pic8259_read_slave_isr();

        // Calculate the Intno on the slace--subtract 8 //
        uint8_t ino_bit = 1 << (irq - 8);

        if (isr & ino_bit)
            outb(PIC8259_IO_PIC2, PIC8259_EOI);

        outb(PIC8259_IO_PIC1, PIC8259_EOI);
    } else {
        uint8_t isr = pic8259_read_master_isr();
        uint8_t ino_bit = 1 << irq;

        if (isr & ino_bit)
            outb(PIC8259_IO_PIC1, PIC8259_EOI);
    }
}

void
pic8259_init(void)
{
    outb(PIC8259_IO_PIC1 + 1, 0xFF);
    outb(PIC8259_IO_PIC2 + 1, 0xFF);

    outb(PIC8259_IO_PIC1, 0x11);
    outb(PIC8259_IO_PIC2, 0x11);

    outb(PIC8259_IO_PIC1 + 1, PIC8259_IRQ0);
    outb(PIC8259_IO_PIC2 + 1, PIC8259_IRQ0 + 8);

    outb(PIC8259_IO_PIC1 + 1, 1 << PIC8259_IRQ_SLAVE);
    outb(PIC8259_IO_PIC2 + 1, PIC_IRQ_SLAVE);

    outb(PIC8259_IO_PIC1 + 1, 0x01);
    outb(PIC8259_IO_PIC2 + 1, 0x01);

    pic_master_set_mask();
    pic_slave_set_mask();
}
