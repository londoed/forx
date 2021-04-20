/**
 * FORX: An open and collaborative operating system kernel for research purposes.
 *
 * Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { drivers/char/serial/com.c }.
 * Copyright (C) 2015, Matt Kilgore.
 *
 * This software is distributed under the GNU General Public License v2.0.
 * Refer to the file LICENSE for additional details.
**/

#include <forx/types.h>
#include <forx/debug.h>
#include <libctl/string.h>
#include <forx/sched.h>
#include <forx/signal.h>
#include <forx/wait.h>
#include <libctl/basic_printf.h>
#include <forx/dev.h>
#include <forx/kparam.h>
#include <forx/initcall.h>

#include <forx/event/device.h>
#include <forx/arch/spinlock.h>
#include <forx/arch/drivers/keyboard.h>
#include <forx/arch/asm.h>
#include <forx/arch/drivers/pic8259.h>
#include <forx/arch/idt.h>
#include <forx/fs/char.h>
#include <forx/drivers/tty.h>
#include <forx/drivers/com.h>

#define COM_CLOCK 115200

static int com_init_was_early = 0;

enum {
    COM1,
    COM2,
};

struct ComPort {
    Io ioport;
    int baud;
    int irq;
    int exists: 1;
    struct Tty *tty;
    struct IrqHandler handler;
};

static struct ComPort com_ports[];

static int
com_write_ready(struct ComPort *com)
{
    return inb(com->ioport + UART_LSR) & UART_LSR_THRE;
}

static void
com_int_handler(struct IrqFrame *frame, void *param)
{
    char b
    struct ComPort *com = param;

    do {
        b = inb(com->ioport + UART_RX);
        struct Tty *tty = com->tty;

        if (tty)
            tty_add_input(tty, &b, 1);
    } while (inb(com->ioport + UART_LSR) & UART_LSR_DR);
}

static struct ComPort com_ports = {
    [COM1] = {
        .ioport = 0x3F8,
        .baud = 38400,
        .irq = 4,
        .exists = 1,
        .handler = IRQ_HANDLER_INIT(com_ports[COM1].handler, "COM1", com_int_handler,
            com_ports + COM1, IRQ_INTERRUPT, 0),
    },
    [COM2] = {
        .ioport = 0x2F8,
        .baud = 38400,
        .irq = 3,
        .exists = 1,
        .handler = IRQ_HANDLER_INIT(com_ports[COM2].handler, "COM2", com_int_handler,
            com_ports + COM2, IRQ_INTERRUPT, 0);
    },
};

static void
com_init_ports_tx(void)
{
    size_t i;
    IrqFlags irq_flags = irq_save();

    irq_disable();

    for (i = 0; i < ARRAY_SIZE(com_ports); i++) {
        if (!com_ports[i].exists)
            continue;

        outb(com_ports[i].ioport + UART_IER, 0x00);
        outb(com_ports[i].ioport + UART_LCR, UART_LCR_DLAB);
        outb(com_ports[i].ioport + UART_DLL, (COM_CLOCK / com_ports[i].baud) & 0xFF);
        outb(com_ports[i].ioport + UART_DLM, (COM_CLOCK / com_ports[i].baud) >> 8);
        outb(com_ports[i].ioport + UART_LCR, UART_LCR_WLEN8);
        outb(com_ports[i].ioport + UART_FCR, UART_FCR_TRIGGER_14 | UART_FCR_CLEAR_XMIT |
            UART_FCR_CLEAR_RCVR | UART_FCR_ENABLE_FIFO);
        outb(com_ports[i].ioport + 4, 0x0B);

        if (inb(com_ports[i].ioport + UART_LSR) == 0xFF) {
            kprintf(KERN_WARN, "COM%d not found\n", i);
            com_ports[i].exists = 0;
            continue;
        }
    }

    irq_restore(irq_flags);
}

static void
com_init_ports_rx(void)
{
    size_t i;
    IrqFlags irq_flags = irq_save();

    irq_disable();

    for (i = 0; i < ARRAY_SIZE(com_ports); i++) {
        if (!com_ports[i].exists)
            continue;

        // All that's left to do here is register the RX interrupt //
        int err = irq_register_handler(com_ports[i].irq, &com_ports[i].handler);

        if (err) {
            kprintf(KERN_ERR, "COM%d: Interrupt %d is already taken\n", i, com_ports[i].irq);
            continue;
        }

        outb(com_ports[i].ioport + UART_IER, UART_ITER_RDI);

        // Clear interrupt registers after we enable them //
        inb(com_ports[i].ioport + UART_LSR);
        inb(com_ports[i].ioport + UART_RX);
        inb(com_ports[i].ioport + UART_IIR);
        inb(com_ports[i].ioport + UART_MSR);
    }

    irq_restore(irq_flags);
}

static int
com_tty_write(struct Tty *tty, const char *buf, size_t len)
{
    struct ComPort *com = com_ports + DEV_MINOR(tty->device_no);
    size_t i;

    for (i = 0; i < len; i++) {
        while (!com_write_ready(com))
            ;

        outb(com->ioport + UART_TX, buf[i]);
    }

    return len;
}

static void
com_tty_ops_init(struct Tty *tty)
{
    struct ComPort *com = com_ports + DEV_MINOR(tty->device_no);
    com->tty = tty;
}

static struct TtyOps ops = {
    .write = com_tty_write,
    .init = com_tty_ops_init,
};

static struct TtyDriver driver = {
    .major = CHAR_DEV_SERIAL_TTY,
    .minor_start = 0,
    .minor_end = 1,
    .ops = &ops,
};

static void
com_init(void)
{
    if (!com_init_was_early)
        com_init_ports_tx();

    com_init_ports_rx();
}

initcall_device(com, com_init);

static void
com_tty_init(void)
{
    kprintf(KERN_TRACE, "COM TTY INIT\n");
    tty_driver_register(&driver);
}

initcall_device(com_tty, com_tty_init);

int
com_init_early(void)
{
    com_init_ports_tx();
    com_init_was_early = 1;

    return 0;
}

static Spinlock com1_kp_sync = SPINLOCK_INIT();

static void
com1_print(struct KpOutput *out, const char *str)
{
    using_spinlock(&com1_kp_sync) {
        for (; *str; str++) {
            while (!com_write_ready(com_ports + COM1))
                ;

            outb(com_ports[COM1].ioport + UART_TX, *str);
        }
    }
}

static struct KpOutputOps com1_kp_output_ops = {
    .print = com1_print,
};

static struct KpOutput com_kp_output = KP_OUTPUT_INIT(com_kp_output, KERN_NORM, "com1", &com1_kp_output_ops);
KPARAM("com1.loglevel", &com_kp_output.max_level, KPARAM_LOGLEVEL);

void
com_kp_register(void)
{
    if (com_ports[COM1].exists)
        kp_output_register(&com_kp_output);
}

void
com_kp_unregister(void)
{
    if (com_ports[COM1].exists)
        kp_output_unregister(&com_kp_output);
}
