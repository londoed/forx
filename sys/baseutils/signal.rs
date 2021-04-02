//
  // FORX: An open and collaborative operating system kernel for research purposes.
  //
  // Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { sys/baseutils/signal.rs }.
  // This Source Code Form is subject to the terms of the Mozilla Public License v2.0.
  // If a copy of the MPL was not distributed with this file, you can obtain one at:
  // https://mozilla.org/MPL/2.0/.
//

#![no_std]

use crate::schedule::*;
use crate::libctl::Deref;
use crate::arch::irq_safety::hold_interrupts;
use crate::arch::apic::get_apic_id;
use crate::kernel::task::{Task, TaskRef, get_current_task};

pub static DEFAULT_SIGNAL: usize = 16;

pub struct Signal<'a> {
    pub call: SigCall,
    pub desc: &'a str,
    pub dispo: Disposition,
}

pub enum Disposition {
    Term,
    Ign,
    Core,
    Stop,
    Cont,
}

pub enum SigCall {
    ABRT = 1,
    ALRM,
    BUS,
    CHLD,
    CONT,
    EMT,
    FPE,
    HUP,
    ILL,
    INT,
    IO,
    KILL,
    LOST,
    PIPE,
    PROF,
    PWR,
    QUIT,
    SEGV,
    STKFLT,
    STOP,
    TSTP,
    SYS,
    TERM,
    TRAP,
    TTIN,
    TTOU,
    URG,
    USR1,
    USR2,
    VTALRM,
    XCPU,
    XFSZ,
    WINCH,
}

pub static ALL_SIGNALS: [SignalCall<'static>; 33] = [
    Signal{
        call: SigCall::ABRT,
        desc: "abort",
        dispo: Disposition::Core,
    },
    Signal{
        call: SigCall::ALRM,
        desc: "timer",
        dispo: Disposition::Term,
    },
    Signal{
        call: SigCall::BUS,
        desc: "bus error",
        dispo: Disposition::Core,
    },
    Signal{
        call: SigCall::CHLD,,
        desc: "child stopped/terminated",
        dispo: Disposition::Ign,
    },
    Signal{
        call: SigCall::CONT,
        desc: "continue if stopped",
        dispo: Disposition::Cont,
    },
    Signal{
        call: SigCall::EMT,
        desc: "emulator trap",
        dispo: Disposition::Term,
    },
    Signal{
        call: SigCall::FPE,
        desc: "floating point execution",
        dispo: Disposition::Core,
    },
    Signal{
        call: SigCall::HUP,
        desc: "hangup on controlling terminal or death of controlling process",
        dispo: Disposition::Term,
    },
    Signal{
        call: SigCall::ILL,
        desc: "illegal instruction",
        dispo: Disposition::Core,
    },
    Signal{
        call: SigCall::INT,
        desc: "keyboard interrupt",
        dispo: Disposition::Term,
    },
    Signal{
        call: SigCall::IO,
        desc: "input/output",
        dispo: Disposition::Term,
    },
    Signal{
        call: SigCall::KILL,
        desc: "kill signal",
        dispo: Disposition::Term,
    },
    Signal{
        call: SigCall::LOST,
        desc: "file lock lost",
        dispo: Disposition::Term;
    },
    Signal{
        call: SigCall::PIPE,
        desc: "broken pipe",
        dispo: Disposition::Term,
    },
    Signal{
        call: SigCall::PROF,
        desc: "profiling timer expired",
        dispo: Disposition::Term,
    },
    Signal{
        call: SigCall::PWR,
        desc: "power failure",
        dispo: Disposition::Term, 
    },
    Signal{
        call: SigCall::QUIT,
        desc: "quit from keyboard",
        dispo: Disposition::Core,
    },
    Signal{
        call: SigCall::SEGV,
        desc: "invalid memory reference",
        dispo: Disposition::Core,
    },
    Signal{
        call: SigCall::STKFLT,
        desc: "stack fault on coprocessor",
        dispo: Disposition::Term,
    },
    Signal{
        call: SigCall::STOP,
        desc: "stop process",
        dispo: Disposition::Stop,
    },
    Signal{
        call: SigCall::TSTP,
        desc: "stop typed at terminal",
        dispo: Disposition::Stop,
    },
    Signal{
        call: SigCall::SYS,
        desc: "bad system call",
        dispo: Disposition::Core,
    },
    Signal{
        call: SigCall::TERM,
        desc: "termination signal",
        dispo: Disposition::Term,
    },
    Signal{
        call: SigCall::TRAP,
        desc: "trace/breakpoint trap",
        dispo: Disposition::Core,
    },
    Signal{
        call: SigCall::TTIN,
        desc: "terminal input for background process",
        dispo: Disposition::Stop,
    },
    Signal{
        call: SigCall::TTOU,
        desc: "terminal output for background process",
        dispo: Disposition::Stop,
    },
    Signal{
        call: SigCall::URG,
        desc: "urgent condition on socket",
        dispo: Disposition::Ign,
    },
    Signal{
        call: SigCall::USR1,
        desc: "user-defined signal 1",
        dispo: Disposition::Term,
    },
    Signal{
        call: SigCall::USR2,
        desc: "user-defined signal 2",
        dispo: Disposition::Term,
    },
    Signal{
        call: SigCall::VTALRM,
        desc: "virtual alarm clock",
        dispo: Disposition::Term,
    },
    Signal{
        call: SigCall::XCPU,
        desc: "cpu time limit exceeded",
        dispo: Disposition::Core,
    },
    Signal{
        call: SigCall::XFSZ,
        desc: "file size limit exceeded",
        dispo: Disposition::Core,
    },
    Signal{
        call: SigCall::WINCH,
        desc: "window resize signal",
        dispo: Disposition::Ign,
    },
];

// Should we use something like Result<(), SignalError> return type?
impl Signal {
    pub fn get_value(sig: &self) -> Option<usize> {
        if let Ok(value) = sig.call as usize {
            return Some(value);
        }

        return None
    }

    pub fn get_signal(val: usize) -> Option<SigCall> {
        if is_signal(val) {
            match val {
                1 => SigCall::ABRT,
                2 => SigCall::ALRM,
                3 => SigCall::BUS,
                4 => SigCall::CHLD,
                5 => SigCall::CONT,
                6 => SigCall::EMT,
                7 => SigCall::FPE,
                8 => SigCall::HUP,
                9 => SigCall::ILL,
                10 => SigCall::INT,
                11 => SigCall::IO,
                12 => SigCall::KILL,
                13 => SigCall::LOST,
                14 => SigCall::PIPE,
                15 => SigCall::PROF,
                16 => SigCall::PWR,
                17 => SigCall::QUIT,
                18 => SigCall::SEGV,
                19 => SigCall::STKFLT,
                20 => SigCall::STOP,
                21 => SigCall::TSTP,
                22 => SigCall::SYS,
                23 => SigCall::TERM,
                24 => SigCall::TRAP,
                25 => SigCall::TTIN,
                26 => SigCall::TTOU,
                27 => SigCall::URG,
                28 => SigCall::USR1,
                29 => SigCall::USR2,
                30 => SigCall::VTALRM,
                31 => SigCall::XCPU,
                32 => SigCall::XFSZ,
                33 => SigCall::WINCH,
                _ => None,
            }
        }

        return None
    }

    pub fn is_signal(val: usize) -> bool {
        return val <= ALL_SIGNALS.len()
    }

    pub fn get_disposition(&self) -> Option<Disposition> {
        if Ok(ret) = self.dispo {
            return Some(ret)
        }

        return None
    }
}
