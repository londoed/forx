//
  // FORX: An open and collaborative operating system kernel for research purposes.
  //
  // Copyright (C) 2021, Eric Londo <londoed@protonmail.com>, { libctl/vga_buffer.rs }.
  // This Source Code Form is subject to the terms of the Mozilla Public License v2.0.
  // If a copy of the MPL was not distributed with this file, you can obtain one at:
  // https://mozilla.org/MPL/2.0/.
//

const BUFFER_HEIGHT: usize = 25;
const BUFFER_WIDTH: usize = 80;

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Color {
    BLACK,
    BLUE,
    GREEN,
    CYAN,
    RED,
    MAGENTA,
    BROWN,
    LIGHT_GREY,
    DARK_GREY,
    LIGHT_BLUE,
    LIGHT_GREEN,
    LIGHT_CYAN,
    LIGHT_RED,
    PINK,
    YELLOW,
    WHITE,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
struct ColorCode(u8);

impl ColorCode {
    fn new(fg: Color, bg: Color) -> ColorCode
    {
        return ColorCode((bg as u8) << 4 | (fg as u8))
    }
}

struct ScreenChar {
    ascii_char: u8,
    color_code: ColorCode,
}

#[repr(transparent)]
struct Buffer {
    chars: [[ScreenChar; BUFFER_WIDTH]; BUFFER_HEIGHT],
}

pub struct ScreenWriter {
    col_pos: usize,
    color_code: ColorCode,
    buffer: &'static mut Buffer,
}

impl Writer {
    pub fn write_byte(&mut self, byte: u8)
    {
        b'\n' => self.newline(),
        byte => {
            if self.col_pos >= BUFFER_WIDTH {
                self.newline();
            }

            let row = BUFFER_HEIGHT - 1;
            let col = self.col_pos;
            let color_code = self.color_code;

            self.buffer.chars[row][col] = ScreenChar{
                ascii_char: byte,
                color_code,
            };

            self.col_pos += 1;
        }
    }

    pub fn write_string(&mut self, s: &str)
    {
        for byte in s.bytes() {
            match byte {
                0x20..=0x7e | b'\n' => self.write_byte(byte),
                _ => self.write_byte(0xfe),
            }
        }
    }

    fn newline(&self)
    {
        self.write_byte(b'\n');
    }
}

pub fn kprint()
{
    let mut writer = Writer{
        col_pos: 0,
        color_code: ColorCode::new(Color::YELLOW, Color::BLUE),
        buffer: unsafe {
            &mut *(0xb8000 as *mut Buffer)
        },
    }

    writer.write_byte(b'F');
    writer.write_string("ORX: ");
    writer.write_string("An open and collaborative operating system kernel!");
}


