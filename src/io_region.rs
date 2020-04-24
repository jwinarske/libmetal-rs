#![allow(dead_code)]

use core::mem;

#[derive(Debug, PartialEq)]
enum IoError {
    InvalidVirt,
    InvalidPhys,
    InvalidPageShift,
    BadOffset,
    BadAddress,
}

/// Libmetal I/O region structure
#[derive(Debug)]
struct IoRegion<'a>  {
    /// base virtual address
    virt: *const u8,
    /// table of base physical address of each of the pages in the I/O region
    physmap: Option<&'a[*const u8]>,
    /// size of the I/O region
    pub size: usize,
    /// page shift of I/O region
    page_shift: usize,
    /// page mask of I/O region
    pub page_mask: usize,
    /// memory attribute of the I/O region
    pub mem_flags: usize,
}

impl<'a> IoRegion<'a> {
    pub fn new(virt: *const u8,
               opt_physmap: Option<&'a[*const u8]>,
               size: usize,
               page_shift: usize,
               mem_flags: usize) -> Result<IoRegion, IoError> {
        // Check for valid virtual address
        if virt.is_null() {
            return Err(IoError::InvalidVirt)
        }
        if page_shift > mem::size_of::<usize>() * 8 || (1 << page_shift) > size {
            return Err(IoError::InvalidPageShift)
        }
        if let Some(physmap) = opt_physmap {
            let page_cnt = size / (1 << page_shift);
            for i in 0..page_cnt {
                if physmap[i].is_null() {
                    return Err(IoError::InvalidPhys)
                }
            }
        }
        // TODO: implement `metal_sys_io_mem_map` -> allow end user to map physical memory by hand
        Ok(IoRegion {
            virt,
            physmap: opt_physmap,
            size,
            page_shift,
            page_mask: (1 << page_shift) - 1,
            mem_flags,
        })
    }

    fn get_virt_address(&self, offset: usize) -> Result<*const u8, IoError> {
        if offset >= self.size {
            return Err(IoError::BadOffset)
        }
        Ok(((self.virt as usize) + offset) as *const u8)
    }

    fn get_offset_from_address(&self, address: *const u8) -> Result<usize, IoError> {
        if address < self.virt || address >= self.virt.wrapping_offset(self.size as isize) {
            return Err(IoError::BadAddress)
        }
        let offset = address.wrapping_sub(self.virt as usize) as usize;
        Ok(offset)
    }

    fn get_physical_address(&self, offset: usize) -> Result<*const u8, IoError> {
        if offset >= self.size {
            return Err(IoError::BadOffset);
        }
        return match self.physmap {
            None => self.get_virt_address(offset),
            Some(map) => {
                let page = offset >> self.page_shift;
                let base_address = map[page];
                Ok(base_address.wrapping_offset((offset & self.page_mask) as isize) as *const u8)
            }
        }
    }

    fn get_page_shift(&self) -> usize {
        self.page_shift
    }

    fn set_page_shift(&mut self, page_shift: usize) -> Result<(), IoError> {
        let page_size = 1 << page_shift;
        if page_size >  self.size {
            return Err(IoError::InvalidPageShift);
        }
        self.page_shift = page_shift;
        Ok(())
    }

    pub fn read<T>(&self, offset: usize) -> Result<T, IoError> {
        if offset > self.size - mem::size_of::<T>() {
            return Err(IoError::BadOffset);
        }
        let ptr = ((self.virt as usize) + offset) as *mut T;
        Ok(unsafe { ptr.read() })
    }

    pub fn write<T>(&self, data: T, offset: usize) -> Result<(), IoError> {
        if offset > self.size - mem::size_of::<T>() {
            return Err(IoError::BadOffset);
        }
        let ptr = ((self.virt as usize) + offset) as *mut T;
        unsafe { ptr.write_volatile(data) };
        Ok(())
    }

    // TODO: "memset"-like intrinsic is not exposed yet, update when it is
    pub fn fill(&self, value: u8, offset: usize, length: usize) -> Result<(), IoError> {
        if offset + length >= self.size{
            return Err(IoError::BadOffset);
        }
        let base_ptr = ((self.virt as usize) + offset) as *mut u8;
        for i in 0..length {
            unsafe {
                let ptr = base_ptr.offset(i as isize);
                ptr.write(value);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::*;
    use super::*;

    /// Length of the buffer
    const MOCKMEMLEN: usize = 0x400; // 1kB = 0b100_0000_000
    /// Number of row to shift a single bit to have the size of a memory page
    const MOCKMEMPAGESHIFT: usize = 8; // 256B = 0x100 = 0b1_0000_000 = 1 << 8
    /// Size of a single memory page
    const MOCKMEMPAGESIZE: usize = 1 << MOCKMEMPAGESHIFT;
    /// Number of page
    const MOCKMEMPAGECNT: usize = MOCKMEMLEN / MOCKMEMPAGESIZE;
    /// Static memory buffer
    const MOCKMEMBUFF: [u8; MOCKMEMLEN] = [0; MOCKMEMLEN];

    /// Provide a fake memory structure to initialize the Ioregion
    #[derive(Clone)]
    struct MockMem {
        buff: [u8; MOCKMEMLEN],
        size: usize,
        page_shift: usize,
        page_map: [*const u8; MOCKMEMPAGECNT],
    }
    impl MockMem {
        pub fn new() -> MockMem {
            let buff = [0 as u8; MOCKMEMLEN];

            const PAGE_SIZE: usize = 1 << MOCKMEMPAGESHIFT;
            let mut page_map = [0 as *const u8; MOCKMEMPAGECNT];
            for i in 0..MOCKMEMPAGECNT {
                page_map[i] = &buff[i*PAGE_SIZE];
            }

            let mock_mem = MockMem {
                buff,
                size: MOCKMEMLEN,
                page_shift: MOCKMEMPAGESHIFT,
                page_map,
            };

            mock_mem
        }
    }

    #[test]
    /// Instantiate a new IoRegion
    fn test_new() {
        let mock_mem = MockMem::new();

        IoRegion::new(
            mock_mem.buff.as_ptr(),
            Some(mock_mem.page_map.as_ref()),
            mock_mem.size,
            mock_mem.page_shift,
            0
        ).unwrap();
    }

    #[test]
    /// Instantiate a new IoRegion with a page size larger than the memory region
    fn test_new_invalid_bit_shift() {
        let mock_mem = MockMem::new();

        let io_region = IoRegion::new(
            mock_mem.buff.as_ptr(),
            Some(mock_mem.page_map.as_ref()),
            mock_mem.size,
            mock_mem.page_shift + 5, // <- page size is bigger than the size of the memory region
            0
        );
        assert_eq!(io_region.err().unwrap(), IoError::InvalidPageShift);
    }

    #[test]
    /// Test access to the virtual region
    fn test_virt_address() {
        let mock_mem = MockMem::new();
        let io_region = IoRegion::new(
            mock_mem.buff.as_ptr(),
            Some(mock_mem.page_map.as_ref()),
            mock_mem.size,
            mock_mem.page_shift,
            0
        ).unwrap();

        assert_eq!(io_region.get_virt_address(0).unwrap(), mock_mem.buff.as_ptr());
        assert_eq!(io_region.get_virt_address(0x42).unwrap(), mock_mem.buff.as_ptr().wrapping_offset(0x42));
        assert_eq!(io_region.get_virt_address(mock_mem.size).err().unwrap(), IoError::BadOffset);
    }

    #[test]
    /// Try to get the offset from an adress in the virtual region
    fn test_offset_from_address() {
        let mock_mem = MockMem::new();
        let io_region = IoRegion::new(
            mock_mem.buff.as_ptr(),
            Some(mock_mem.page_map.as_ref()),
            mock_mem.size,
            mock_mem.page_shift,
            0
        ).unwrap();

        assert_eq!(io_region.get_offset_from_address(mock_mem.buff.as_ptr()).unwrap(), 0);
        assert_eq!(io_region.get_offset_from_address(mock_mem.buff.as_ptr().wrapping_offset(0x42)).unwrap(), 0x42);
        assert_eq!(io_region.get_offset_from_address(mock_mem.buff.as_ptr().wrapping_offset(mock_mem.size as isize)).err().unwrap(), IoError::BadAddress);
        assert_eq!(io_region.get_offset_from_address(mock_mem.buff.as_ptr().wrapping_offset((mock_mem.size + 1) as isize)).err().unwrap(), IoError::BadAddress);
        assert_eq!(io_region.get_offset_from_address(mock_mem.buff.as_ptr().wrapping_offset((-1) as isize)).err().unwrap(), IoError::BadAddress);
        assert_eq!(io_region.get_offset_from_address(0 as *const u8).err().unwrap(), IoError::BadAddress);
    }

    #[test]
    /// Try to get the offset from an address in the virtual region
    fn test_get_physical_address() {
        let mock_mem = MockMem::new();
        let io_region = IoRegion::new(
            mock_mem.buff.as_ptr(),
            Some(mock_mem.page_map.as_ref()),
            mock_mem.size,
            mock_mem.page_shift,
            0
        ).unwrap();

        assert_eq!(io_region.get_physical_address(0).unwrap(), mock_mem.page_map[0]);
        assert_eq!(io_region.get_physical_address(MOCKMEMPAGESIZE).unwrap(), mock_mem.page_map[1]);
        assert_eq!(io_region.get_physical_address(MOCKMEMPAGESIZE + 1).unwrap(), mock_mem.page_map[1].wrapping_offset(1));
        assert_eq!(io_region.get_physical_address(MOCKMEMPAGESIZE * MOCKMEMPAGECNT).err().unwrap(), IoError::BadOffset);
    }

    #[test]
    /// Test to retrieve page shift
    fn test_get_page_shift() {
        let mock_mem = MockMem::new();
        let io_region = IoRegion::new(
            mock_mem.buff.as_ptr(),
            Some(mock_mem.page_map.as_ref()),
            mock_mem.size,
            mock_mem.page_shift,
            0
        ).unwrap();

        assert_eq!(io_region.get_page_shift(), mock_mem.page_shift);
    }

    #[test]
    /// Try to set the page shift value
    fn test_set_page_shift() {
        let mock_mem = MockMem::new();
        let mut io_region = IoRegion::new(
            mock_mem.buff.as_ptr(),
            Some(mock_mem.page_map.as_ref()),
            mock_mem.size,
            mock_mem.page_shift,
            0
        ).unwrap();

        assert_eq!(io_region.set_page_shift(mock_mem.page_shift).unwrap(), ());
        assert_eq!(io_region.set_page_shift(0).unwrap(), ());
        assert_eq!(io_region.set_page_shift(MOCKMEMLEN.trailing_zeros() as usize).unwrap(), ());
        assert_eq!(io_region.set_page_shift(MOCKMEMLEN.trailing_zeros() as usize + 1).err().unwrap(), IoError::InvalidPageShift);
    }

    #[test]
    /// Try to read data
    fn test_read() {
        let mut mock_mem = MockMem::new();
        let io_region = IoRegion::new(
            mock_mem.buff.as_ptr(),
            Some(mock_mem.page_map.as_ref()),
            mock_mem.size,
            mock_mem.page_shift,
            0
        ).unwrap();

        let data_u8 = 42_u8;
        let data_u32 = 0xDEADBEEF_u32;

        mock_mem.buff[0] = data_u8;
        unsafe { *(mock_mem.buff.as_mut_ptr().offset(1) as *mut u32) = data_u32; }
        unsafe { *(mock_mem.buff.as_mut_ptr().offset((mock_mem.size - mem::size_of::<u32>()) as isize) as *mut u32) = data_u32; }

        assert_eq!(io_region.read::<u8>(0).unwrap(), data_u8);
        assert_eq!(io_region.read::<u32>(1).unwrap(), data_u32);
        assert_eq!(io_region.read::<u8>(mock_mem.size).err().unwrap(), IoError::BadOffset);
        assert_eq!(io_region.read::<u32>(mock_mem.size - mem::size_of::<u32>()).unwrap(), data_u32);
        assert_eq!(io_region.read::<u32>(mock_mem.size - mem::size_of::<u32>() + 1).err().unwrap(), IoError::BadOffset);
    }

    #[test]
    /// Try to write data
    fn test_write() {
        let mock_mem = MockMem::new();
        let io_region = IoRegion::new(
            mock_mem.buff.as_ptr(),
            Some(mock_mem.page_map.as_ref()),
            mock_mem.size,
            mock_mem.page_shift,
            0
        ).unwrap();

        let data_u8 = 42_u8;
        let data_u32 = 0xDEADBEEF_u32;

        io_region.write::<u8>(data_u8, 0).unwrap();
        io_region.write::<u32>(data_u32, 1).unwrap();
        io_region.write::<u32>(data_u32, mock_mem.size - mem::size_of::<u32>()).unwrap();

        assert_eq!(mock_mem.buff[0], data_u8);
        assert_eq!(unsafe { *(mock_mem.buff.as_ptr().offset(1) as *const u32) }, data_u32);
        assert_eq!(unsafe { *(mock_mem.buff.as_ptr().offset((mock_mem.size - mem::size_of::<u32>()) as isize) as *const u32) }, data_u32);
        assert_eq!(io_region.write::<u32>(data_u32, mock_mem.size - mem::size_of::<u32>() + 1).err().unwrap(), IoError::BadOffset);
    }

    #[test]
    /// Try to fill a part of the buffer
    fn test_fill() {
        let mock_mem = MockMem::new();
        let io_region = IoRegion::new(
            mock_mem.buff.as_ptr(),
            Some(mock_mem.page_map.as_ref()),
            mock_mem.size,
            mock_mem.page_shift,
            0
        ).unwrap();

        let data1_u8 = 42_u8;
        let length1 = 20;

        io_region.fill(data1_u8, 0, length1).unwrap();
        for i in 0..length1 {
            println!("i:{} -> {}", i, mock_mem.buff[i]);
            assert_eq!(mock_mem.buff[i], data1_u8);
        }
        assert_eq!(mock_mem.buff[length1], 0);


        let data2_u8 = 0xA5_u8;
        let length2 = 12;
        let offset2 = 4;

        io_region.fill(data2_u8, offset2, length2).unwrap();
        for i in 0..offset2 {
            println!("i:{} -> {}", i, mock_mem.buff[i]);
            assert_eq!(mock_mem.buff[i], data1_u8);
        }
        for i in offset2..offset2+length2 {
            println!("i:{} -> {}", i, mock_mem.buff[i]);
            assert_eq!(mock_mem.buff[i], data2_u8);
        }

        assert_eq!(io_region.fill(0, mock_mem.size - 4 - 1, 4).unwrap(), ());
        assert_eq!(io_region.fill(0, mock_mem.size - 4, 4).err().unwrap(), IoError::BadOffset);
    }
}
