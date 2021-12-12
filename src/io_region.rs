#![allow(dead_code)]

use core::mem;

#[derive(Debug, PartialEq)]
enum IoError {
    InvalidPhys,
    InvalidPageShift,
    BadOffset,
    BadAddress,
}

/// Physical map of the memory with given page size
struct PhyMap<'a> {
    /// Table of base physical address of each of the pages in the I/O region
    pub map: &'a mut [*const u8],
    /// Page shift of the I/O region
    /// The page size is derived from this as `1 << page_shift`
    pub page_shift: usize,
}

impl<'a> PhyMap<'a> {
    /// Return the size of a page
    pub const fn page_size(&self) -> usize {
        1 << self.page_shift
    }

    /// Return the bit mask for masking the memory range for a page
    pub const fn page_mask(&self) -> usize {
        self.page_size() - 1
    }
}

/// Libmetal I/O region structure
/// If `phy_map` is `None`, `virt` is not mapped to another region
struct IoRegion<'a> {
    /// Virtual array
    pub virt: *const u8,
    /// Size of memory
    pub size: usize,
    /// Optional tuple with the table of base physical address of each of the pages in the I/O region and the number of entries
    pub phy_map: Option<&'a PhyMap<'a>>,
}

impl<'a> IoRegion<'a> {
    pub fn new(
        virt: *const u8,
        size: usize,
        phy_map: Option<&'a PhyMap<'a>>,
    ) -> Result<IoRegion<'a>, IoError> {
        if let Some(phy_map) = phy_map {
            // Check for valid page size derived from the number of bits to shift
            let page_size = phy_map.page_mask();
            if page_size > size {
                return Err(IoError::InvalidPageShift);
            }
            // TODO: verify that pages are not overlapping each others
        }
        Ok(IoRegion {
            virt,
            size,
            phy_map,
        })
    }

    /// Return the virtual address at a specified offset
    fn get_virt_address(&self, offset: usize) -> Result<*const u8, IoError> {
        if offset >= self.size {
            return Err(IoError::BadOffset);
        }
        Ok(((self.virt as usize) + offset) as *const u8)
    }

    /// Return the offset from the base virtual address at a specified address
    fn get_offset_from_address(&self, address: *const u8) -> Result<usize, IoError> {
        if address < self.virt || address >= self.virt.wrapping_add(self.size) {
            return Err(IoError::BadAddress);
        }
        let offset = address.wrapping_sub(self.virt as usize) as usize;
        Ok(offset)
    }

    /// Return the physical address at a specified offset
    fn get_physical_address(&self, offset: usize) -> Result<*const u8, IoError> {
        if offset >= self.size {
            return Err(IoError::BadOffset);
        }

        match self.phy_map {
            None => self.get_virt_address(offset),
            Some(phy_map) => {
                let page_number = offset >> phy_map.page_shift;
                let base_address = phy_map.map[page_number] as *const u8;
                Ok(
                    base_address.wrapping_add(offset & phy_map.page_mask())
                        as *const u8,
                )
            }
        }
    }

    /// Read a value of type `T` at a specified offset from virt memory
    pub fn read<T>(&self, offset: usize) -> Result<T, IoError> {
        // Check for overflow
        if offset > self.size - mem::size_of::<T>() {
            return Err(IoError::BadOffset);
        }
        let ptr = ((self.virt as usize) + offset) as *mut T;
        Ok(unsafe { ptr.read_volatile() })
    }

    pub fn write<T>(&mut self, data: T, offset: usize) -> Result<(), IoError> {
        // Check for overflow
        if offset > self.size - mem::size_of::<T>() {
            return Err(IoError::BadOffset);
        }
        let ptr = ((self.virt as usize) + offset) as *mut T;
        unsafe { ptr.write_volatile(data) };
        Ok(())
    }

    // TODO: "memset"-like intrinsic is not exposed yet, update when it is
    pub fn fill(&mut self, value: u8, offset: usize, length: usize) -> Result<(), IoError> {
        // Check for overflow
        if offset + length >= self.size {
            return Err(IoError::BadOffset);
        }
        let base_ptr = ((self.virt as usize) + offset) as *mut u8;
        for i in 0..length {
            unsafe {
                let ptr = base_ptr.add(i);
                ptr.write(value);
            };
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::*;

    /// Length of the buffer
    const MOCK_MEM_BUFF_SIZE: usize = 0x400; // 1kB = 0b100_0000_000
    /// Number of row to shift a single bit to have the size of a memory page
    const MOCK_MEM_PAGE_SHIFT: usize = 8; // 256B = 0x100 = 0b1_0000_000 = 1 << 8
    /// Size of a single memory page
    const MOCK_MEM_PAGE_SIZE: usize = 1 << MOCK_MEM_PAGE_SHIFT;
    /// Number of page
    const MOCK_MEM_PAGE_CNT: usize = MOCK_MEM_BUFF_SIZE / MOCK_MEM_PAGE_SIZE;
    /// Static memory buffer
    static mut MOCK_MEM_BUFF: [u8; MOCK_MEM_BUFF_SIZE] = [0; MOCK_MEM_BUFF_SIZE];
    /// Statically allocated page map
    static mut MOCK_MEM_PAGE_MAP: [*const u8; MOCK_MEM_PAGE_CNT] =
        [0 as *const u8; MOCK_MEM_PAGE_CNT];

    /// Provide a fake memory structure to initialize the IoRegion
    struct MockMem<'a> {
        buff: *const u8,
        size: usize,
        phy_map: PhyMap<'a>,
    }
    impl<'a> MockMem<'a> {
        pub fn new() -> MockMem<'a> {
            // Fill the page map with the address of each page
            const PAGE_SIZE: usize = 1 << MOCK_MEM_PAGE_SHIFT;
            for i in 0..MOCK_MEM_PAGE_CNT {
                unsafe {
                    MOCK_MEM_PAGE_MAP[i] = MOCK_MEM_BUFF[i * PAGE_SIZE] as *const u8;
                }
            }

            // Create the physical memory map
            let phy_map = PhyMap {
                map: unsafe { &mut MOCK_MEM_PAGE_MAP },
                page_shift: MOCK_MEM_PAGE_SHIFT,
            };

            // Return the mock mem struct
            MockMem {
                buff: unsafe { MOCK_MEM_BUFF.as_ptr() },
                size: MOCK_MEM_BUFF_SIZE,
                phy_map,
            }
        }
    }

    #[test]
    /// Instantiate a new IoRegion
    fn test_new() {
        let mock_mem = MockMem::new();

        // Should not throw error
        IoRegion::new(mock_mem.buff, mock_mem.size, Some(&mock_mem.phy_map)).unwrap();
    }

    #[test]
    /// Instantiate a new IoRegion with a page size larger than the memory region
    fn test_new_invalid_page_size() {
        let mut mock_mem = MockMem::new();
        // Put an invalid page shift (page size is 1 bit bigger than memory size)
        mock_mem.phy_map.page_shift = (MOCK_MEM_BUFF_SIZE as u32).trailing_zeros() as usize + 2;

        let io_region = IoRegion::new(mock_mem.buff, mock_mem.size, Some(&mock_mem.phy_map));
        assert_eq!(io_region.err().unwrap(), IoError::InvalidPageShift);
    }

    #[test]
    /// Test access to the virtual region
    fn test_virt_address() {
        let mock_mem = MockMem::new();
        let io_region =
            IoRegion::new(mock_mem.buff, mock_mem.size, Some(&mock_mem.phy_map)).unwrap();

        assert_eq!(io_region.get_virt_address(0).unwrap(), mock_mem.buff);
        assert_eq!(
            io_region.get_virt_address(0x42).unwrap(),
            mock_mem.buff.wrapping_offset(0x42)
        );
        assert_eq!(
            io_region.get_virt_address(mock_mem.size).err().unwrap(),
            IoError::BadOffset
        );
    }

    #[test]
    /// Try to get the offset from an address in the virtual region
    fn test_offset_from_address() {
        let mock_mem = MockMem::new();
        let io_region =
            IoRegion::new(mock_mem.buff, mock_mem.size, Some(&mock_mem.phy_map)).unwrap();

        assert_eq!(io_region.get_offset_from_address(mock_mem.buff).unwrap(), 0);
        assert_eq!(
            io_region
                .get_offset_from_address(mock_mem.buff.wrapping_offset(0x42))
                .unwrap(),
            0x42
        );
        assert_eq!(
            io_region
                .get_offset_from_address(mock_mem.buff.wrapping_offset(mock_mem.size as isize))
                .err()
                .unwrap(),
            IoError::BadAddress
        );
        assert_eq!(
            io_region
                .get_offset_from_address(
                    mock_mem.buff.wrapping_offset((mock_mem.size + 1) as isize)
                )
                .err()
                .unwrap(),
            IoError::BadAddress
        );
        assert_eq!(
            io_region
                .get_offset_from_address(mock_mem.buff.wrapping_offset((-1) as isize))
                .err()
                .unwrap(),
            IoError::BadAddress
        );
        assert_eq!(
            io_region
                .get_offset_from_address(0 as *const u8)
                .err()
                .unwrap(),
            IoError::BadAddress
        );
    }

    #[test]
    /// Try to get the offset from an address in the virtual region
    fn test_get_physical_address() {
        let mock_mem = MockMem::new();
        let io_region =
            IoRegion::new(mock_mem.buff, mock_mem.size, Some(&mock_mem.phy_map)).unwrap();

        assert_eq!(
            io_region.get_physical_address(0).unwrap(),
            mock_mem.phy_map.map[0] as *const u8
        );
        assert_eq!(
            io_region.get_physical_address(MOCK_MEM_PAGE_SIZE).unwrap(),
            mock_mem.phy_map.map[1] as *const u8
        );
        assert_eq!(
            io_region
                .get_physical_address(MOCK_MEM_PAGE_SIZE + 1)
                .unwrap(),
            (mock_mem.phy_map.map[1] as *const u8).wrapping_offset(1)
        );
        assert_eq!(
            io_region
                .get_physical_address(MOCK_MEM_PAGE_SIZE * MOCK_MEM_PAGE_CNT)
                .err()
                .unwrap(),
            IoError::BadOffset
        );
    }

    #[test]
    /// Try to read data
    fn test_read() {
        let mock_mem = MockMem::new();

        // Prepare some known values
        let data_u8 = 42_u8;
        let data_u32 = 0xDEAD_BEEF_u32;

        // Write 42 in the first byte
        unsafe {
            (mock_mem.buff.offset(0) as *mut u8).write_volatile(data_u8);
        }
        // Write 0xDEAD_BEEF from the 2nd to 5th bytes
        unsafe {
            (mock_mem.buff.offset(1) as *mut u32).write_volatile(data_u32);
        }
        // Write 0xDEAD_BEEF in the last 4 bytes
        unsafe {
            (mock_mem
                .buff
                .offset((mock_mem.size - mem::size_of::<u32>()) as isize) as *mut u32)
                .write_volatile(data_u32);
        }

        let io_region =
            IoRegion::new(mock_mem.buff, mock_mem.size, Some(&mock_mem.phy_map)).unwrap();

        // Check that we can read 42 as the first byte in the virtual memory
        assert_eq!(io_region.read::<u8>(0).unwrap(), data_u8);

        // Check that we can read 0xDEAD_BEEF at the offset 1
        assert_eq!(io_region.read::<u32>(1).unwrap(), data_u32);

        // Check that reading from an out-of-bound offset return a BadOffset error
        assert_eq!(
            io_region.read::<u8>(mock_mem.size).err().unwrap(),
            IoError::BadOffset
        );

        // Check that reading the last 4 byte return 0xDEAD_BEEF
        assert_eq!(
            io_region
                .read::<u32>(mock_mem.size - mem::size_of::<u32>())
                .unwrap(),
            data_u32
        );

        // Check that we can't read an object than will have some bytes out of the memory space
        assert_eq!(
            io_region
                .read::<u32>(mock_mem.size - mem::size_of::<u32>() + 1)
                .err()
                .unwrap(),
            IoError::BadOffset
        );
    }

    #[test]
    /// Try to write data
    fn test_write() {
        let mock_mem = MockMem::new();
        let mut io_region =
            IoRegion::new(mock_mem.buff, mock_mem.size, Some(&mock_mem.phy_map)).unwrap();

        // Prepare some known values
        let data_u8 = 42_u8;
        let data_u32 = 0xDEADBEEF_u32;

        // Write the values in the virtual memory
        io_region.write::<u8>(data_u8, 0).unwrap();
        io_region.write::<u32>(data_u32, 1).unwrap();
        io_region
            .write::<u32>(data_u32, mock_mem.size - mem::size_of::<u32>())
            .unwrap();

        // Check that we properly wrote 42 as the first byte in the buffer
        assert_eq!(unsafe { *(mock_mem.buff.offset(0) as *const u8) }, data_u8);

        // Check that we properly wrote 0xDEAD_BEEF at offset 1
        assert_eq!(
            unsafe { *(mock_mem.buff.offset(1) as *const u32) },
            data_u32
        );

        // Check that we properly wrote 0xDEAD_BEEF to the last 4 bytes of the buffer
        assert_eq!(
            unsafe {
                *(mock_mem
                    .buff
                    .offset((mock_mem.size - mem::size_of::<u32>()) as isize)
                    as *const u32)
            },
            data_u32
        );

        // Check that writing an object out of memory space return BadOffset
        assert_eq!(
            io_region.write::<u8>(data_u8, mock_mem.size).err().unwrap(),
            IoError::BadOffset
        );

        // Check that writing an object that will have some bytes out of the memory space return BadOffset
        assert_eq!(
            io_region
                .write::<u32>(data_u32, mock_mem.size - mem::size_of::<u32>() + 1)
                .err()
                .unwrap(),
            IoError::BadOffset
        );
    }

    #[test]
    /// Try to fill a part of the buffer
    fn test_fill() {
        let mock_mem = MockMem::new();
        let mut io_region =
            IoRegion::new(mock_mem.buff, mock_mem.size, Some(&mock_mem.phy_map)).unwrap();

        // Fill the 20 first bytes with 42
        let data1_u8 = 42_u8;
        let length1 = 20;

        io_region.fill(data1_u8, 0, length1).unwrap();
        for i in 0..length1 {
            // Print for debug
            println!("i:{} -> {}", i, unsafe {
                *(mock_mem.buff.offset(i as isize) as *mut u8)
            });
            // Check that every byte if properly written
            assert_eq!(
                unsafe { *(mock_mem.buff.offset(i as isize) as *mut u8) },
                data1_u8
            );
        }

        // Check that we only wrote until length-1, the buffer in 0-initialized
        assert_eq!(
            unsafe { *(mock_mem.buff.offset(length1 as isize) as *mut u8) },
            0
        );

        // Fill 12 bytes from offset 4, overwriting some previous values
        let data2_u8 = 0xA5_u8;
        let length2 = 12;
        let offset2 = 4;

        io_region.fill(data2_u8, offset2, length2).unwrap();
        for i in 0..offset2 {
            // Print for debug
            println!("i:{} -> {}", i, unsafe {
                *(mock_mem.buff.offset(i as isize) as *mut u8)
            });
            // Check that the first 4 bytes are not overwritten
            assert_eq!(
                unsafe { *(mock_mem.buff.offset(i as isize) as *mut u8) },
                data1_u8
            );
        }
        for i in offset2..offset2 + length2 {
            // Print for debug
            println!("i:{} -> {}", i, unsafe {
                *(mock_mem.buff.offset(i as isize) as *mut u8)
            });
            // Check that the 12 next bytes are properly written
            assert_eq!(
                unsafe { *(mock_mem.buff.offset(i as isize) as *mut u8) },
                data2_u8
            );
        }

        // Check off-by-one at the end of the buffer
        assert_eq!(io_region.fill(0, mock_mem.size - 4 - 1, 4).unwrap(), ());

        // Check that writing out-of-bound returns BadOffset
        assert_eq!(
            io_region.fill(0, mock_mem.size - 4, 4).err().unwrap(),
            IoError::BadOffset
        );
    }
}
