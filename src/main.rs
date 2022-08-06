#![allow(unused_variables)]
#![allow(non_snake_case)]
#![allow(unused_must_use)]
#![feature(read_buf)]

use std::{env, io::{Read, Seek, ReadBuf}, fs, mem::MaybeUninit};

use lzxd::Lzxd;

fn main() {
    use std::time::Instant;
    let now = Instant::now();

    let args: Vec<String> = env::args().collect();

    if args.len() <= 1 {
        println!("please specify a fastfile\nUsage: filename.exe <fastfile>");
        return;
    }

    let arg1 = args.get(1).to_owned();
    
    let fastFileName = arg1.as_deref().unwrap();

    if !fastFileName.ends_with(".ff") {
        println!("please specify a fastfile that ends with .ff");
        return;
    }

    
    let fastFileAttempt = fs::File::open(fastFileName);
    let mut fastFile = fastFileAttempt.unwrap();

    let mut ff_magic = [0; 8];
    let mut ff_version = [0; 4];
    let mut ff_allowOnlineUpdate = [0];
    let mut ff_language  = [0; 4];
    let mut ff_fileCreationTime = [0; 8];
    let mut ff_padding = [0; 4];
    let mut ff_unusedSize = [0; 4];
    let mut ff_usedSize = [0; 4];
    let mut ff_unknown = [0; 4];


    fastFile.read_exact(&mut ff_magic);
    let ff_magic_str = std::str::from_utf8(&ff_magic).unwrap();
    println!("Magic: {}", ff_magic_str);

    fastFile.read_exact(&mut ff_version);
    let ff_version_u32 = u32::from_be_bytes(ff_version);
    println!("Version: {}", ff_version_u32);
    
    fastFile.read_exact(&mut ff_allowOnlineUpdate);
    println!("Allow online update: {}", ff_allowOnlineUpdate[0]);

    fastFile.read_exact(&mut ff_fileCreationTime);
    let ff_fileCreationTime_u64 = u64::from_be_bytes(ff_fileCreationTime);
    println!("File Creation Time: {}", ff_fileCreationTime_u64);

    fastFile.read_exact(&mut ff_language);
    let ff_language_u32 = u32::from_be_bytes(ff_language);
    println!("Language: {}", ff_language_u32);

    fastFile.read_exact(&mut ff_padding);
    let ff_padding_u32 = u32::from_be_bytes(ff_padding);
    println!("Padding: {}", ff_padding_u32);

    if ff_padding_u32 > 0 {
        let temp_padding = (ff_padding_u32 * 12) as i64;
        fastFile.seek(std::io::SeekFrom::Current(temp_padding));
    }
    
    fastFile.read_exact(&mut ff_unusedSize);
    let ff_unusedSize_u32 = u32::from_be_bytes(ff_unusedSize);
    println!("Unused Size: {}", ff_unusedSize_u32);

    fastFile.read_exact(&mut ff_usedSize);
    let ff_usedSize_u32 = u32::from_be_bytes(ff_usedSize);
    println!("Used Size: {}", ff_usedSize_u32);

    if ff_magic_str == "IWffu100" {
        println!("#### DETECTED UNSIGNED FASTFILE ####");

        println!("This section isn't working as intended.. yet.");
        let mut compressed = [0; 0x2000];
        let mut decompressed = [0; 0x2000 * 4];

        let mut result = fastFile.read_exact(&mut compressed);

        println!("compressed {:02X?}", compressed);
        let mut read = result.is_ok();
    
        let mut lzxd = Lzxd::new(lzxd::WindowSize::MB8);

        let lzxd_response = lzxd.decompress_next(&compressed);
        let decompressed_bytes = lzxd_response.unwrap_err();
        println!("Decompressed: {:?}", decompressed_bytes);
        
        while read == true {
            result = fastFile.read_exact(&mut compressed);
            
            let lzxd_response = lzxd.decompress_next(&mut compressed);
            let decompressed_bytes = lzxd_response.unwrap();
            println!("Decompressed: {:?}", decompressed_bytes);
            read = result.is_ok();
        }
    }

    else if ff_magic_str == "IWff0100" {
        println!("#### DETECTED SIGNED FASTFILE ####");
        fastFile.read_exact(&mut ff_magic);
        let ff_magic_str = std::str::from_utf8(&ff_magic).unwrap();

        if ff_magic_str != "IWffs100" {
            println!("Invalid magic. Fastfile is invalid");
            return;
        }

        println!("Magic: {}", ff_magic_str);

        /* Unused Bytes */
        fastFile.read_exact(&mut ff_unknown);

        let mut ff_checksum = [0; 32];
        fastFile.read_exact(&mut ff_checksum);
        println!("Checksum: {:02X?}", ff_checksum);

        let mut ff_rsa_sig = [0; 256];
        fastFile.read_exact(&mut ff_rsa_sig);
        println!("RSA Signature: {:02X?}", ff_rsa_sig);

        let mut ff_name = [0; 32];
        fastFile.read_exact(&mut ff_name);
        let ff_name_str = std::str::from_utf8(&ff_name).unwrap();
        println!("File Name: {}", ff_name_str);

        /* Unused Bytes */
        fastFile.read_exact(&mut ff_unknown);

        let mut ff_bigSigBlock = [MaybeUninit::<u8>::uninit(); 7856];

        let mut ff_bigSigBlock = ReadBuf::uninit(&mut ff_bigSigBlock);

        fastFile.read_buf(&mut ff_bigSigBlock);

        println!("Big Signature Block Size: {} bytes", ff_bigSigBlock.filled().len());

        println!("#### END OF SIGNED FASTFILE ####");
    }

    let elapsed = now.elapsed();
    println!("Elapsed: {:.2?}", elapsed);
}
