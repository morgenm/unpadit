/*
unpadit
Author: Morgen Malinoski
Description: This is a quick program I threw together to help with the analysis of a piece of malware encountered in the wild.
    The malware had a bunch of garbage data appended to the end of it to prevent it from being uploaded to VirusTotal. So, this
    program just calculates the end of the file based on the section headers, and ignores everything else, and outputs the 
    "stripped" binary.
*/

use pelite::FileMap;
use pelite::pe64::{Pe, PeFile};
use pelite::resources::{DirectoryEntry};
use pelite::Error;
use std::fs::File;
use std::io::Write;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    // Input file
    #[arg(short, long)]
    input_file: String,

    // Output file
    #[arg(short, long)]
    output_file: String,
}

fn main() {
    let args = Args::parse();

	// Open and load the given input file
	let file_map = FileMap::open(&args.input_file).unwrap();

	// Analyze .rsrc section. Right now, just prints the resource dirs and entries
    analyze_rsrc(file_map.as_ref()).unwrap();

    // Check for excess junk data at end of file, and remove it if found
    let outfile = strip_junk_at_end(file_map.as_ref()).unwrap();

    output_file(outfile, args.output_file);
}

fn strip_junk_at_end(image: &[u8]) -> pelite::Result<&[u8]> {
    let file = PeFile::from_bytes(image)?;
    let section_headers = file.section_headers();

    let mut max_end: u32 = 0;
    for section_header in section_headers {
        let sec_end: u32 = section_header.file_range().end;
        println!("{} ends at {}", section_header.name().unwrap(), sec_end);
        if sec_end > max_end { // Update max_end so it will be end of file
            max_end = sec_end;
        }
    }
    
    let file_size_real: u32 = image.len() as u32;
    if file_size_real > max_end {
        println!("Discrepancy in file size. This means the file could be packed with garbge data.");
        println!("File size real: {}, File size calculated {}", file_size_real, max_end);

        // Cut out excess data, then output the file!
        let end: usize = max_end as usize;
        let new_image: &[u8] = &image[0..end+1];
        return Ok(new_image);
    }
    else if file_size_real < max_end {
        println!("Error: Calculated end of file greater than file size!");
        return Err(Error::Bounds);
    }

    Err(Error::Bounds) // TODO: Replace with a better error!
}

fn output_file(image: &[u8], fileName: String) -> Result<(), &'static str>{
    let mut out_file = File::create(fileName).unwrap();
    out_file.write(image);
    Ok(())
}

fn get_tab_str_from_level(level: i32) -> String {
    let mut s: String = String::new();

    for _ in 0..level {
        s.push_str("  "); // One level = 2 spaces
    }

    s
}

fn walk_dir(entry: DirectoryEntry, level: i32) -> pelite::Result<i32>{
    let mut total_size: i32 = 0;

    // Recursive case. It's an entry, so keep walkin'! (also print)
    if entry.is_dir() {
        println!("{} d : {}", get_tab_str_from_level(level), entry.name()?);
        let dir = entry.entry()?.dir().unwrap();
        let entries = dir.entries();
        for e in entries {
            total_size += walk_dir(e, level + 1)?;
        }
    }
    // Base case. Not a dir, so just print!
    else {
        let data = entry.entry()?.data().unwrap();
        total_size += data.size() as i32;
        let data_size: f32 = (data.size() as f32) / 1024.0;
        println!("{} e: '{}', with size: {} KB", get_tab_str_from_level(level), entry.name()?, data_size);
    }

    Ok(total_size)
}

fn analyze_rsrc(image: &[u8]) -> pelite::Result<()> {
	// Interpret the bytes as a PE32+ executable
	let file = PeFile::from_bytes(image)?;

    // 
    let resources = file.resources()?;
    let root = resources.root()?;
    let entries = root.entries();

    let manifest = resources.manifest();
    match manifest {
        Ok(m) => println!("Manifest: {}", m),
        Err(_) => println!("No manifest!")
    }

    let mut total_size = 0;
    for e in entries {
        total_size += walk_dir(e, 0)?;
    }

    println!("Total size of entries in rsrc (bytes): {}", total_size);

    // Does it always have to have rsrc as its name? And is it always present?
    let section_headers = file.section_headers();
    let rsrc_header = section_headers.by_name(".rsrc").unwrap();
    let file_range = rsrc_header.file_range();

    println!("Rsrc size by header {}",file_range.end - file_range.start);

	Ok(())
}