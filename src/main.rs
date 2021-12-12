#[macro_use]
extern crate clap;
use clap::App;
use flate2::read::GzDecoder;
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};
use svd_rs::{
    Access, Cpu, Device, Interrupt, Peripheral, PeripheralInfo, Protection, RegisterProperties,
    ValidateLevel,
};

#[derive(Debug)]
enum PsocFileError {
    Open,
    Read,
    Decode,
}

fn load_datafile(f: &Path) -> Result<String, PsocFileError> {
    let file = File::open(f);
    if let Ok(mut file) = file {
        let mut buf = Vec::new();
        if file.read_to_end(&mut buf).is_ok() {
            let header_str = "PSOCCREATORDATAFILE";
            if &buf[..header_str.len()] == header_str.as_bytes() {
                let key = "Cypress";
                let key_bytes = key.as_bytes();
                for (i, b) in key_bytes.iter().enumerate() {
                    buf[header_str.len() + i] ^= b;
                }

                let mut gz_decoder = GzDecoder::new(&buf[header_str.len()..]);
                let mut xml = String::new();
                let decode_result = gz_decoder.read_to_string(&mut xml);
                if decode_result.is_ok() {
                    Ok(xml)
                } else {
                    Err(PsocFileError::Decode)
                }
            } else {
                Err(PsocFileError::Decode)
            }
        } else {
            Err(PsocFileError::Read)
        }
    } else {
        Err(PsocFileError::Open)
    }
}

fn main() {
    let yaml = load_yaml!("cli.yaml");
    let matches = App::from_yaml(yaml).get_matches();

    let directory = matches.value_of("directory").unwrap();
    let dir_path = Path::new(directory);

    println!("Generating SVD from directory: {}", dir_path.display());

    let datasheet_path = dir_path.join("datasheet.cydata");
    let register_map_path = dir_path.join("map_inst.cydata");
    let hsiom_conn_path = dir_path.join("hsiomconn.cydata");
    let clk_conn_path = dir_path.join("clkconn.cydata");
    let irq_conn_path = dir_path.join("irqconn.cydata");

    println!("Loading source .cydata files");
    let datasheet_xml = load_datafile(datasheet_path.as_path()).expect("Parsing datasheet file");
    let register_map_xml =
        load_datafile(register_map_path.as_path()).expect("Parsing register map file");
    let hsiom_conn_xml =
        load_datafile(hsiom_conn_path.as_path()).expect("Parsing HSIOM connection file");
    let clk_conn_xml = load_datafile(clk_conn_path.as_path()).expect("Parsing CLK connection file");
    let irq_conn_xml = load_datafile(irq_conn_path.as_path()).expect("Parsing IRQ connection file");

    println!("Parsing .cydata XML");
    let datasheet_doc = roxmltree::Document::parse(&datasheet_xml).expect("Parsing datasheet XML");
    let _register_map_doc =
        roxmltree::Document::parse(&register_map_xml).expect("Parsing register map XML");
    let _hsiom_conn_doc =
        roxmltree::Document::parse(&hsiom_conn_xml).expect("Parsing HSIOM connection XML");
    let _clk_conn_doc =
        roxmltree::Document::parse(&clk_conn_xml).expect("Parsing CLK connection XML");
    let _irq_conn_doc =
        roxmltree::Document::parse(&irq_conn_xml).expect("Parsing IRQ connection XML");

    let description = datasheet_doc
        .root_element()
        .children()
        .find(|n| n.has_tag_name("Overview"))
        .unwrap()
        .attribute("value")
        .unwrap();
    println!("Chip description: {}", description);

    // TODO:
    // interrupts
    // peripherals
    //    registers
    //    pin mappings for hsiom
    let mut peripherals = Vec::<Peripheral>::new();
    let temp_interrupt = Interrupt::builder()
        .name("test".to_string())
        .value(0)
        .build(ValidateLevel::Strict)
        .expect("Creating interrupt");
    let temp_peripheral = PeripheralInfo::builder()
        .name("test".to_string())
        .base_address(0x10000000)
        .interrupt(Some([temp_interrupt].to_vec()))
        .build(ValidateLevel::Strict)
        .expect("Creating peripheral");
    peripherals.push(Peripheral::Single(temp_peripheral));

    let mut default_register_properties = RegisterProperties::new();
    default_register_properties.access = Some(Access::ReadWrite);
    default_register_properties.protection = Some(Protection::NonSecure);
    default_register_properties.reset_value = Some(0);
    default_register_properties.reset_mask = Some(0xFFFF_FFFF);
    default_register_properties.size = Some(32);

    let cpu = Cpu::builder()
        .name("CM0".to_string()) // TODO - placeholder. Can be extracted from devicetree in device data root?
        .revision("r1p0".to_string())
        .endian(svd_rs::Endian::Little)
        .mpu_present(false)
        .fpu_present(false)
        .nvic_priority_bits(2)
        .has_vendor_systick(false)
        .build(ValidateLevel::Strict)
        .expect("Constructing CPU");

    let svd_device = Device::builder()
        .name("CCG2".to_string())
        .version(Some("1.0".to_string()))
        .schema_version(Some("1.3".to_string()))
        .description(Some(description.to_string()))
        .width(Some(32))
        .address_unit_bits(Some(8))
        .default_register_properties(default_register_properties)
        .cpu(Some(cpu))
        .peripherals(peripherals)
        .build(ValidateLevel::Strict)
        .expect("Constructing SVD Device");

    let svd_xml = svd_encoder::encode(&svd_device).expect("Encoding SVD");

    let svd_filename = matches.value_of("output").unwrap();
    let mut svd_file = match File::create(&svd_filename) {
        Err(why) => panic!("couldn't create {}: {}", svd_filename, why),
        Ok(file) => file,
    };

    match svd_file.write_all(svd_xml.as_bytes()) {
        Err(why) => panic!("couldn't write to {}: {}", svd_filename, why),
        Ok(_) => println!("successfully wrote to {}", svd_filename),
    }
}
