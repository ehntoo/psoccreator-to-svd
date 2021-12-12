#[macro_use]
extern crate clap;
use clap::App;
use flate2::read::GzDecoder;
use regex::Regex;
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};
use svd_rs::{
    Access, AddressBlock, BitRange, Cpu, Device, EnumeratedValue, EnumeratedValues, Field,
    FieldInfo, ModifiedWriteValues, Peripheral, PeripheralInfo, Protection, ReadAction, Register,
    RegisterCluster, RegisterInfo, RegisterProperties, ValidateLevel,
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
    // let hsiom_conn_path = dir_path.join("hsiomconn.cydata");
    // let clk_conn_path = dir_path.join("clkconn.cydata");
    // let irq_conn_path = dir_path.join("irqconn.cydata");

    println!("Loading source .cydata files");
    let datasheet_xml = load_datafile(datasheet_path.as_path()).expect("Parsing datasheet file");
    let register_map_xml =
        load_datafile(register_map_path.as_path()).expect("Parsing register map file");
    // let hsiom_conn_xml =
    //     load_datafile(hsiom_conn_path.as_path()).expect("Parsing HSIOM connection file");
    // let clk_conn_xml = load_datafile(clk_conn_path.as_path()).expect("Parsing CLK connection file");
    // let irq_conn_xml = load_datafile(irq_conn_path.as_path()).expect("Parsing IRQ connection file");

    println!("Parsing .cydata XML");
    let datasheet_doc = roxmltree::Document::parse(&datasheet_xml).expect("Parsing datasheet XML");
    let register_map_doc =
        roxmltree::Document::parse(&register_map_xml).expect("Parsing register map XML");
    // let _hsiom_conn_doc =
    //     roxmltree::Document::parse(&hsiom_conn_xml).expect("Parsing HSIOM connection XML");
    // let _clk_conn_doc =
    //     roxmltree::Document::parse(&clk_conn_xml).expect("Parsing CLK connection XML");
    // let _irq_conn_doc =
    //     roxmltree::Document::parse(&irq_conn_xml).expect("Parsing IRQ connection XML");

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
    // pin mappings for hsiom
    let mut peripherals = Vec::<Peripheral>::new();
    // let temp_interrupt = Interrupt::builder()
    //     .name("test".to_string())
    //     .value(0)
    //     .build(ValidateLevel::Strict)
    //     .expect("Creating interrupt");

    let mmio_block_name_regex = Regex::new(r"MMIO").unwrap();
    let doc_mmio_blocks = register_map_doc.root_element().children().filter(|n| {
        n.has_tag_name("block")
            && n.has_attribute("name")
            && mmio_block_name_regex.is_match(n.attribute("name").unwrap())
    });

    let peripheral_blocks = doc_mmio_blocks
        .flat_map(|n| n.children())
        .filter(|n| n.is_element())
        .collect::<Vec<roxmltree::Node>>();
    println!("Found {} peripherals", peripheral_blocks.len());

    for p in &peripheral_blocks {
        println!("Creating peripheral for {:?}", p);
        let mut new_peripheral = PeripheralInfo::builder();
        if p.has_attribute("basename") {
            let basename = p.attribute("basename").unwrap();
            let derived_from_peripheral = peripheral_blocks
                .iter()
                .find(|n| {
                    n.has_attribute("basename") && n.attribute("basename").unwrap() == basename
                })
                .unwrap();
            if p != derived_from_peripheral {
                new_peripheral = new_peripheral.derived_from(Some(
                    derived_from_peripheral
                        .attribute("name")
                        .unwrap()
                        .to_string(),
                ));
            }
        }
        if p.has_attribute("name") {
            new_peripheral = new_peripheral.name(p.attribute("name").unwrap().to_string());
        }

        // Let's assume that a base address has been provided, since I don't know what we'd do without one
        let base_addr_str = p.attribute("BASE").unwrap().trim_start_matches("0x");
        let base_addr = u64::from_str_radix(base_addr_str, 16).unwrap();
        new_peripheral = new_peripheral.base_address(base_addr);

        if p.has_attribute("SIZE") {
            let peripheral_size_str = p.attribute("SIZE").unwrap().trim_start_matches("0x");
            let address_block = AddressBlock::builder()
                .size(u32::from_str_radix(peripheral_size_str, 16).unwrap())
                .offset(0)
                .usage(svd_rs::AddressBlockUsage::Registers)
                .build(ValidateLevel::Strict)
                .unwrap();
            new_peripheral = new_peripheral.address_block(Some([address_block].to_vec()));
        }

        // TODO - handle register clusters, which are direct block children of the peripheral.
        // We can then swap the following `descendants` call with `children`
        // TODO - handle reset values. the cydata format puts the reset value on each register
        // field, so we'll have to aggregate the reset value of each field along with its mask
        // value in order to produce the right output
        let registers = p.descendants().filter(|n| n.has_tag_name("register"));
        let registers = registers.map(|r| {
            let name = r.attribute("name").unwrap();
            let address_str = r.attribute("address").unwrap().trim_start_matches("0x");
            let address = u64::from_str_radix(address_str, 16).unwrap();
            let fields = r.children().filter(|n| n.has_tag_name("field")).map(|f| {
                // println!("Parsing field {:?}", f);
                let name = f.attribute("name").unwrap();
                let bit_from: u32 = f.attribute("from").unwrap().parse().unwrap();
                let bit_to: u32 = f.attribute("to").unwrap().parse().unwrap();
                let bit_range = BitRange {
                    offset: bit_to,
                    width: (bit_from - bit_to) + 1,
                    range_type: svd_rs::BitRangeType::BitRange,
                };
                let access_string = f.attribute("access");
                let access = match access_string {
                    Some("RW") => Some(Access::ReadWrite),
                    Some("R") => Some(Access::ReadOnly),
                    Some("W") => Some(Access::WriteOnly),
                    Some("RWOCLR") => Some(Access::ReadWrite),
                    Some("RWOSET") => Some(Access::ReadWrite),
                    Some("RCLR") => Some(Access::ReadOnly),
                    Some("RWCLR") => Some(Access::ReadWrite),
                    Some("RWZCLR") => Some(Access::ReadWrite),
                    _ => None,
                };
                let modified_write = match access_string {
                    Some("RWOCLR") => Some(ModifiedWriteValues::OneToClear),
                    Some("RWOSET") => Some(ModifiedWriteValues::OneToSet),
                    Some("RWCLR") => Some(ModifiedWriteValues::Clear),
                    Some("RWZCLR") => Some(ModifiedWriteValues::ZeroToClear),
                    _ => None,
                };
                let read_action = match access_string {
                    Some("RCLR") => Some(ReadAction::Clear),
                    _ => None,
                };
                // let field_description = if let Some(s) = f.attribute("description") {
                //     Some(s.to_string())
                // } else {
                //     None
                // };
                let field_options = f
                    .children()
                    .filter(|v| v.has_tag_name("value"))
                    .map(|v| {
                        let val_string = v.attribute("value").unwrap();
                        EnumeratedValue::builder()
                            .name(v.attribute("name").unwrap().to_string())
                            .value(Some(u64::from_str_radix(val_string, 2).unwrap()))
                            .build(ValidateLevel::Strict)
                            .unwrap()
                    })
                    .collect::<Vec<EnumeratedValue>>();
                let mut field_builder = FieldInfo::builder()
                    .name(name.to_string())
                    .access(access)
                    .read_action(read_action)
                    .modified_write_values(modified_write)
                    .bit_range(bit_range);
                if !field_options.is_empty() {
                    let field_options = EnumeratedValues::builder()
                        .values(field_options)
                        .build(ValidateLevel::Strict)
                        .unwrap();
                    field_builder = field_builder.enumerated_values([field_options].to_vec());
                }

                let field = field_builder.build(ValidateLevel::Strict).unwrap();
                Field::Single(field)
            });

            let reg = RegisterInfo::builder()
                .name(name.to_string())
                .address_offset((address - base_addr).try_into().unwrap())
                .fields(Some(fields.collect()))
                .build(ValidateLevel::Strict)
                .unwrap();
            RegisterCluster::Register(Register::Single(reg))
        });
        new_peripheral = new_peripheral.registers(Some(registers.collect()));
        let new_peripheral = new_peripheral.build(ValidateLevel::Strict).unwrap();
        peripherals.push(Peripheral::Single(new_peripheral));
    }

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
        .nvic_priority_bits(2) // TODO - extract from register map, width of IPR0/0xe000e400
        .has_vendor_systick(false) // the PSoC parts all seem to have the ARM systick
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
        Err(why) => panic!("Couldn't create {}: {}", svd_filename, why),
        Ok(file) => file,
    };

    match svd_file.write_all(svd_xml.as_bytes()) {
        Err(why) => panic!("Couldn't write to {}: {}", svd_filename, why),
        Ok(_) => println!("Successfully wrote to {}", svd_filename),
    }
}
