//! `corerouter-image ova --vmdk F --capacity BYTES --out F [--name N]`
//! (G1.6c): the VMware/VirtualBox appliance. An OVA is a ustar archive with
//! the OVF descriptor first, then the manifest, then the disks (DMTF DSP0243
//! §5.3); the disk is the image converted by `qemu-img` to a
//! streamOptimized VMDK (the only VMDK flavour an OVA may carry).
//!
//! The machine: 2 vCPUs, 1 GiB, UEFI (the image has no BIOS boot; VMware
//! reads `firmware=efi`, VirtualBox needs "Enable EFI" after import), the
//! disk on SATA/AHCI, two e1000 ports (both hypervisors have the driver;
//! the image also has vmxnet3).

use std::io::Write;
use std::path::{Path, PathBuf};

use corerouter_sysupdate::package;

const DISK: &str = "corerouter-disk1.vmdk";

fn ovf(name: &str, vmdk_size: u64, capacity: u64) -> String {
    let item = |id: u32, rtype: u32, body: &str| {
        format!(
            "      <Item>\n        <rasd:InstanceID>{id}</rasd:InstanceID>\n        <rasd:ResourceType>{rtype}</rasd:ResourceType>\n{body}      </Item>\n"
        )
    };
    let el = |k: &str, v: &str| format!("        <rasd:{k}>{v}</rasd:{k}>\n");
    let mut hw = String::new();
    hw += &item(
        1,
        3,
        &(el("ElementName", "2 virtual CPUs")
            + &el("Description", "Number of virtual CPUs")
            + &el("VirtualQuantity", "2")),
    );
    hw += &item(
        2,
        4,
        &(el("AllocationUnits", "byte * 2^20")
            + &el("ElementName", "1024 MB of memory")
            + &el("Description", "Memory size")
            + &el("VirtualQuantity", "1024")),
    );
    hw += &item(
        3,
        20,
        &(el("ElementName", "sata0")
            + &el("Description", "SATA controller")
            + &el("ResourceSubType", "AHCI")
            + &el("Address", "0")),
    );
    hw += &item(
        4,
        17,
        &(el("ElementName", "disk0")
            + &el("HostResource", "ovf:/disk/vmdisk1")
            + &el("Parent", "3")
            + &el("AddressOnParent", "0")),
    );
    for (i, id) in [(1u32, 5u32), (2, 6)] {
        hw += &item(
            id,
            10,
            &(el("ElementName", &format!("ether{i}"))
                + &el("ResourceSubType", "E1000")
                + &el("Connection", "nat")
                + &el("AutomaticAllocation", "true")
                + &el("AddressOnParent", &(i - 1).to_string())),
        );
    }
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<Envelope ovf:version="1.0" xml:lang="en-US" xmlns="http://schemas.dmtf.org/ovf/envelope/1" xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1" xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData" xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData" xmlns:vmw="http://www.vmware.com/schema/ovf" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <References>
    <File ovf:href="{DISK}" ovf:id="file1" ovf:size="{vmdk_size}"/>
  </References>
  <DiskSection>
    <Info>Virtual disk information</Info>
    <Disk ovf:capacity="{capacity}" ovf:capacityAllocationUnits="byte" ovf:diskId="vmdisk1" ovf:fileRef="file1" ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"/>
  </DiskSection>
  <NetworkSection>
    <Info>The logical networks</Info>
    <Network ovf:name="nat">
      <Description>Management and first data network</Description>
    </Network>
  </NetworkSection>
  <VirtualSystem ovf:id="{name}">
    <Info>CoreRouter (A/B image, UEFI)</Info>
    <Name>{name}</Name>
    <OperatingSystemSection ovf:id="101" vmw:osType="other5xLinux64Guest">
      <Info>The guest operating system</Info>
      <Description>Linux 64-bit (CoreRouter)</Description>
    </OperatingSystemSection>
    <VirtualHardwareSection>
      <Info>Virtual hardware requirements</Info>
      <System>
        <vssd:ElementName>Virtual Hardware Family</vssd:ElementName>
        <vssd:InstanceID>0</vssd:InstanceID>
        <vssd:VirtualSystemIdentifier>{name}</vssd:VirtualSystemIdentifier>
        <vssd:VirtualSystemType>vmx-14</vssd:VirtualSystemType>
      </System>
{hw}      <vmw:Config ovf:required="false" vmw:key="firmware" vmw:value="efi"/>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>
"#
    )
}

/// One ustar member header (POSIX.1-1988), fixed owner and time.
fn tar_header(name: &str, size: u64, mtime: u64) -> Result<[u8; 512], String> {
    if name.len() > 99 {
        return Err(format!("{name}: name too long for ustar"));
    }
    if size >= 1 << 33 {
        return Err(format!("{name}: larger than 8 GiB"));
    }
    let mut h = [0u8; 512];
    let mut put = |at: usize, b: &[u8]| {
        if let Some(d) = h.get_mut(at..at + b.len()) {
            d.copy_from_slice(b);
        }
    };
    put(0, name.as_bytes());
    put(100, b"0000644\0");
    put(108, b"0000000\0");
    put(116, b"0000000\0");
    put(124, format!("{size:011o}\0").as_bytes());
    put(136, format!("{mtime:011o}\0").as_bytes());
    put(148, b"        ");
    put(156, b"0");
    put(257, b"ustar\0");
    put(263, b"00");
    put(265, b"root");
    put(297, b"root");
    let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
    if let Some(d) = h.get_mut(148..156) {
        d.copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    }
    Ok(h)
}

fn member(out: &mut dyn Write, name: &str, data: &[u8], mtime: u64) -> Result<(), String> {
    out.write_all(&tar_header(name, data.len() as u64, mtime)?)
        .and_then(|_| out.write_all(data))
        .and_then(|_| out.write_all(&vec![0u8; data.len().next_multiple_of(512) - data.len()]))
        .map_err(|e| e.to_string())
}

/// The OVA bytes.
pub fn ova(name: &str, vmdk: &[u8], capacity: u64, mtime: u64) -> Result<Vec<u8>, String> {
    let desc = ovf(name, vmdk.len() as u64, capacity);
    let ovf_name = format!("{name}.ovf");
    let mf = format!(
        "SHA256({ovf_name})= {}\nSHA256({DISK})= {}\n",
        package::sha256_hex(desc.as_bytes()),
        package::sha256_hex(vmdk)
    );
    let mut out = Vec::with_capacity(vmdk.len() + 8192);
    member(&mut out, &ovf_name, desc.as_bytes(), mtime)?;
    member(&mut out, &format!("{name}.mf"), mf.as_bytes(), mtime)?;
    member(&mut out, DISK, vmdk, mtime)?;
    out.extend_from_slice(&[0u8; 1024]);
    Ok(out)
}

pub fn main(args: &[String]) -> Result<(), String> {
    let mut vmdk: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut capacity: Option<u64> = None;
    let mut name = "corerouter".to_owned();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().cloned().ok_or(format!("{a} needs a value"));
        match a.as_str() {
            "--vmdk" => vmdk = Some(PathBuf::from(val()?)),
            "--out" => out = Some(PathBuf::from(val()?)),
            "--capacity" => capacity = Some(val()?.parse().map_err(|_| "--capacity: bytes")?),
            "--name" => name = val()?,
            other => return Err(format!("unknown argument '{other}'")),
        }
    }
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("--name: letters, digits, - and _".into());
    }
    let vmdk = crate::read(&vmdk.ok_or("--vmdk <file> is required")?)?;
    let capacity = capacity.ok_or("--capacity <bytes> is required")?;
    let mtime: u64 = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let out = out.ok_or("--out <file> is required")?;
    std::fs::write(&out, ova(&name, &vmdk, capacity, mtime)?)
        .map_err(|e| format!("{}: {e}", Path::new(&out).display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ova_is_a_tar_with_the_descriptor_first_and_a_matching_manifest() {
        let vmdk = vec![0x4b; 1000];
        let a = ova("corerouter", &vmdk, 1 << 30, 1_800_000_000).unwrap();
        assert_eq!(a.len() % 512, 0);
        let name = |at: usize| {
            String::from_utf8_lossy(&a[at..at + 100])
                .trim_end_matches('\0')
                .to_owned()
        };
        let size = |at: usize| {
            u64::from_str_radix(std::str::from_utf8(&a[at + 124..at + 135]).unwrap(), 8).unwrap()
        };
        assert_eq!(name(0), "corerouter.ovf");
        let ovf_len = size(0) as usize;
        let ovf_text = std::str::from_utf8(&a[512..512 + ovf_len]).unwrap();
        assert!(ovf_text.contains(r#"ovf:capacity="1073741824""#));
        assert!(ovf_text.contains(r#"ovf:size="1000""#));
        assert!(ovf_text.contains(r#"vmw:value="efi""#));
        let mf_at = 512 + ovf_len.next_multiple_of(512);
        assert_eq!(name(mf_at), "corerouter.mf");
        let mf = std::str::from_utf8(&a[mf_at + 512..mf_at + 512 + size(mf_at) as usize]).unwrap();
        assert!(mf.contains(&package::sha256_hex(ovf_text.as_bytes())));
        assert!(mf.contains(&package::sha256_hex(&vmdk)));
        let disk_at = mf_at + 512 + (size(mf_at) as usize).next_multiple_of(512);
        assert_eq!(name(disk_at), DISK);
        // ustar checksum (header with the field as spaces).
        let mut h = a[..512].to_vec();
        let stored = u32::from_str_radix(std::str::from_utf8(&h[148..154]).unwrap(), 8).unwrap();
        h[148..156].fill(b' ');
        assert_eq!(stored, h.iter().map(|&b| u32::from(b)).sum::<u32>());
        assert_eq!(&a[257..262], b"ustar");
        assert_eq!(ova("corerouter", &vmdk, 1 << 30, 1_800_000_000).unwrap(), a);
    }

    #[test]
    fn bad_names() {
        assert!(tar_header(&"x".repeat(100), 1, 0).is_err());
        assert!(main(&["--name".into(), "a/b".into()]).is_err());
    }
}
