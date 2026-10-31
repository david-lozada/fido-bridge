use anyhow::{Context, Result};
use mdns_sd::{ServiceDaemon, ServiceInfo};
use tracing::info;

pub struct MdnsAdvertisement {
    daemon: ServiceDaemon,
    fullname: String,
}

impl MdnsAdvertisement {
    pub fn start(instance_name: &str, port: u16) -> Result<Self> {
        let daemon = ServiceDaemon::new().context("create mdns daemon")?;
        let host_name = format!("{instance_name}.local.");
        let properties = [("proto", "fidobridge"), ("ver", "1")];
        let service = ServiceInfo::new(
            "_fidobridge._tcp.local.",
            instance_name,
            &host_name,
            "", // let mdns-sd fill addresses
            port,
            &properties[..],
        )
        .context("build service info")?
        .enable_addr_auto();

        let fullname = service.get_fullname().to_string();
        daemon.register(service).context("register mdns service")?;
        info!("mDNS advertising {fullname} on port {port}");
        Ok(Self { daemon, fullname })
    }
}

impl Drop for MdnsAdvertisement {
    fn drop(&mut self) {
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
    }
}
