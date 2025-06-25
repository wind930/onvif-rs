extern crate onvif;
use onvif::discovery;
use std::net::IpAddr;

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    tracing_subscriber::fmt::init();

    use futures_util::stream::StreamExt;
    const MAX_CONCURRENT_JUMPERS: usize = 100;

    // 将字符串解析为 IpAddr
    let listen_addr: IpAddr = "192.168.1.100".parse().unwrap();

    discovery::DiscoveryBuilder::default()
        .listen_address(listen_addr)
        .run()
        .await
        .unwrap()
        .for_each_concurrent(MAX_CONCURRENT_JUMPERS, |addr| async move {
            println!("Device found: {:?}", addr);
        })
        .await;
}
