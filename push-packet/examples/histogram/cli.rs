use clap::Parser;

// CLI Args
#[derive(Parser, Debug)]
pub struct Args {
    #[arg(short, long)]
    pub interface: String,
    #[arg(short, long, default_value_t = 10)]
    pub window: usize,
    #[arg(short, long)]
    pub nickname: Option<String>,
    #[arg(short, long)]
    pub mask: bool,
    #[arg(long)]
    pub no_tcp: bool,
    #[arg(long)]
    pub no_udp: bool,
    #[arg(long)]
    pub no_icmp: bool,
    #[arg(long)]
    pub no_v4: bool,
    #[arg(long)]
    pub no_v6: bool,
    #[arg(long, default_value_t = 30)]
    pub fps: u32,
}
