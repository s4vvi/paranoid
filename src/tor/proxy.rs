use std::sync::Arc;
use tokio::sync::Mutex;
use console::style;
use futures::io::{
    AsyncRead,
    AsyncReadExt,
    AsyncWrite, 
    AsyncWriteExt,
    Error as IoError
};
use futures::FutureExt;
use futures::stream::StreamExt;
use futures::task::SpawnExt;
use std::io::Result as IoResult;
use std::net::{
    IpAddr,
    Ipv4Addr,
    Ipv6Addr
};
use log::{warn, debug, error};
use anyhow::{
    anyhow,
    Context,
    Result
};
use arti_client::{
    ErrorKind,
    HasKind,
    StreamPrefs,
    TorClient,
};
use tor_config::Listen;
use tor_error::warn_report;
use tor_rtcompat::{Runtime, TcpListener};
use tor_socksproto::{
    SocksAddr,
    SocksAuth,
    SocksCmd,
    SocksRequest
};

use crate::tor::Clients;
use crate::globals::WRONG_PROTOCOL_PAYLOAD;
use crate::app::TNTR;


/// Type pulled from the arti project
pub type PinnedFuture<T> = std::pin::Pin<Box<dyn futures::Future<Output = T>>>;


/// The main asynchronous run function
///
/// # Arguments
///
/// * `runtime` - a TLS tokio runtime
/// * `listen` - the socks listener information
/// * `clients` - bootstraped TOR clients 
pub async fn run(
    runtime: TNTR,
    listen: Listen,
    clients: Arc<Mutex<Clients<TNTR>>>,
) -> Result<()> {
    // Start the SOCKS proxies
    // Starts one for IPv4 & IPv6
    let mut proxy: Vec<PinnedFuture<(Result<()>, &str)>> = Vec::new();
    if !listen.is_empty() {
        let runtime = runtime.clone();
        proxy.push(Box::pin(async move {
            let res = run_socks_proxy(
                runtime,
                clients,
                listen,
            )
            .await;
            (res, "SOCKS")
        }));
    }
    
    // Check if proxies started
    if proxy.is_empty() {
        error!("No proxy port set.");
        return Ok(());
    }
    
    // Do proxy thangs
    // Modified from the Arti project
    let proxy = futures::future::select_all(proxy)
        .map(|(finished, _index, _others)| finished);
    futures::select!(
        r = proxy.fuse() => r.0.context(format!("{} proxy failure", r.1)),
        r = async {
            futures::future::pending::<Result<()>>().await
        }.fuse() => r.context("bootstrap"),
    )?;
    Ok(())
}


/// Runs the socks proxy
///
/// # Arguments
///
/// * `runtime` - the runtime to use
/// * `clients` - the Tor clients Arc Mutex
/// * `listen`  - the listener address & port
pub async fn run_socks_proxy<R: Runtime>(
    runtime: R,
    clients: Arc<Mutex<Clients<R>>>,
    listen: Listen,
) -> Result<()> {
    let mut listeners = Vec::new();

    // Try to bind to the SOCKS ports
    match listen.ip_addrs() {
        Ok(addrgroups) => {
            for addrgroup in addrgroups {
                for addr in addrgroup {
                    match runtime.listen(&addr).await {
                        Ok(listener) => {
                            println!("{} {}",
                                     style("Listening on").bold(),
                                     style(addr).bold().yellow());
                            listeners.push(listener);
                        }
                        Err(ref e) if e.raw_os_error() == Some(libc::EAFNOSUPPORT) => {
                            warn_report!(e, "Address family not supported {}", addr);
                        }
                        Err(ref e) => {
                            return Err(anyhow!("Can't listen on {}: {e}", addr));
                        }
                    }
                }
            }
        }
        Err(e) => warn_report!(e, "Invalid listen spec"),
    }

    // Return if no binds were successful
    if listeners.is_empty() {
        error!("Couldn't open any SOCKS listeners.");
        return Err(anyhow!("Couldn't open SOCKS listeners"));
    }

    // Create a stream of incoming socket & listener ID
    let mut incoming = futures::stream::select_all(
        listeners
            .into_iter()
            .map(TcpListener::incoming)
            .enumerate()
            .map(|(listener_id, incoming_conns)| {
                incoming_conns.map(move |socket| (socket, listener_id))
            }),
    );
    
    // Loop over all incoming connections
    // For each one handle the connection
    while let Some((stream, sock_id)) = incoming.next().await {
        let (stream, addr) = match stream {

            Ok((s, a)) => (s, a),
            Err(err) => {
                if accept_err_is_fatal(&err) {
                    return Err(err).context("Failed to receive incoming stream on SOCKS port");
                }
                warn_report!(err, "Incoming stream failed");
                continue;
            }
        };
        
        // Lock the clients
        let clients_lock = clients.lock().await;
        // Loop the randomizer
        let client_lock = loop {
            // Attempt to get an unlocked client
            match clients_lock.random().try_lock() {
                Ok(lock) => break lock,
                Err(..) => continue,
            }
        };
        // Create a socks cotext with the found client
        debug!("Created socks context for client {}", client_lock);
        let socks_context = SocksConnContext {
            client: client_lock.tor.clone(),
        };
        // Drop locks
        drop(client_lock);
        drop(clients_lock);

        // Make a copy of runtime
        // Handle the connection
        let runtime_copy = runtime.clone();
        runtime.spawn(async move {
            let res =
                handle_connection(runtime_copy,
                                  socks_context,
                                  stream,
                                  (sock_id, addr.ip())).await;
            if let Err(error) = res {
                error!("Message: {}", error);
            }
        })?;
    }

    Ok(())
}


/// Type alias for the isolation information.
/// Associated with a given SOCKS connection before SOCKS is negotiated.
type ConnIsolation = (
    usize,  // index for which listen accepted connection
    IpAddr  // Address of the client
);


/// The SOCKS connection context
struct SocksConnContext<R: Runtime> {
    client: TorClient<R>,
}


impl<R: Runtime> SocksConnContext<R> {
    fn get_prefs_and_session(
        &self,
        request: &SocksRequest,
        target_addr: &str,
        conn_isolation: ConnIsolation,
    ) -> Result<(StreamPrefs, TorClient<R>)> {

        let mut prefs = stream_preference(request, target_addr);
        let auth = request.auth().clone();
        prefs.set_isolation(SocksIsolationKey(conn_isolation, auth));
        Ok((prefs, self.client.clone()))
    }
}


/// Find out which kind of address family we can / should use.
///
/// # Arguments
/// 
/// * `req` - the socks request
/// * `addr` - the string address
fn stream_preference(req: &SocksRequest, addr: &str) -> StreamPrefs {
    let mut prefs = StreamPrefs::new();

    
    // If they asked for an IPv4 address correctly, nothing else will do.
    if addr.parse::<Ipv4Addr>().is_ok() {
        prefs.ipv4_only();
        return prefs;
    }

    
    // If they asked for an IPv6 address correctly, nothing else will do.
    if addr.parse::<Ipv6Addr>().is_ok() {
        prefs.ipv6_only();
        return prefs;
    }


    // SOCKS4 and SOCKS4a only support IPv4
    if req.version() == tor_socksproto::SocksVersion::V4 {
        prefs.ipv4_only();
        return prefs;
    }
    

    // Otherwise, default to saying IPv4 is preferred.
    prefs.ipv4_preferred();
    prefs
}


/// A Key used to isolate connections.
///
/// Composed of an usize (representing which listener socket accepted
/// the connection, the source IpAddr of the client, and the
/// authentication string provided by the client).
#[derive(Debug, Clone, PartialEq, Eq)]
struct SocksIsolationKey(ConnIsolation, SocksAuth);

impl arti_client::isolation::IsolationHelper for SocksIsolationKey {
    fn compatible_same_type(&self, other: &Self) -> bool {
        self == other
    }

    fn join_same_type(&self, other: &Self) -> Option<Self> {
        if self == other {
            Some(self.clone())
        } else {
            None
        }
    }
}


/// Given a just-received TCP connection `S` on a SOCKS port, handle the
/// SOCKS handshake and relay the connection over the Tor network.
///
/// Uses `isolation_info` to decide which circuits this connection
/// may use.  Requires that `isolation_info` is a pair listing the listener
/// id and the source address for the socks request.
async fn handle_connection<R, S>(
    runtime: R,
    context: SocksConnContext<R>,
    socks_stream: S,
    isolation_info: ConnIsolation,
) -> Result<()>
where
    R: Runtime,
    S: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
{
    // Create new SOCKS handshake
    let mut handshake = tor_socksproto::SocksProxyHandshake::new();
    
    // Split the socks stream
    let (mut socks_r, mut socks_w) = socks_stream.split();

    // Read the socks request into the buffer
    let mut inbuf = [0_u8; 1024];
    let mut n_read = 0;

    let request = loop {
        if n_read == inbuf.len() {
            // Reject handshakes that don't fit in 1024 bytes
            // This is a temp solution
            return Err(anyhow!("Socks handshake did not fit in 1KiB buffer"));
        }

        // Read some more stuff
        n_read += socks_r
            .read(&mut inbuf[n_read..])
            .await
            .context("Error while reading SOCKS handshake")?;

        // Attempt to advance the handshake
        let action = match handshake.handshake(&inbuf[..n_read]) {
            Err(_) => continue, // Message truncated
            Ok(Err(e)) => {
                if let tor_socksproto::Error::BadProtocol(version) = e {
                    // Check for HTTP methods
                    // Check the first byte of the connection
                    // This contains the SOCKS version
                    if [b'C', b'D', b'G', b'H', b'O', b'P', b'T'].contains(&version) {
                        write_all_and_close(&mut socks_w, WRONG_PROTOCOL_PAYLOAD).await?;
                    }
                }
                // Socks handshake error
                return Err(e.into());
            }
            Ok(Ok(action)) => action,
        };

        // 
        // Reply if needed
        //
        if action.drain > 0 {
            inbuf.copy_within(action.drain..action.drain + n_read, 0);
            n_read -= action.drain;
        }

        if !action.reply.is_empty() {
            write_all_and_flush(&mut socks_w, &action.reply).await?;
        }

        if action.finished {
            break handshake.into_request();
        }
    };
    
    // Return request or write error
    let request = match request {
        Some(r) => r,
        None => {
            error!("SOCKS handshake success, can't convert to request!");
            return Ok(());
        }
    };

    // Unpack request
    // Get target & port
    let addr = request.addr().to_string();
    let port = request.port();
    debug!("Got {} request for: {}:{}", request.command(), addr, port);
    
    // Get session preferences & TOR client
    let (prefs, tor_client) = context.get_prefs_and_session(&request, &addr, isolation_info)?;
    
    // Figure out the request command
    // Perform handling
    match request.command() {
        SocksCmd::CONNECT => {
            // Create a TOR stream
            let tor_stream = tor_client
                .connect_with_prefs((addr.clone(), port), &prefs)
                .await;

            let tor_stream = match tor_stream {
                Ok(s) => s,
                Err(e) => return reply_error(&mut socks_w, &request, e.kind()).await,
            };
            // Okay, great! We have a connection over the Tor network
            debug!("Got stream for: {}:{}", addr, port);
            
            // Send back a SOCKS response, telling the client that it
            // successfully connected
            let reply = request
                .reply(tor_socksproto::SocksStatus::SUCCEEDED, None)
                .context("Encoding socks reply")?;
            write_all_and_flush(&mut socks_w, &reply[..]).await?;

            let (tor_r, tor_w) = tor_stream.split();
            

            // Finally, spawn two background tasks to relay traffic between
            // the socks stream and the tor stream
            runtime.spawn(copy_interactive(socks_r, tor_w).map(|_| ()))?;
            runtime.spawn(copy_interactive(tor_r, socks_w).map(|_| ()))?;
        }
        SocksCmd::RESOLVE => {
            // We've been asked to perform a regular hostname lookup.
            // (This is a tor-specific SOCKS extension.)

            let addr = if let Ok(addr) = addr.parse() {
                // if this is a valid ip address, just parse it and reply.
                Ok(addr)
            } else {
                tor_client
                    .resolve_with_prefs(&addr, &prefs)
                    .await
                    .map_err(|e| e.kind())
                    .and_then(|addrs| addrs.first().copied().ok_or(ErrorKind::Other))
            };
            match addr {
                Ok(addr) => {
                    let reply = request
                        .reply(
                            tor_socksproto::SocksStatus::SUCCEEDED,
                            Some(&SocksAddr::Ip(addr)),
                        )
                        .context("Encoding socks reply")?;
                    write_all_and_close(&mut socks_w, &reply[..]).await?;
                }
                Err(e) => return reply_error(&mut socks_w, &request, e).await,
            }
        }
        SocksCmd::RESOLVE_PTR => {
            // We've been asked to perform a reverse hostname lookup.
            // (This is a tor-specific SOCKS extension.)
            let addr: IpAddr = match addr.parse() {
                Ok(ip) => ip,
                Err(e) => {
                    let reply = request
                        .reply(tor_socksproto::SocksStatus::ADDRTYPE_NOT_SUPPORTED, None)
                        .context("Encoding socks reply")?;
                    write_all_and_close(&mut socks_w, &reply[..]).await?;
                    return Err(anyhow!(e));
                }
            };
            let hosts = match tor_client.resolve_ptr_with_prefs(addr, &prefs).await {
                Ok(hosts) => hosts,
                Err(e) => return reply_error(&mut socks_w, &request, e.kind()).await,
            };
            if let Some(host) = hosts.into_iter().next() {
                // this conversion should never fail, legal DNS names len must be <= 253 but Socks
                // names can be up to 255 chars.
                let hostname = SocksAddr::Hostname(host.try_into()?);
                let reply = request
                    .reply(tor_socksproto::SocksStatus::SUCCEEDED, Some(&hostname))
                    .context("Encoding socks reply")?;
                write_all_and_close(&mut socks_w, &reply[..]).await?;
            }
        }
        _ => {
            // We don't support this SOCKS command.
            warn!("Dropping request, {:?} is unsupported",
                  style(request.command()).red());
            let reply = request
                .reply(tor_socksproto::SocksStatus::COMMAND_NOT_SUPPORTED, None)
                .context("Encoding socks reply")?;
            write_all_and_close(&mut socks_w, &reply[..]).await?;
        }
    };

    Ok(())
}


/// write_all the data to the writer & flush the writer if write_all is successful.
async fn write_all_and_flush<W>(writer: &mut W, buf: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(buf)
        .await
        .context("Error while writing SOCKS reply")?;
    writer
        .flush()
        .await
        .context("Error while flushing SOCKS stream")
}


/// write_all the data to the writer & close the writer if write_all is successful.
async fn write_all_and_close<W>(writer: &mut W, buf: &[u8]) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer
        .write_all(buf)
        .await
        .context("Error while writing SOCKS reply")?;
    writer
        .close()
        .await
        .context("Error while closing SOCKS stream")
}

/// Reply a Socks error based on an arti-client Error and close the stream.
/// Returns the error provided in parameter
async fn reply_error<W>(
    writer: &mut W,
    request: &SocksRequest,
    error: arti_client::ErrorKind,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    use {tor_socksproto::SocksStatus as S, ErrorKind as EK};

    // TODO: Currently we _always_ try to return extended SOCKS return values
    // for onion service failures from proposal 304 when they are appropriate.
    // But according to prop 304, this is something we should only do when it's
    // requested, for compatibility with SOCKS implementations that can't handle
    // unexpected REP codes.
    //
    // I suggest we make these extended error codes "always-on" for now, and
    // later add a feature to disable them if it's needed. -nickm

    // TODO: Perhaps we should map the extended SOCKS return values for onion
    // service failures unconditionally, even if we haven't compiled in onion
    // service client support.  We can make that change after the relevant
    // ErrorKinds are no longer `experimental-api` in `tor-error`.

    // We need to send an error. See what kind it is.
    let status = match error {
        EK::RemoteNetworkFailed => S::TTL_EXPIRED,

        _ => S::GENERAL_FAILURE,
    };
    let reply = request
        .reply(status, None)
        .context("Encoding socks reply")?;
    // if writing back the error fail, still return the original error
    let _ = write_all_and_close(writer, &reply[..]).await;

    Err(anyhow!(error))
}


/// Copy all the data from `reader` into `writer` until we encounter an EOF or
/// an error.
///
/// Unlike as futures::io::copy(), this function is meant for use with
/// interactive readers and writers, where the reader might pause for
/// a while, but where we want to send data on the writer as soon as
/// it is available.
///
/// This function assumes that the writer might need to be flushed for
/// any buffered data to be sent.  It tries to minimize the number of
/// flushes, however, by only flushing the writer when the reader has no data.
async fn copy_interactive<R, W>(mut reader: R, mut writer: W) -> IoResult<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    use futures::{poll, task::Poll};

    let mut buf = [0_u8; 1024];

    // At this point we could just loop, calling read().await,
    // write_all().await, and flush().await.  But we want to be more
    // clever than that: we only want to flush when the reader is
    // stalled.  That way we can pack our data into as few cells as
    // possible, but flush it immediately whenever there's no more
    // data coming.
    let loop_result: IoResult<()> = loop {
        let mut read_future = reader.read(&mut buf[..]);
        match poll!(&mut read_future) {
            Poll::Ready(Err(e)) => break Err(e),
            Poll::Ready(Ok(0)) => break Ok(()), // EOF
            Poll::Ready(Ok(n)) => {
                writer.write_all(&buf[..n]).await?;
                continue;
            }
            Poll::Pending => writer.flush().await?,
        }

        // The read future is pending, so we should wait on it.
        match read_future.await {
            Err(e) => break Err(e),
            Ok(0) => break Ok(()),
            Ok(n) => {
                writer.write_all(&buf[..n]).await?
            },
        }
    };

    // Make sure that we flush any lingering data if we can.
    //
    // If there is a difference between closing and dropping, then we
    // only want to do a "proper" close if the reader closed cleanly.
    let flush_result = if loop_result.is_ok() {
        writer.close().await
    } else {
        writer.flush().await
    };

    loop_result.or(flush_result)
}


/// Return true if a given IoError, when received from accept, is a fatal
/// error.
fn accept_err_is_fatal(err: &IoError) -> bool {
    // Currently, EMFILE and ENFILE aren't distinguished by ErrorKind;
    // we need to use OS-specific errors. :P
    match err.raw_os_error() {
        #[cfg(unix)]
        Some(libc::EMFILE) | Some(libc::ENFILE) => false,
        _ => true,
    }
}
