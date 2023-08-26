use crate::{
    application::Application,
    log::{LogEnum, LogFactoryEnum, LogFactoryTrait},
    net::proxy::load_dialer_config,
    session::{factory::SessionFactory, session_id::SessionID, settings::SessionSettings, Session},
    settings::Settings,
    store::{MessageStoreFactoryEnum, MessageStoreFactoryTrait},
};
use dashmap::DashMap;
use scopeguard::defer;
// use defer_lite::defer;
use simple_error::SimpleResult;
use std::{collections::HashMap, sync::Arc};
use tokio::time::{sleep, Duration, Instant};
use tokio::{
    runtime::Handle,
    sync::{
        mpsc::{channel, unbounded_channel, Receiver, Sender, UnboundedReceiver, UnboundedSender},
        Mutex, OnceCell,
    },
};
use wg::AsyncWaitGroup;

pub struct Initiator<A: Application> {
    app: Arc<Mutex<A>>,
    settings: Settings,
    session_settings: DashMap<Arc<SessionID>, SessionSettings>,
    store_factory: MessageStoreFactoryEnum,
    log_factory: LogFactoryEnum,
    global_log: LogEnum,
    stop_chan: Option<UnboundedReceiver<bool>>,
    wg: AsyncWaitGroup,
    sessions: HashMap<Arc<SessionID>, Arc<Mutex<Session>>>,
    session_factory: SessionFactory,
}

impl<A> Initiator<A>
where
    A: Application + 'static,
{
    pub async fn new(
        app: Arc<Mutex<A>>,
        store_factory: MessageStoreFactoryEnum,
        app_settings: Settings,
        mut log_factory: LogFactoryEnum,
    ) -> SimpleResult<Self> {
        let session_settings = app_settings.session_settings().await;
        let global_log = log_factory
            .create()
            .await
            .map_err(|err| simple_error!(err))?;
        let mut i = Self {
            app: app.clone(),
            settings: app_settings,
            session_settings,
            store_factory: store_factory.clone(),
            log_factory: log_factory.clone(),
            global_log,
            stop_chan: None,
            wg: AsyncWaitGroup::new(),
            sessions: Default::default(),
            session_factory: SessionFactory {
                build_initiators: true,
            },
        };

        for entry in i.session_settings.iter() {
            let (session_id, s) = entry.pair();
            let session = i
                .session_factory
                .create_session(
                    session_id.clone(),
                    store_factory.clone(),
                    s,
                    log_factory.clone(),
                    app.clone(),
                )
                .await?;
            i.sessions.insert(session_id.clone(), session);
        }

        Ok(i)
    }

    pub async fn start(&mut self) -> SimpleResult<()> {
        let (_sender, receiver) = unbounded_channel::<bool>();
        self.stop_chan = Some(receiver);

        for entry in self.session_settings.iter() {
            let (session_id, settings) = entry.pair();
            //     // TODO: move into session factory.
            //     var tlsConfig *tls.Config
            //     if tlsConfig, err = loadTLSConfig(settings); err != nil {
            //         return
            //     }

            // let dialer = load_dialer_config(settings).await?;

            let wg_done = self.wg.add(1);
            tokio::spawn(async move {
                //         i.handleConnection(i.sessions[sessID], tlsConfig, dialer)
                wg_done.done()
            });
            //     go func(sessID SessionID) {
            //         i.wg.Done()
            //     }(sessionID)
        }

        Ok(())
    }

    // Stop Initiator.
    pub async fn stop(&mut self) {
        tokio::select! {
            Some(_) = self.stop_chan.as_mut().unwrap().recv() => {
                // Closed already.
                return
            }
            else => {
            }
        }
        self.stop_chan.as_mut().unwrap().close();
        self.wg.wait().await;
    }

    // wait_for_in_session_time returns true if the session is in session, false if the handler should stop.
    async fn wait_for_in_session_time(&mut self, session: Arc<Mutex<Session>>) -> bool {
        let (in_session_time_tx, mut in_session_time_rx) = channel::<bool>(1);
        tokio::spawn(async move {
            session.lock().await.wait_for_in_session_time().await;
            drop(in_session_time_tx)
        });

        tokio::select! {
            Some(_) = in_session_time_rx.recv() => {}
            Some(_) = self.stop_chan.as_mut().unwrap().recv() => {
                return false;
            }
        }

        true
    }

    // wait_for_reconnect_interval returns true if a reconnect should be re-attempted, false if handler should stop.
    async fn wait_for_reconnect_interval(&mut self, reconnect_interval: Duration) -> bool {
        let sl = sleep(reconnect_interval);
        tokio::pin!(sl);

        tokio::select! {
            () = &mut sl => {}
            Some(_) = self.stop_chan.as_mut().unwrap().recv() => {
                return false;
            }
        }

        true
    }

    async fn handle_connection(&mut self, session: Arc<Mutex<Session>>) {
        // , tlsConfig *tls.Config, dialer proxy.Dialer) {
        let wg = AsyncWaitGroup::new();
        let wg_done = wg.add(1);

        let running_session = session.clone();

        tokio::spawn(async move {
            running_session.lock().await.run().await;
            wg_done.done();
        });

        let executor = Handle::current();
        let stop_session = session.clone();

        defer! {
            executor.spawn({
                async move {
                    stop_session.lock().await.stop().await;
                }
            });

        }
        let mut connection_attempt = 0;

        loop {
            if !self.wait_for_in_session_time(session.clone()).await {
                return;
            }

            //         var disconnected chan interface{}
            //         var msgIn chan fixIn
            //         var msgOut chan []byte

            //         address := session.SocketConnectAddress[connectionAttempt%len(session.SocketConnectAddress)]
            //         session.log.OnEventf("Connecting to: %v", address)

            //         netConn, err := dialer.Dial("tcp", address)
            //         if err != nil {
            //             session.log.OnEventf("Failed to connect: %v", err)
            //             goto reconnect
            //         } else if tlsConfig != nil {
            //             // Unless InsecureSkipVerify is true, server name config is required for TLS
            //             // to verify the received certificate
            //             if !tlsConfig.InsecureSkipVerify && len(tlsConfig.ServerName) == 0 {
            //                 serverName := address
            //                 if c := strings.LastIndex(serverName, ":"); c > 0 {
            //                     serverName = serverName[:c]
            //                 }
            //                 tlsConfig.ServerName = serverName
            //             }
            //             tlsConn := tls.Client(netConn, tlsConfig)
            //             if err = tlsConn.Handshake(); err != nil {
            //                 session.log.OnEventf("Failed handshake: %v", err)
            //                 goto reconnect
            //             }
            //             netConn = tlsConn
            //         }

            //         msgIn = make(chan fixIn)
            //         msgOut = make(chan []byte)
            //         if err := session.connect(msgIn, msgOut); err != nil {
            //             session.log.OnEventf("Failed to initiate: %v", err)
            //             goto reconnect
            //         }

            //         go readLoop(newParser(bufio.NewReader(netConn)), msgIn)
            //         disconnected = make(chan interface{})
            //         go func() {
            //             writeLoop(netConn, msgOut, session.log)
            //             if err := netConn.Close(); err != nil {
            //                 session.log.OnEvent(err.Error())
            //             }
            //             close(disconnected)
            //         }()

            //         select {
            //         case <-disconnected:
            //         case <-i.stopChan:
            //             return
            //         }

            //     reconnect:
            //         connectionAttempt++
            //         session.log.OnEventf("Reconnecting in %v", session.ReconnectInterval)
            //         if !i.waitForReconnectInterval(session.ReconnectInterval) {
            //             return
            //         }
        }
    }
}
