/// The available configuration keys.
/*
extern crate strum;
#[macro_use]
extern crate strum_macros;
// */


use strum::{EnumProperty, IntoEnumIterator};
use strum_macros::{AsRefStr, Display, EnumIter, EnumString};


#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Display,
    EnumString,
    AsRefStr,
    EnumIter,
    EnumProperty,
    PartialOrd,
    Ord,
)]
#[strum(serialize_all = "snake_case")]
pub enum Config {
    /// Email address, used in the `From:` field.
    Addr,

    /// IMAP server hostname.
    MailServer,

    /// IMAP server username.
    MailUser,

    /// IMAP server password.
    MailPw,

    /// IMAP server port.
    MailPort,

    /// IMAP server security (e.g. TLS, STARTTLS).
    MailSecurity,

    /// How to check IMAP server TLS certificates.
    ImapCertificateChecks,

    /// SMTP server hostname.
    SendServer,

    /// SMTP server username.
    SendUser,

    /// SMTP server password.
    SendPw,

    /// SMTP server port.
    SendPort,

    /// SMTP server security (e.g. TLS, STARTTLS).
    SendSecurity,

    /// How to check SMTP server TLS certificates.
    SmtpCertificateChecks,

    /// Whether to use OAuth 2.
    ///
    /// Historically contained other bitflags, which are now deprecated.
    /// Should not be extended in the future, create new config keys instead.
    ServerFlags,

    /// True if SOCKS5 is enabled.
    ///
    /// Can be used to disable SOCKS5 without erasing SOCKS5 configuration.
    Socks5Enabled,

    /// SOCKS5 proxy server hostname or address.
    Socks5Host,

    /// SOCKS5 proxy server port.
    Socks5Port,

    /// SOCKS5 proxy server username.
    Socks5User,

    /// SOCKS5 proxy server password.
    Socks5Password,

    /// Own name to use in the `From:` field when sending messages.
    Displayname,

    /// Own status to display, sent in message footer.
    Selfstatus,

    /// Own avatar filename.
    Selfavatar,

    /// Send BCC copy to self.
    ///
    /// Should be enabled for multidevice setups.
    #[strum(props(default = "1"))]
    BccSelf,

    /// True if encryption is preferred according to Autocrypt standard.
    #[strum(props(default = "1"))]
    E2eeEnabled,

    /// True if Message Delivery Notifications (read receipts) should
    /// be sent and requested.
    #[strum(props(default = "1"))]
    MdnsEnabled,

    /// True if "Sent" folder should be watched for changes.
    #[strum(props(default = "0"))]
    SentboxWatch,

    /// True if chat messages should be moved to a separate folder.
    #[strum(props(default = "1"))]
    MvboxMove,

    /// Watch for new messages in the "Mvbox" (aka DeltaChat folder) only.
    ///
    /// This will not entirely disable other folders, e.g. the spam folder will also still
    /// be watched for new messages.
    #[strum(props(default = "0"))]
    OnlyFetchMvbox,

    /// Whether to show classic emails or only chat messages.
    #[strum(props(default = "2"))] // also change ShowEmails.default() on changes
    ShowEmails,

    /// Quality of the media files to send.
    #[strum(props(default = "0"))] // also change MediaQuality.default() on changes
    MediaQuality,

    /// If set to "1", on the first time `start_io()` is called after configuring,
    /// the newest existing messages are fetched.
    /// Existing recipients are added to the contact database regardless of this setting.
    #[strum(props(default = "0"))]
    FetchExistingMsgs,

    /// If set to "1", then existing messages are considered to be already fetched.
    /// This flag is reset after successful configuration.
    #[strum(props(default = "1"))]
    FetchedExistingMsgs,

    /// Type of the OpenPGP key to generate.
    #[strum(props(default = "0"))]
    KeyGenType,

    /// Timer in seconds after which the message is deleted from the
    /// server.
    ///
    /// Equals to 0 by default, which means the message is never
    /// deleted.
    ///
    /// Value 1 is treated as "delete at once": messages are deleted
    /// immediately, without moving to DeltaChat folder.
    #[strum(props(default = "0"))]
    DeleteServerAfter,

    /// Timer in seconds after which the message is deleted from the
    /// device.
    ///
    /// Equals to 0 by default, which means the message is never
    /// deleted.
    #[strum(props(default = "0"))]
    DeleteDeviceAfter,

    /// Move messages to the Trash folder instead of marking them "\Deleted". Overrides
    /// `ProviderOptions::delete_to_trash`.
    DeleteToTrash,

    /// Save raw MIME messages with headers in the database if true.
    SaveMimeHeaders,

    /// The primary email address. Also see `SecondaryAddrs`.
    ConfiguredAddr,

    /// Configured IMAP server hostname.
    ConfiguredMailServer,

    /// Configured IMAP server username.
    ConfiguredMailUser,

    /// Configured IMAP server password.
    ConfiguredMailPw,

    /// Configured IMAP server port.
    ConfiguredMailPort,

    /// Configured IMAP server security (e.g. TLS, STARTTLS).
    ConfiguredMailSecurity,

    /// How to check IMAP server TLS certificates.
    ConfiguredImapCertificateChecks,

    /// Configured SMTP server hostname.
    ConfiguredSendServer,

    /// Configured SMTP server username.
    ConfiguredSendUser,

    /// Configured SMTP server password.
    ConfiguredSendPw,

    /// Configured SMTP server port.
    ConfiguredSendPort,

    /// How to check SMTP server TLS certificates.
    ConfiguredSmtpCertificateChecks,

    /// Whether OAuth 2 is used with configured provider.
    ConfiguredServerFlags,

    /// Configured SMTP server security (e.g. TLS, STARTTLS).
    ConfiguredSendSecurity,

    /// Configured folder for incoming messages.
    ConfiguredInboxFolder,

    /// Configured folder for chat messages.
    ConfiguredMvboxFolder,

    /// Configured "Sent" folder.
    ConfiguredSentboxFolder,

    /// Configured "Trash" folder.
    ConfiguredTrashFolder,

    /// Unix timestamp of the last successful configuration.
    ConfiguredTimestamp,

    /// ID of the configured provider from the provider database.
    ConfiguredProvider,

    /// True if account is configured.
    Configured,

    /// All secondary self addresses separated by spaces
    /// (`addr1@example.org addr2@example.org addr3@example.org`)
    SecondaryAddrs,

    /// Read-only core version string.
    #[strum(serialize = "sys.version")]
    SysVersion,

    /// Maximal recommended attachment size in bytes.
    #[strum(serialize = "sys.msgsize_max_recommended")]
    SysMsgsizeMaxRecommended,

    /// Space separated list of all config keys available.
    #[strum(serialize = "sys.config_keys")]
    SysConfigKeys,

    /// True if it is a bot account.
    Bot,

    /// True when to skip initial start messages in groups.
    #[strum(props(default = "0"))]
    SkipStartMessages,

    /// Whether we send a warning if the password is wrong (set to false when we send a warning
    /// because we do not want to send a second warning)
    #[strum(props(default = "0"))]
    NotifyAboutWrongPw,

    /// If a warning about exceeding quota was shown recently,
    /// this is the percentage of quota at the time the warning was given.
    /// Unset, when quota falls below minimal warning threshold again.
    QuotaExceeding,

    /// address to webrtc instance to use for videochats
    WebrtcInstance,

    /// Timestamp of the last time housekeeping was run
    LastHousekeeping,

    /// Timestamp of the last `CantDecryptOutgoingMsgs` notification.
    LastCantDecryptOutgoingMsgs,

    /// To how many seconds to debounce scan_all_folders. Used mainly in tests, to disable debouncing completely.
    #[strum(props(default = "60"))]
    ScanAllFoldersDebounceSecs,

    /// Whether to avoid using IMAP IDLE even if the server supports it.
    ///
    /// This is a developer option for testing "fake idle".
    #[strum(props(default = "0"))]
    DisableIdle,

    /// Defines the max. size (in bytes) of messages downloaded automatically.
    /// 0 = no limit.
    #[strum(props(default = "0"))]
    DownloadLimit,

    /// Enable sending and executing (applying) sync messages. Sending requires `BccSelf` to be set.
    #[strum(props(default = "1"))]
    SyncMsgs,

    /// Space-separated list of all the authserv-ids which we believe
    /// may be the one of our email server.
    ///
    /// See `crate::authres::update_authservid_candidates`.
    AuthservIdCandidates,

    /// Make all outgoing messages with Autocrypt header "multipart/signed".
    SignUnencrypted,

    /// Let the core save all events to the database.
    /// This value is used internally to remember the MsgId of the logging xdc
    #[strum(props(default = "0"))]
    DebugLogging,

    /// Last message processed by the bot.
    LastMsgId,

    /// How often to gossip Autocrypt keys in chats with multiple recipients, in seconds. 2 days by
    /// default.
    ///
    /// This is not supposed to be changed by UIs and only used for testing.
    #[strum(props(default = "172800"))]
    GossipPeriod,

    /// Feature flag for verified 1:1 chats; the UI should set it
    /// to 1 if it supports verified 1:1 chats.
    /// Regardless of this setting, `chat.is_protected()` returns true while the key is verified,
    /// and when the key changes, an info message is posted into the chat.
    /// 0=Nothing else happens when the key changes.
    /// 1=After the key changed, `can_send()` returns false and `is_protection_broken()` returns true
    /// until `chat_id.accept()` is called.
    #[strum(props(default = "0"))]
    VerifiedOneOnOneChats,

    /// Row ID of the key in the `keypairs` table
    /// used for signatures, encryption to self and included in `Autocrypt` header.
    KeyId,

    /// This key is sent to the self_reporting bot so that the bot can recognize the user
    /// without storing the email address
    SelfReportingId,
}

pub enum Status {
    /// Provider is known to be working with Delta Chat.
    Ok = 1,

    /// Provider works with Delta Chat, but requires some preparation,
    /// such as changing the settings in the web interface.
    Preparation = 2,

    /// Provider is known not to work with Delta Chat.
    Broken = 3,
}

pub enum Protocol {
    /// SMTP protocol.
    Smtp = 1,

    /// IMAP protocol.
    Imap = 2,
}

#[derive(Default)]
pub enum Socket {
    /// Unspecified socket security, select automatically.
    #[default]
    Automatic = 0,

    /// TLS connection.
    Ssl = 1,

    /// STARTTLS connection.
    Starttls = 2,

    /// No TLS, plaintext connection.
    Plain = 3,
}

pub enum UsernamePattern {
    /// Whole email is used as username.
    Email = 1,

    /// Part of address before `@` is used as username.
    Emaillocalpart = 2,
}

pub enum Oauth2Authorizer {
    /// Yandex.
    Yandex = 1,

    /// Gmail.
    Gmail = 2,
}

pub struct Server {
    /// Server protocol, e.g. SMTP or IMAP.
    pub protocol: Protocol,

    /// Port security, e.g. TLS or STARTTLS.
    pub socket: Socket,

    /// Server host.
    pub hostname: &'static str,

    /// Server port.
    pub port: u16,

    /// Pattern used to construct login usernames from email addresses.
    pub username_pattern: UsernamePattern,
}

pub struct ConfigDefault {
    /// Configuration variable name.
    pub key: Config,

    /// Configuration variable value.
    pub value: &'static str,
}

pub struct Provider {
    /// Unique ID, corresponding to provider database filename.
    pub id: &'static str,

    /// Provider status according to manual testing.
    pub status: Status,

    /// Hint to be shown to the user on the login screen.
    pub before_login_hint: &'static str,

    /// Hint to be added to the device chat after provider configuration.
    pub after_login_hint: &'static str,

    /// URL of the page with provider overview.
    pub overview_page: &'static str,

    /// List of provider servers.
    pub server: &'static [Server],

    /// Default configuration values to set when provider is configured.
    pub config_defaults: Option<&'static [ConfigDefault]>,

    /// Type of OAuth 2 authorization if provider supports it.
    pub oauth2_authorizer: Option<Oauth2Authorizer>,

    /// Options with good defaults.
    pub opt: ProviderOptions,
}

pub struct ProviderOptions {
    /// True if provider is known to use use proper,
    /// not self-signed certificates.
    pub strict_tls: bool,

    /// Maximum number of recipients the provider allows to send a single email to.
    pub max_smtp_rcpt_to: Option<u16>,

    /// Move messages to the Trash folder instead of marking them "\Deleted".
    pub delete_to_trash: bool,
}
