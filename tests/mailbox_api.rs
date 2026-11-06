//! `Mailbox` construction and reuse through `MessageBuilder`.

use mime_message::{parse, Error, Mailbox, Message};

#[test]
fn mailbox_new_and_from_str_validate_and_normalise() {
    let mailbox = Mailbox::new(Some("  Shop  "), " shop@example.com ").expect("valid mailbox");
    assert_eq!(mailbox.name.as_deref(), Some("Shop"));
    assert_eq!(mailbox.address, "shop@example.com");

    let anonymous = Mailbox::new(Some("   "), "kunde@example.com").expect("valid mailbox");
    assert_eq!(anonymous.name, None);

    let parsed: Mailbox = "Shop <shop@example.com>".parse().expect("valid mailbox");
    assert_eq!(parsed, mailbox);

    assert!(matches!(
        Mailbox::new(None, "not-an-address"),
        Err(Error::InvalidMailbox(_))
    ));
    assert!(matches!(
        "not-an-address".parse::<Mailbox>(),
        Err(Error::InvalidMailbox(_))
    ));
    assert!(matches!(
        Mailbox::new(Some("Bad\r\nBcc: attacker@example.com"), "a@example.com"),
        Err(Error::InvalidMailbox(_))
    ));
}

#[test]
fn builder_accepts_constructed_and_parsed_mailboxes() {
    let sender = Mailbox::new(Some("Shop"), "shop@example.com").expect("valid sender");
    let parsed = parse("From: other@example.com\r\n\r\nx").expect("parsed message");

    let message = Message::builder()
        .from_mailbox(sender)
        .expect("valid sender")
        .to_mailbox(parsed.from)
        .expect("valid recipient")
        .cc_mailbox(Mailbox::new(Some("Cc"), "cc@example.com").expect("valid cc"))
        .expect("valid cc")
        .bcc_mailbox(Mailbox::new(None, "secret@example.com").expect("valid bcc"))
        .expect("valid bcc")
        .body("hello")
        .build()
        .expect("message builds");

    assert_eq!(message.from.name.as_deref(), Some("Shop"));
    assert_eq!(message.to[0].address, "other@example.com");
    assert_eq!(message.cc[0].address, "cc@example.com");
    assert_eq!(message.bcc[0].address, "secret@example.com");

    let raw = String::from_utf8(message.render().expect("render")).expect("rendered UTF-8");
    assert!(!raw.contains("secret@example.com"));
}

#[test]
fn builder_revalidates_public_mailbox_fields() {
    let mut message = parse("From: a@example.com\r\nTo: b@example.com\r\n\r\nx").expect("parse");
    message.from.address = "a@example.com, attacker@example.com".to_string();
    assert!(matches!(
        Message::builder().from_mailbox(message.from),
        Err(Error::InvalidMailbox(_))
    ));

    let mut message = parse("From: a@example.com\r\nTo: b@example.com\r\n\r\nx").expect("parse");
    message.to[0].name = Some("Bad\r\nBcc: attacker@example.com".to_string());
    assert!(matches!(
        Message::builder()
            .from("a@example.com")
            .expect("valid sender")
            .to_mailbox(message.to.remove(0)),
        Err(Error::InvalidMailbox(_))
    ));
}
