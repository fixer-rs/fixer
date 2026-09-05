//! Round-trip tests for the repeating-group types emitted by `fixer-gen`.
//!
//! `fixer-fix/src` is generated and rewritten by `make generate`, so these live
//! outside it. They cover the parts that generation can get subtly wrong: the
//! template order (whose first entry is the group delimiter), the derived
//! `NumInGroup` count, and nested groups.

use fixer::message::Message;
use fixer_fix::{fix44, tag};

/// Writing a group and reading it back through the generated accessors.
#[test]
fn market_data_entries_round_trip() {
    let mut snapshot = fix44::market_data_snapshot_full_refresh::MarketDataSnapshotFullRefresh::new();

    let mut entries = fix44::market_data_snapshot_full_refresh::NoMDEntriesRepeatingGroup::new();
    {
        let mut e = entries.add();
        e.set_md_entry_type('0'.to_string());
        e.set_md_entry_px(rust_decimal::Decimal::new(7499, 5), 5);
    }
    {
        let mut e = entries.add();
        e.set_md_entry_type('1'.to_string());
        e.set_md_entry_px(rust_decimal::Decimal::new(7501, 5), 5);
    }
    assert_eq!(2, entries.len());
    assert!(!entries.is_empty());

    snapshot.set_no_md_entries(entries);

    let read_back = snapshot.get_no_md_entries().expect("group should be present");
    assert_eq!(2, read_back.len());
    assert_eq!("0", read_back.get(0).get_md_entry_type().unwrap());
    assert_eq!("1", read_back.get(1).get_md_entry_type().unwrap());
    assert!(read_back.get(0).has_md_entry_px());

    // The NumInGroup counter is derived from the entries, never set by hand.
    let raw = snapshot.to_message().build();
    let raw = String::from_utf8_lossy(&raw);
    assert!(
        raw.contains(&format!("\u{1}{}=2\u{1}", tag::NO_MD_ENTRIES)),
        "expected NoMDEntries=2 in {raw}"
    );
}

/// Reading a group out of a message parsed off the wire, rather than one we
/// built in memory: this is the path that goes through the group template,
/// where the delimiter and template order actually matter.
#[test]
fn market_data_entries_parsed_from_wire() {
    let mut snapshot = fix44::market_data_snapshot_full_refresh::MarketDataSnapshotFullRefresh::new();

    let mut entries = fix44::market_data_snapshot_full_refresh::NoMDEntriesRepeatingGroup::new();
    {
        let mut e = entries.add();
        e.set_md_entry_type("0".to_string());
        e.set_md_entry_px(rust_decimal::Decimal::new(7499, 5), 5);
        e.set_md_entry_size(rust_decimal::Decimal::new(60, 0), 0);
    }
    {
        let mut e = entries.add();
        e.set_md_entry_type("1".to_string());
        e.set_md_entry_px(rust_decimal::Decimal::new(7501, 5), 5);
        e.set_md_entry_size(rust_decimal::Decimal::new(70, 0), 0);
    }
    snapshot.set_no_md_entries(entries);

    // Serialize to the wire and parse it back, so the group is rebuilt by
    // RepeatingGroup::read against the generated template.
    let mut msg = snapshot.to_message();
    {
        let mut header = fix44::header::Header::new(&mut msg.header.field_map);
        header.set_sender_comp_id("TEST".to_string());
        header.set_target_comp_id("TST".to_string());
        header.set_msg_seq_num(7);
        header.set_sending_time(jiff::Timestamp::UNIX_EPOCH);
    }
    let raw = msg.build();

    let mut parsed = Message::new();
    parsed
        .parse_message(&raw)
        .unwrap_or_else(|e| panic!("built message should parse: {e}"));

    let snapshot =
        fix44::market_data_snapshot_full_refresh::MarketDataSnapshotFullRefresh::from_message(parsed);
    let entries = snapshot
        .get_no_md_entries()
        .expect("NoMDEntries should be readable after parsing");

    assert_eq!(2, entries.len());
    assert_eq!("0", entries.get(0).get_md_entry_type().unwrap());
    assert_eq!("1", entries.get(1).get_md_entry_type().unwrap());
    assert_eq!(
        rust_decimal::Decimal::new(7499, 5),
        entries.get(0).get_md_entry_px().unwrap()
    );
    assert_eq!(
        rust_decimal::Decimal::new(70, 0),
        entries.get(1).get_md_entry_size().unwrap()
    );
}

/// A group nested inside another group, which is where the per-occurrence type
/// naming and the recursive template construction matter.
#[test]
fn nested_group_round_trip() {
    use fix44::new_order_list::{NoOrdersNoPartyIDsRepeatingGroup, NoOrdersRepeatingGroup};

    let mut orders = NoOrdersRepeatingGroup::new();
    {
        let mut order = orders.add();
        order.set_cl_ord_id("ORDER-1".to_string());
        order.set_list_seq_no(1);

        let mut parties = NoOrdersNoPartyIDsRepeatingGroup::new();
        {
            let mut p = parties.add();
            p.set_party_id("BROKER-A".to_string());
            p.set_party_role(1);
        }
        {
            let mut p = parties.add();
            p.set_party_id("BROKER-B".to_string());
            p.set_party_role(2);
        }
        order.set_no_party_i_ds(parties);
    }
    assert_eq!(1, orders.len());

    let order = orders.get(0);
    assert_eq!("ORDER-1", order.get_cl_ord_id().unwrap());

    let parties = order.get_no_party_i_ds().expect("nested group should read back");
    assert_eq!(2, parties.len());
    assert_eq!("BROKER-A", parties.get(0).get_party_id().unwrap());
    assert_eq!("BROKER-B", parties.get(1).get_party_id().unwrap());
    assert_eq!(2, parties.get(1).get_party_role().unwrap());
}

/// An empty group still round-trips, and reports a zero count.
#[test]
fn empty_group_round_trip() {
    let mut snapshot = fix44::market_data_snapshot_full_refresh::MarketDataSnapshotFullRefresh::new();

    let entries = fix44::market_data_snapshot_full_refresh::NoMDEntriesRepeatingGroup::new();
    assert!(entries.is_empty());
    snapshot.set_no_md_entries(entries);

    assert!(snapshot.has_no_md_entries());
    assert_eq!(0, snapshot.get_no_md_entries().unwrap().len());
}

/// The header group (`NoHops`) is generated the same way as body groups.
#[test]
fn header_group_round_trip() {
    let mut msg = Message::new();
    {
        let mut header = fix44::header::Header::new(&mut msg.header.field_map);

        let mut hops = fix44::header::NoHopsRepeatingGroup::new();
        {
            let mut hop = hops.add();
            hop.set_hop_comp_id("HOP-1".to_string());
        }
        header.set_no_hops(hops);

        assert!(header.has_no_hops());
        let read_back = header.get_no_hops().expect("NoHops should be readable");
        assert_eq!(1, read_back.len());
        assert_eq!("HOP-1", read_back.get(0).get_hop_comp_id().unwrap());
    }
}

/// Each group entry must start with the group's delimiter (its first template
/// field), even when that tag is not the numerically lowest in the entry.
/// `NoPartyIDs` is delimited by `PartyID` (448) but also carries
/// `PartyIDSource` (447), so plain ascending-tag order would emit it second
/// and produce a message the counterparty cannot parse.
#[test]
fn group_entry_starts_with_delimiter() {
    use fix44::new_order_single::{NewOrderSingle, NoPartyIDsRepeatingGroup};

    let mut nos = NewOrderSingle::new(
        fixer_fix::field::ClOrdIDField::new("ORDER-1".to_string()),
        fixer_fix::field::SideField::new("1".to_string()),
        fixer_fix::field::TransactTimeField::new(jiff::Timestamp::UNIX_EPOCH),
        fixer_fix::field::OrdTypeField::new("1".to_string()),
    );

    let mut parties = NoPartyIDsRepeatingGroup::new();
    {
        let mut p = parties.add();
        // Set the lower tag first, so an ordering bug is visible in the output.
        p.set_party_id_source("D".to_string());
        p.set_party_id("BROKER-A".to_string());
    }
    nos.set_no_party_i_ds(parties);

    let raw = nos.to_message().build();
    let raw = String::from_utf8_lossy(&raw).into_owned();

    let marker = format!("\u{1}{}=1\u{1}", tag::NO_PARTY_I_DS);
    let count_at = raw
        .find(&marker)
        .unwrap_or_else(|| panic!("NoPartyIDs count not found in {raw}"));
    let rest = &raw[count_at + 1..];
    assert!(
        rest.starts_with(&format!(
            "{}=1\u{1}{}=",
            tag::NO_PARTY_I_DS,
            tag::PARTY_ID
        )),
        "delimiter PartyID must immediately follow the count, got {rest}"
    );
}

/// The case from issue #94: a nested group parsed off the wire must be readable
/// back through the parent entry. `RepeatingGroup::read` used to store only the
/// nested group's `NumInGroup` counter on the parent entry and drop the entries
/// themselves, so the data was silently unreachable even though parsing
/// succeeded and the counts matched.
#[test]
fn nested_group_survives_wire_parse() {
    use fix44::new_order_list::{
        NewOrderList, NoOrdersNoPartyIDsRepeatingGroup, NoOrdersRepeatingGroup,
    };

    let mut nol = NewOrderList::new(
        fixer_fix::field::ListIDField::new("LIST-1".to_string()),
        fixer_fix::field::BidTypeField::new(1),
        fixer_fix::field::TotNoOrdersField::new(1),
    );

    let mut orders = NoOrdersRepeatingGroup::new();
    {
        let mut order = orders.add();
        order.set_cl_ord_id("ORDER-1".to_string());
        order.set_list_seq_no(1);
        order.set_side("1".to_string());

        let mut parties = NoOrdersNoPartyIDsRepeatingGroup::new();
        {
            let mut p = parties.add();
            p.set_party_id("BROKER-A".to_string());
            p.set_party_role(1);
        }
        {
            let mut p = parties.add();
            p.set_party_id("BROKER-B".to_string());
            p.set_party_role(2);
        }
        order.set_no_party_i_ds(parties);
    }
    nol.set_no_orders(orders);

    let mut msg = nol.to_message();
    {
        let mut header = fix44::header::Header::new(&mut msg.header.field_map);
        header.set_sender_comp_id("TEST".to_string());
        header.set_target_comp_id("TST".to_string());
        header.set_msg_seq_num(1);
        header.set_sending_time(jiff::Timestamp::UNIX_EPOCH);
    }
    let raw = msg.build();

    let mut parsed = Message::new();
    parsed
        .parse_message(&raw)
        .unwrap_or_else(|e| panic!("built message should parse: {e}"));

    let orders = NewOrderList::from_message(parsed)
        .get_no_orders()
        .expect("NoOrders should be readable after parsing");
    assert_eq!(1, orders.len());

    let order = orders.get(0);
    assert_eq!("ORDER-1", order.get_cl_ord_id().unwrap());

    let parties = order
        .get_no_party_i_ds()
        .expect("nested NoPartyIDs should be readable after parsing");
    assert_eq!(2, parties.len(), "nested group entries were dropped");
    assert_eq!("BROKER-A", parties.get(0).get_party_id().unwrap());
    assert_eq!(1, parties.get(0).get_party_role().unwrap());
    assert_eq!("BROKER-B", parties.get(1).get_party_id().unwrap());
    assert_eq!(2, parties.get(1).get_party_role().unwrap());
}
