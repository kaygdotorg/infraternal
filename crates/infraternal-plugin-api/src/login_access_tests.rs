use super::*;

const LINUX: OrdinaryUids = OrdinaryUids::LINUX;
const HOST: HostRef = HostRef::Remote([7; 16]);
const OTHER_HOST: HostRef = HostRef::Remote([8; 16]);

fn rule(subject: Subject, account: Account, hosts: Hosts) -> Rule {
    Rule {
        subject,
        account,
        hosts,
    }
}

fn person(id: &str) -> Subject {
    Subject::Person(id.to_owned())
}

fn defaults(owner: &str) -> Vec<Rule> {
    vec![
        rule(Subject::Everyone, Account::OwnUsername, Hosts::All),
        rule(person(owner), Account::Any, Hosts::All),
    ]
}

fn added(host: HostRef) -> HostFacts {
    HostFacts {
        host,
        added_by_person: true,
        names_match_people: false,
    }
}

fn foreign(host: HostRef) -> HostFacts {
    HostFacts {
        host,
        added_by_person: false,
        names_match_people: false,
    }
}

#[test]
fn owner_default_allows_any_account_including_root() {
    let grant = grant(&defaults("p-owner"), "p-owner", "kayg", &foreign(HOST));
    assert!(grant.allows("root", 0, LINUX));
    assert!(grant.allows("deploy", 998, LINUX));
    assert!(grant.allows("kayg", 1000, LINUX));
}

#[test]
fn own_username_only_on_machines_the_person_added() {
    let rules = defaults("p-owner");
    let mine = grant(&rules, "p-bob", "bob", &added(HOST));
    assert!(mine.allows("bob", 1001, LINUX));
    // D319: elsewhere name matching does not apply until sign-in exists.
    let theirs = grant(&rules, "p-bob", "bob", &foreign(HOST));
    assert!(!theirs.allows("bob", 1001, LINUX));
    assert_eq!(theirs, LoginGrant::default());
}

#[test]
fn own_username_on_a_machine_marked_names_match_people() {
    let facts = HostFacts {
        host: HOST,
        added_by_person: false,
        names_match_people: true,
    };
    let grant = grant(&defaults("p-owner"), "p-bob", "bob", &facts);
    assert!(grant.allows("bob", 1001, LINUX));
}

#[test]
fn own_username_never_reaches_root_system_or_other_names() {
    let grant = grant(&defaults("p-owner"), "p-bob", "bob", &added(HOST));
    // A system account that happens to carry the person's name is not theirs.
    assert!(!grant.allows("bob", 999, LINUX));
    assert!(!grant.allows("bob", 0, LINUX));
    assert!(!grant.allows("bob", 65_534, LINUX));
    assert!(!grant.allows("root", 0, LINUX));
    assert!(!grant.allows("alice", 1002, LINUX));
    // D231's root fallback is a different account and needs its own rule.
    assert!(!grant.allows("root", 0, LINUX));
}

#[test]
fn a_person_named_root_gets_no_own_username() {
    let grant = grant(&defaults("p-owner"), "p-x", "root", &added(HOST));
    assert_eq!(grant.own_username, None);
    assert!(!grant.allows("root", 0, LINUX));
}

#[test]
fn macos_ordinary_accounts_start_at_501() {
    let grant = grant(&defaults("p-owner"), "p-bob", "bob", &added(HOST));
    assert!(grant.allows("bob", 501, OrdinaryUids::MACOS));
    assert!(!grant.allows("bob", 500, OrdinaryUids::MACOS));
    assert!(!grant.allows("bob", 501, LINUX));
}

#[test]
fn named_rules_match_their_exact_account_and_host_only() {
    let rules = vec![rule(
        person("p-bob"),
        Account::Named("deploy".into()),
        Hosts::Host(HOST),
    )];
    let here = grant(&rules, "p-bob", "bob", &foreign(HOST));
    assert!(here.allows("deploy", 998, LINUX));
    assert!(!here.allows("Deploy", 998, LINUX));
    assert!(!here.allows("deploy2", 998, LINUX));
    assert!(!here.allows("bob", 1001, LINUX));
    let elsewhere = grant(&rules, "p-bob", "bob", &foreign(OTHER_HOST));
    assert!(!elsewhere.allows("deploy", 998, LINUX));
}

#[test]
fn rules_for_another_person_never_apply() {
    let rules = vec![
        rule(person("p-alice"), Account::Any, Hosts::All),
        rule(
            person("p-alice"),
            Account::Named("deploy".into()),
            Hosts::All,
        ),
        rule(person("p-alice"), Account::OwnUsername, Hosts::All),
    ];
    let grant = grant(&rules, "p-bob", "bob", &added(HOST));
    assert_eq!(grant, LoginGrant::default());
    assert!(!grant.allows("deploy", 998, LINUX));
}

#[test]
fn no_rules_refuse_everything() {
    let grant = grant(&[], "p-owner", "kayg", &added(HostRef::Embedded));
    assert!(!grant.allows("kayg", 1000, LINUX));
    assert!(!grant.allows("root", 0, LINUX));
}

#[test]
fn embedded_host_is_its_own_target() {
    let rules = vec![rule(
        person("p-bob"),
        Account::Named("deploy".into()),
        Hosts::Host(HostRef::Embedded),
    )];
    assert!(
        grant(&rules, "p-bob", "bob", &foreign(HostRef::Embedded)).allows("deploy", 998, LINUX)
    );
    assert!(!grant(&rules, "p-bob", "bob", &foreign(HOST)).allows("deploy", 998, LINUX));
}

#[test]
fn empty_or_unsafe_account_names_never_match() {
    let rules = vec![rule(
        person("p-bob"),
        Account::Named(String::new()),
        Hosts::All,
    )];
    let grant = grant(&rules, "p-bob", "", &added(HOST));
    assert!(!grant.allows("", 1001, LINUX));
}

#[test]
fn a_grant_without_fields_decodes_as_refusing_everything() {
    let decoded: LoginGrant = serde_json::from_str("{}").expect("empty grant");
    assert_eq!(decoded, LoginGrant::default());
    assert!(!decoded.allows("root", 0, LINUX));
    assert!(serde_json::from_str::<LoginGrant>(r#"{"any":true}"#).is_err());
}
