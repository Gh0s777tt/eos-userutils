// GENERATED FILE -- do not edit by hand. Regenerate with tools/gen_supplement.py.
//
// E-OS supplement to the corpus table in `blocklist_data.rs`. Two things the
// xato-net corpus structurally cannot contain:
//
//   1. E-OS's own vocabulary -- brand, product and component names, and the
//      three-character harness password `eos` itself. `eos` is blocklisted so
//      that no environment variable can talk the policy into accepting it:
//      `EOS_CREDPOLICY_ALLOW_WEAK` waives the length floor and the score floor
//      but NEVER the blocklist, so `install-smoke-drive.py`'s PASSWORD must
//      change in the same merge request that wires this library in
//      (ROADMAP `R-602e`). `eosdisk` -- the harness's FDE password on
//      line 28 -- is here for the same reason: measured, it failed only
//      the length floor, which `EOS_CREDPOLICY_ALLOW_WEAK` waives, so
//      without this entry the escape could have rescued it.
//   2. Polish-locale passwords. The corpus is an English-language breach
//      sample; E-OS's owner-facing locale is Polish, and `zaq12wsx`,
//      `kochamcie` or `haslo123` do not appear in an English corpus at all.
//
// [UNVERIFIED]: unlike `blocklist_data.rs`, these entries are AUTHORED from
// well-known patterns, not measured from a breach corpus. No frequency or rank
// is claimed for them and none is stored. If a permissively licensed Polish
// corpus ever becomes available, replace this table with a generated one.
//
// Entries are lower-cased ASCII, sorted by byte order for binary search.
// Diacritics are handled by the de-accent step in `blocklist::contains`, so
// "haslo" here also catches "hasło".
//
// 15 of these 145 entries also appear in the corpus table;
// duplication across the two tables is harmless (both are searched).

/// Number of entries in [`SUPPLEMENT`].
pub const SUPPLEMENT_LEN: usize = 145;

/// E-OS and Polish-locale weak passwords, sorted by byte order.
pub static SUPPLEMENT: [&str; SUPPLEMENT_LEN] = [
    "1qaz@wsx",
    "administrator",
    "administrator1",
    "agnieszka",
    "andrzej",
    "ania",
    "aniolek",
    "asia",
    "babcia",
    "barbara",
    "bartek",
    "basia",
    "bialoczerwoni",
    "bialystok",
    "bydgoszcz",
    "changeme",
    "changeme123",
    "cookbook",
    "correcthorsebatterystaple",
    "cracovia",
    "crimson",
    "crimson1",
    "czekolada",
    "czestochowa",
    "damian",
    "defaultpassword",
    "dominik",
    "dupa",
    "dupa1",
    "dupa12",
    "dupa123",
    "dupa1234",
    "dupablada",
    "dziadek",
    "e-os",
    "eos",
    "eosadmin",
    "eosdisk",
    "eoslinux",
    "eosos",
    "eospassword",
    "eosredox",
    "eosuser",
    "gdansk",
    "gdynia",
    "gornik",
    "grzesiek",
    "haslo",
    "haslo1",
    "haslo12",
    "haslo123",
    "haslo1234",
    "haslo12345",
    "iloveyouforever",
    "ion",
    "jadwiga",
    "jagoda",
    "jakub",
    "karolina",
    "kasia",
    "katarzyna",
    "katowice",
    "kocham",
    "kochamcie",
    "kochamcie1",
    "komputer",
    "kotek",
    "krakow",
    "krzysztof",
    "kurwa",
    "kurwa123",
    "lechia",
    "lechpoznan",
    "legia",
    "legiawarszawa",
    "lublin",
    "magda",
    "malgorzata",
    "malina",
    "mama",
    "marcin",
    "mateusz",
    "matura",
    "michal",
    "milosc",
    "misiek",
    "misiu",
    "mojehaslo",
    "motylek",
    "natalia",
    "ojczyzna",
    "orbital",
    "orblogin",
    "orzelbialy",
    "passwordissecure",
    "patryk",
    "piesek",
    "piotrek",
    "pkgar",
    "polska",
    "polska1",
    "polska123",
    "polskagola",
    "poznan",
    "praca",
    "przyjazn",
    "qwerty1234",
    "qwertyuiop123",
    "qwertz",
    "qwertz123",
    "redox",
    "redoxfs",
    "redoxos",
    "redoxuser",
    "rodzina",
    "rzeszow",
    "siostra",
    "slaskwroclaw",
    "slonce",
    "sloneczko",
    "slonko",
    "stanislaw",
    "studia",
    "szczecin",
    "szkola",
    "szymon",
    "tajne",
    "tajnehaslo",
    "tata",
    "tomasz",
    "tomek",
    "torun",
    "truskawka",
    "wakacje",
    "warszawa",
    "wisla",
    "wislakrakow",
    "wladyslaw",
    "wojtek",
    "wolnosc",
    "wroclaw",
    "zajebiste",
    "zakopane",
    "zaq12wsx",
    "zaq1@wsx",
];
