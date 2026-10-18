//! Merge planning for two-way sync. Pure logic, no I/O, so it can be unit-tested.
//!
//! Every entry id is in one of these states on each side (this device / Drive):
//!   * Live(updated, stamp): the entry exists
//!   * Dead(deleted_at):     it was deleted (a "tombstone")
//!   * nothing:              this side has never heard of it
//!
//! The newer timestamp wins. On an exact tie a delete beats an edit, and between
//! two different edits with the same timestamp the larger content stamp wins, so
//! every device reaches the same answer.

use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq)]
pub struct Live {
    pub updated: i64,
    pub stamp: String,
}

#[derive(Clone, Debug, PartialEq)]
enum St {
    Live(Live),
    Dead(i64),
}

#[derive(Default, Debug, PartialEq)]
pub struct Plan {
    /// Local entries to upload (creates or replaces `e-<id>` on Drive).
    pub upload: Vec<String>,
    /// Remote entries to fetch and store locally.
    pub download: Vec<String>,
    /// Drive should hold `t-<id>` with this deletion time.
    pub put_tombstone: Vec<(String, i64)>,
    /// Remote file names to remove (`e-<id>` / `t-<id>`).
    pub remote_delete: Vec<String>,
    /// Delete the local entry (if untouched since) and remember the tombstone.
    pub local_delete: Vec<(String, i64)>,
    /// Remember a tombstone locally; there is no local entry.
    pub adopt_tombstone: Vec<(String, i64)>,
    pub unchanged: usize,
}

fn resolve(live: Option<&Live>, dead: Option<&i64>) -> Option<St> {
    match (live, dead) {
        (Some(l), Some(&d)) => Some(if d >= l.updated { St::Dead(d) } else { St::Live(l.clone()) }),
        (Some(l), None) => Some(St::Live(l.clone())),
        (None, Some(&d)) => Some(St::Dead(d)),
        (None, None) => None,
    }
}

pub fn plan(
    local: &BTreeMap<String, Live>,
    local_dead: &BTreeMap<String, i64>,
    remote: &BTreeMap<String, Live>,
    remote_dead: &BTreeMap<String, i64>,
) -> Plan {
    let mut ids: BTreeSet<&String> = BTreeSet::new();
    ids.extend(local.keys());
    ids.extend(local_dead.keys());
    ids.extend(remote.keys());
    ids.extend(remote_dead.keys());

    let mut p = Plan::default();
    for id in ids {
        let l = resolve(local.get(id), local_dead.get(id));
        let r = resolve(remote.get(id), remote_dead.get(id));

        // Drive holds both an entry and a tombstone (two devices raced): drop the loser.
        if remote.contains_key(id) && remote_dead.contains_key(id) {
            match r {
                Some(St::Dead(_)) => p.remote_delete.push(format!("e-{id}")),
                Some(St::Live(_)) => p.remote_delete.push(format!("t-{id}")),
                None => {}
            }
        }

        match (l, r) {
            (None, None) => {}
            (Some(St::Live(_)), None) => p.upload.push(id.clone()),
            (Some(St::Live(a)), Some(St::Live(b))) => {
                if a.stamp == b.stamp {
                    p.unchanged += 1;
                } else if (a.updated, &a.stamp) > (b.updated, &b.stamp) {
                    p.upload.push(id.clone());
                } else {
                    p.download.push(id.clone());
                }
            }
            (Some(St::Live(a)), Some(St::Dead(d))) => {
                if d >= a.updated {
                    p.local_delete.push((id.clone(), d));
                } else {
                    // Edited after it was deleted elsewhere: the edit wins.
                    p.upload.push(id.clone());
                    p.remote_delete.push(format!("t-{id}"));
                }
            }
            // Deleted here, and Drive never had it: nothing to tell anyone.
            (Some(St::Dead(_)), None) => p.unchanged += 1,
            (Some(St::Dead(d)), Some(St::Live(b))) => {
                if d >= b.updated {
                    p.put_tombstone.push((id.clone(), d));
                    p.remote_delete.push(format!("e-{id}"));
                } else {
                    p.download.push(id.clone());
                }
            }
            (Some(St::Dead(dl)), Some(St::Dead(dr))) => {
                if dl > dr {
                    p.put_tombstone.push((id.clone(), dl));
                } else if dr > dl {
                    p.adopt_tombstone.push((id.clone(), dr));
                } else {
                    p.unchanged += 1;
                }
            }
            (None, Some(St::Live(_))) => p.download.push(id.clone()),
            (None, Some(St::Dead(d))) => p.adopt_tombstone.push((id.clone(), d)),
        }
    }
    p
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live(u: i64, s: &str) -> Live {
        Live { updated: u, stamp: s.into() }
    }
    fn m<T: Clone>(items: &[(&str, T)]) -> BTreeMap<String, T> {
        items.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }
    fn empty<T>() -> BTreeMap<String, T> {
        BTreeMap::new()
    }

    #[test]
    fn new_local_uploads_new_remote_downloads() {
        let p = plan(&m(&[("a", live(5, "x"))]), &empty(), &m(&[("b", live(6, "y"))]), &empty());
        assert_eq!(p.upload, vec!["a"]);
        assert_eq!(p.download, vec!["b"]);
    }

    #[test]
    fn identical_is_unchanged() {
        let p = plan(&m(&[("a", live(5, "x"))]), &empty(), &m(&[("a", live(5, "x"))]), &empty());
        assert_eq!(p, Plan { unchanged: 1, ..Plan::default() });
    }

    #[test]
    fn newer_side_wins() {
        let p = plan(&m(&[("a", live(9, "new"))]), &empty(), &m(&[("a", live(5, "old"))]), &empty());
        assert_eq!(p.upload, vec!["a"]);
        let p = plan(&m(&[("a", live(5, "old"))]), &empty(), &m(&[("a", live(9, "new"))]), &empty());
        assert_eq!(p.download, vec!["a"]);
    }

    #[test]
    fn tie_is_deterministic_on_both_devices() {
        let a = m(&[("e", live(5, "aaa"))]);
        let b = m(&[("e", live(5, "bbb"))]);
        let on_a = plan(&a, &empty(), &b, &empty());
        let on_b = plan(&b, &empty(), &a, &empty());
        // "bbb" must win everywhere.
        assert_eq!(on_a.download, vec!["e"]);
        assert_eq!(on_b.upload, vec!["e"]);
    }

    #[test]
    fn remote_delete_removes_local_copy() {
        let p = plan(&m(&[("a", live(5, "x"))]), &empty(), &empty(), &m(&[("a", 7)]));
        assert_eq!(p.local_delete, vec![("a".to_string(), 7)]);
    }

    #[test]
    fn edit_after_delete_resurrects() {
        let p = plan(&m(&[("a", live(9, "x"))]), &empty(), &empty(), &m(&[("a", 7)]));
        assert_eq!(p.upload, vec!["a"]);
        assert_eq!(p.remote_delete, vec!["t-a"]);
        assert!(p.local_delete.is_empty());
    }

    #[test]
    fn tie_delete_beats_edit() {
        let p = plan(&m(&[("a", live(7, "x"))]), &empty(), &empty(), &m(&[("a", 7)]));
        assert_eq!(p.local_delete.len(), 1);
    }

    #[test]
    fn local_delete_propagates() {
        let p = plan(&empty(), &m(&[("a", 8)]), &m(&[("a", live(5, "x"))]), &empty());
        assert_eq!(p.put_tombstone, vec![("a".to_string(), 8)]);
        assert_eq!(p.remote_delete, vec!["e-a"]);
    }

    #[test]
    fn local_delete_loses_to_newer_remote_edit() {
        let p = plan(&empty(), &m(&[("a", 8)]), &m(&[("a", live(12, "x"))]), &empty());
        assert_eq!(p.download, vec!["a"]);
        assert!(p.put_tombstone.is_empty());
    }

    #[test]
    fn deleted_everywhere_converges() {
        let p = plan(&empty(), &m(&[("a", 8)]), &empty(), &m(&[("a", 6)]));
        assert_eq!(p.put_tombstone, vec![("a".to_string(), 8)]);
        let p = plan(&empty(), &m(&[("a", 6)]), &empty(), &m(&[("a", 8)]));
        assert_eq!(p.adopt_tombstone, vec![("a".to_string(), 8)]);
    }

    #[test]
    fn unsynced_delete_makes_no_noise() {
        let p = plan(&empty(), &m(&[("a", 8)]), &empty(), &empty());
        assert_eq!(p, Plan { unchanged: 1, ..Plan::default() });
    }

    #[test]
    fn fresh_device_learns_old_deletes_without_resurrecting() {
        let p = plan(&empty(), &empty(), &empty(), &m(&[("a", 8)]));
        assert_eq!(p.adopt_tombstone, vec![("a".to_string(), 8)]);
        assert!(p.download.is_empty());
    }

    #[test]
    fn racing_entry_and_tombstone_on_drive_is_cleaned_up() {
        let p = plan(&empty(), &empty(), &m(&[("a", live(5, "x"))]), &m(&[("a", 9)]));
        assert_eq!(p.remote_delete, vec!["e-a"]);
        assert_eq!(p.adopt_tombstone, vec![("a".to_string(), 9)]);
    }
}
