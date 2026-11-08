use super::*;
use std::collections::BTreeMap;

#[test]
fn sparse_pages_match_ordered_map_through_writes_clones_and_range_deletion() {
    for shift in [0, 2] {
        let mut memory = Memory::new(shift);
        let mut reference = BTreeMap::new();
        let mut snapshots = Vec::new();
        let mut seed = 0x382951afu32;
        for index in 0..3000 {
            seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
            let address = if index % 5 == 0 {
                u32::MAX - (seed & 255)
            } else {
                0x4000 + (seed & 1023)
            } & !((1 << shift) - 1);
            match index % 9 {
                0 => {
                    memory.remove(address);
                    reference.remove(&address);
                }
                1 => {
                    let end = address.saturating_add((seed >> 16) & 127);
                    memory.forget_range(address, end);
                    reference.retain(|&at, _| at < address || at >= end);
                }
                _ => {
                    let value = if index % 2 == 0 {
                        Value::constant(seed)
                    } else {
                        Value::input(seed)
                    };
                    memory.insert(address, value);
                    reference.insert(address, value);
                }
            }
            assert_eq!(memory.get(address), reference.get(&address).copied());
            assert_eq!(memory.len(), reference.len());
            if index % 137 == 0 {
                assert_eq!(
                    memory.iter().collect::<Vec<_>>(),
                    reference
                        .iter()
                        .map(|(&at, &v)| (at, v))
                        .collect::<Vec<_>>()
                );
                snapshots.push((memory.clone(), reference.clone()));
            }
        }
        for (snapshot, expected) in snapshots {
            assert_eq!(snapshot.len(), expected.len());
            assert_eq!(
                snapshot.iter().collect::<Vec<_>>(),
                expected.into_iter().collect::<Vec<_>>()
            );
        }
        memory.forget_range(0, u32::MAX);
        assert_eq!(memory.len(), usize::from(reference.contains_key(&u32::MAX)));
        memory.remove(!((1 << shift) - 1));
        assert_eq!(memory.len(), 0);
    }
}

#[test]
fn changed_pages_retain_forks_and_missing_entries() {
    let mut original = Memory::new(2);
    for n in 0..CELLS as u32 * 4 {
        original.insert(0x1000 + n * 4, Value::constant(n));
    }
    let mut fork = original.clone();
    assert_eq!(fork.changed(&original).count(), 0);
    fork.insert(0x1004, Value::constant(99));
    fork.remove(0x1008);
    let changed = fork.changed(&original).collect::<Vec<_>>();
    assert_eq!(changed.len(), CELLS - 1);
    assert!(
        changed
            .iter()
            .all(|(at, _)| *at < 0x1000 + CELLS as u32 * 4)
    );
    assert_eq!(original.get(0x1004), Some(Value::constant(1)));
    assert_eq!(original.get(0x1008), Some(Value::constant(2)));
    fork.forget_range(0x1080, 0x1100);
    assert_eq!(original.changed(&fork).count(), CELLS * 2);
    assert_eq!(fork.changed(&original).count(), CELLS - 1);
}

#[test]
fn span_writes_cross_pages_and_wrap_without_modifying_snapshots() {
    for shift in [0, 2] {
        let values = (0..(CELLS * 3 + 7))
            .map(|n| Value::constant(n as u32))
            .collect::<Vec<_>>();
        for start in [
            0x1000 + ((CELLS as u32 - 2) << shift),
            u32::MAX - ((3 << shift) - 1),
        ] {
            let mut memory = Memory::new(shift);
            memory.insert(start, Value::input(9));
            let snapshot = memory.clone();
            memory.insert_span(start, &values);
            assert_eq!(memory.len(), values.len());
            for (n, &value) in values.iter().enumerate() {
                assert_eq!(
                    memory.get(start.wrapping_add((n as u32) << shift)),
                    Some(value)
                );
            }
            assert_eq!(snapshot.len(), 1);
            assert_eq!(snapshot.get(start), Some(Value::input(9)));
            let identical = memory.clone();
            memory.insert_span(start, &values);
            assert_eq!(memory.changed(&identical).count(), 0);
            memory.insert_span(start, &[]);
            assert_eq!(memory.len(), values.len());
        }
    }
}
