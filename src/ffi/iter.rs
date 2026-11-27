use std::iter::FusedIterator;

/// Iterator over a parent that exposes an item count and an index-based getter.
///
/// The item count is read once at construction, since the underlying C objects
/// are immutable. If `get` returns `None`, the iterator ends early and stays
/// exhausted.
pub(crate) struct IndexedIter<P, T> {
    parent: P,
    index: usize,
    len: usize,
    get: fn(&P, usize) -> Option<T>,
}

impl<P, T> IndexedIter<P, T> {
    pub(crate) fn new(parent: P, len: usize, get: fn(&P, usize) -> Option<T>) -> Self {
        Self {
            parent,
            index: 0,
            len,
            get,
        }
    }
}

impl<P, T> Iterator for IndexedIter<P, T> {
    type Item = T;

    fn next(&mut self) -> Option<T> {
        if self.index >= self.len {
            return None;
        }

        let item = (self.get)(&self.parent, self.index);
        if item.is_some() {
            self.index += 1;
        } else {
            self.index = self.len;
        }
        item
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.len - self.index;
        (remaining, Some(remaining))
    }
}

impl<P, T> ExactSizeIterator for IndexedIter<P, T> {}

impl<P, T> FusedIterator for IndexedIter<P, T> {}

#[cfg(test)]
mod tests {
    use super::*;

    fn slice_iter(items: &[u32]) -> IndexedIter<&[u32], u32> {
        IndexedIter::new(items, items.len(), |s, i| s.get(i).copied())
    }

    #[test]
    fn yields_all_items_in_order() {
        let items = [10, 20, 30];
        assert_eq!(slice_iter(&items).collect::<Vec<_>>(), vec![10, 20, 30]);
    }

    #[test]
    fn empty_parent_yields_nothing() {
        let mut iter = slice_iter(&[]);
        assert_eq!(iter.len(), 0);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn len_and_size_hint_track_consumption() {
        let items = [1, 2, 3];
        let mut iter = slice_iter(&items);
        assert_eq!(iter.len(), 3);
        assert_eq!(iter.size_hint(), (3, Some(3)));

        iter.next();
        assert_eq!(iter.len(), 2);
        assert_eq!(iter.size_hint(), (2, Some(2)));

        iter.next();
        iter.next();
        assert_eq!(iter.len(), 0);
        assert_eq!(iter.size_hint(), (0, Some(0)));
    }

    #[test]
    fn returns_none_after_end() {
        let items = [1];
        let mut iter = slice_iter(&items);
        assert_eq!(iter.next(), Some(1));
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn getter_returning_none_ends_iteration() {
        // The getter fails at index 1, but would succeed again at index 2.
        let items = [Some(1), None, Some(3)];
        let mut iter = IndexedIter::new(&items[..], items.len(), |s, i| s[i]);
        assert_eq!(iter.next(), Some(1));
        assert_eq!(iter.next(), None);
        assert_eq!(iter.len(), 0);
        assert_eq!(iter.next(), None);
    }
}
