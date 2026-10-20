from warrant.store import MAX_LIMIT, NoteStore


def test_notes_are_scoped_to_their_owner():
    store = NoteStore()
    mine = store.create("alice", "groceries", "milk")
    store.create("bob", "groceries", "eggs")

    assert store.get("alice", mine.id) == mine
    assert store.get("bob", mine.id) is None
    assert [n.body for n in store.search("bob", "groceries")] == ["eggs"]


def test_search_is_case_insensitive_and_literal():
    store = NoteStore()
    store.create("alice", "Q3 Plan", "ship 100% of it")
    store.create("alice", "other", "nothing here")

    assert [n.title for n in store.search("alice", "q3 plan")] == ["Q3 Plan"]
    assert [n.title for n in store.search("alice", "100%")] == ["Q3 Plan"]
    assert store.search("alice", "%") == store.search("alice", "100%")


def test_empty_query_lists_newest_first_within_limit():
    store = NoteStore()
    for i in range(MAX_LIMIT + 5):
        store.create("alice", f"note {i}", "")

    recent = store.search("alice", "", limit=3)
    assert [n.title for n in recent] == [
        f"note {MAX_LIMIT + 4}",
        f"note {MAX_LIMIT + 3}",
        f"note {MAX_LIMIT + 2}",
    ]
    assert len(store.search("alice", "", limit=1000)) == MAX_LIMIT
    assert len(store.search("alice", "", limit=-1)) == 1


def test_persists_across_connections(tmp_path):
    path = str(tmp_path / "notes.db")
    note = NoteStore(path).create("alice", "kept", "on disk")
    assert NoteStore(path).get("alice", note.id) == note
