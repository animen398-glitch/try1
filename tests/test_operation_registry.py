"""OperationRegistry persistence helpers."""

from utils.operation_registry import OperationRegistry


def test_start_serializes_non_json_metadata_with_default_str(tmp_path):
    reg = OperationRegistry(tmp_path / 'operations.db')
    out = tmp_path / 'scan'

    op_id = reg.start('https://x.com', 'collection', metadata={'path': out})

    assert reg.get(op_id)['metadata']['path'] == str(out)


def test_finish_can_replace_metadata(tmp_path):
    reg = OperationRegistry(tmp_path / 'operations.db')
    op_id = reg.start('https://x.com', 'collection',
                      metadata={'scan_id': 's1', 'status': 'running'})

    reg.finish(op_id, metadata={
        'scan_id': 's1',
        'status': 'Success',
        'warning_count': 2,
    })

    row = reg.get(op_id)
    assert row['status'] == 'success'
    assert row['metadata'] == {
        'scan_id': 's1',
        'status': 'Success',
        'warning_count': 2,
    }


# ── T8: bounded history (retention) ────────────────────────────────────────


class _SmallReg(OperationRegistry):
    MAX_HISTORY = 4
    PRUNE_EVERY = 3


def test_prune_keeps_newest(tmp_path):
    reg = OperationRegistry(tmp_path / 'ops.db')  # PRUNE_EVERY=200 → no auto-prune
    for i in range(10):
        reg.start(f't{i}', 'recon')
    deleted = reg.prune(max_rows=3)
    assert deleted == 7
    hist = reg.history(limit=100)
    assert len(hist) == 3
    assert {h['target'] for h in hist} == {'t7', 't8', 't9'}


def test_prune_noop_under_cap(tmp_path):
    reg = OperationRegistry(tmp_path / 'ops.db')
    for i in range(3):
        reg.start(f't{i}', 'recon')
    assert reg.prune(max_rows=10) == 0
    assert len(reg.history(limit=100)) == 3


def test_start_auto_prunes(tmp_path):
    reg = _SmallReg(tmp_path / 'ops.db')
    for i in range(9):                 # ids 1..9; prune fires at id 3, 6, 9
        reg.start(f't{i}', 'recon')
    hist = reg.history(limit=100)
    assert len(hist) == 4              # at id 9 → newest 4 kept
    assert {h['target'] for h in hist} == {'t5', 't6', 't7', 't8'}
