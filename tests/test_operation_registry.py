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
